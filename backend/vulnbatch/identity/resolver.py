from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from vulnbatch.identity.normalization import IDENTIFIER_TYPES, clean_text, normalize_identifier

DecisionAction = Literal["match", "create", "review"]

_STRONG_PRIORITY: tuple[tuple[str, ...], ...] = (
    ("tenable_asset_uuid", "agent_uuid"),
    ("hardware_uuid",),
    ("mac_address",),
    ("fqdn",),
)
_CONFLICT_SENSITIVE_TYPES = frozenset(
    {"tenable_asset_uuid", "agent_uuid", "hardware_uuid", "mac_address", "fqdn"}
)
_IP_TYPES = frozenset({"ipv4", "ipv6"})
_CONFIDENCE_BY_RULE = {
    "manual_override": 1.0,
    "exact_scanner_uuid": 0.99,
    "exact_hardware_uuid": 0.97,
    "exact_mac": 0.95,
    "exact_fqdn": 0.93,
    "verified_short_hostname": 0.91,
    "unique_ip_history": 0.90,
}


@dataclass(frozen=True, slots=True)
class IncomingIdentifier:
    identifier_type: str
    normalized_value: str
    original_value: str


@dataclass(frozen=True, slots=True)
class IdentifierAssociation:
    identifier_type: str
    normalized_value: str
    original_value: str
    first_observed_at: datetime
    last_observed_at: datetime
    active: bool = True
    manually_verified: bool = False
    manual_override: bool = False
    shared_or_non_identifying: bool = False

    def __post_init__(self) -> None:
        if self.identifier_type not in IDENTIFIER_TYPES:
            raise ValueError(f"Unsupported identifier type: {self.identifier_type}")
        expected = normalize_identifier(self.identifier_type, self.normalized_value)
        if expected != self.normalized_value:
            raise ValueError("IdentifierAssociation.normalized_value is not normalized")


@dataclass(frozen=True, slots=True)
class AssetCandidate:
    asset_id: str
    identifiers: tuple[IdentifierAssociation, ...] = ()
    operating_system: str | None = None
    active: bool = True


@dataclass(frozen=True, slots=True)
class IdentityDecision:
    action: DecisionAction
    asset_id: str | None
    matching_rule: str
    confidence: float
    explanation: str
    candidate_asset_ids: tuple[str, ...] = ()
    incoming_identifiers: tuple[IncomingIdentifier, ...] = ()
    conflicting_evidence: tuple[dict[str, Any], ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)


class IdentityResolver:
    def __init__(
        self,
        *,
        staleness_days: int = 90,
        auto_match_threshold: float = 0.85,
    ) -> None:
        if staleness_days < 1:
            raise ValueError("staleness_days must be positive")
        if not 0.0 <= auto_match_threshold <= 1.0:
            raise ValueError("auto_match_threshold must be between 0 and 1")
        self.staleness_days = staleness_days
        self.auto_match_threshold = auto_match_threshold

    def resolve(
        self,
        incoming: Mapping[str, object],
        candidates: Sequence[AssetCandidate],
        *,
        observed_at: datetime | None = None,
        operating_system: str | None = None,
    ) -> IdentityDecision:
        observation_time = _ensure_aware(observed_at or datetime.now(UTC))
        incoming_identifiers = _normalize_incoming(incoming)
        active_candidates = tuple(candidate for candidate in candidates if candidate.active)

        if not incoming_identifiers:
            return IdentityDecision(
                action="create",
                asset_id=None,
                matching_rule="no_usable_identifiers",
                confidence=0.0,
                explanation="No valid identifiers were supplied; no automatic association is possible.",
            )

        manual_matches = self._manual_matches(incoming_identifiers, active_candidates)
        if len(manual_matches) == 1:
            candidate = manual_matches[0]
            return self._match(
                candidate,
                incoming_identifiers,
                "manual_override",
                "A manually verified override matched and takes precedence over automatic evidence.",
            )
        if len(manual_matches) > 1:
            return self._review(
                incoming_identifiers,
                manual_matches,
                "conflicting_manual_overrides",
                "More than one canonical asset has a matching manual override.",
            )

        strong_result = self._resolve_strong(incoming_identifiers, active_candidates)
        if strong_result is not None:
            return strong_result

        short_matches = self._matching_candidates(
            incoming_identifiers,
            active_candidates,
            {"short_hostname"},
            require_verified=True,
        )
        if len(short_matches) == 1:
            candidate = short_matches[0]
            conflicts = _candidate_conflicts(candidate, incoming_identifiers)
            cross_conflicts, conflicting_candidates = _cross_candidate_conflicts(
                candidate,
                incoming_identifiers,
                active_candidates,
            )
            conflicts += cross_conflicts
            if conflicts:
                return self._review(
                    incoming_identifiers,
                    (candidate, *conflicting_candidates),
                    "verified_short_hostname_conflict",
                    "The verified short hostname matched, but stronger incoming evidence conflicts.",
                    conflicts,
                )
            return self._match(
                candidate,
                incoming_identifiers,
                "verified_short_hostname",
                "One manually verified short-hostname association matched.",
            )
        if len(short_matches) > 1:
            return self._review(
                incoming_identifiers,
                short_matches,
                "ambiguous_verified_short_hostname",
                "The verified short hostname is associated with multiple canonical assets.",
            )

        ip_result = self._resolve_ip(incoming_identifiers, active_candidates, observation_time)
        if ip_result is not None:
            return ip_result

        weighted_result = self._resolve_weighted(
            incoming_identifiers,
            active_candidates,
            operating_system=operating_system,
        )
        if weighted_result is not None:
            return weighted_result

        unverified_short_matches = self._matching_candidates(
            incoming_identifiers,
            active_candidates,
            {"short_hostname"},
        )
        if unverified_short_matches:
            return self._review(
                incoming_identifiers,
                unverified_short_matches,
                "unverified_short_hostname",
                "A short hostname matched existing assets but is not manually verified.",
            )

        return IdentityDecision(
            action="create",
            asset_id=None,
            matching_rule="no_match",
            confidence=0.0,
            explanation="No safe automatic association met the configured confidence threshold.",
            incoming_identifiers=incoming_identifiers,
        )

    def _manual_matches(
        self,
        incoming: tuple[IncomingIdentifier, ...],
        candidates: Sequence[AssetCandidate],
    ) -> tuple[AssetCandidate, ...]:
        values = {(item.identifier_type, item.normalized_value) for item in incoming}
        return tuple(
            candidate
            for candidate in candidates
            if any(
                association.active
                and association.manual_override
                and not association.shared_or_non_identifying
                and (association.identifier_type, association.normalized_value) in values
                for association in candidate.identifiers
            )
        )

    def _resolve_strong(
        self,
        incoming: tuple[IncomingIdentifier, ...],
        candidates: Sequence[AssetCandidate],
    ) -> IdentityDecision | None:
        all_strong_matches: dict[str, AssetCandidate] = {}
        matches_by_group: list[tuple[AssetCandidate, ...]] = []
        for group in _STRONG_PRIORITY:
            matches = self._matching_candidates(incoming, candidates, set(group))
            matches_by_group.append(matches)
            for candidate in matches:
                all_strong_matches[candidate.asset_id] = candidate

        if len(all_strong_matches) > 1:
            return self._review(
                incoming,
                tuple(all_strong_matches.values()),
                "conflicting_strong_identifiers",
                "Strong identifiers in the same observation point to different canonical assets.",
            )

        for index, matches in enumerate(matches_by_group):
            if not matches:
                continue
            if len(matches) > 1:
                return self._review(
                    incoming,
                    matches,
                    "duplicate_strong_identifier",
                    "A strong identifier is associated with multiple canonical assets.",
                )
            candidate = matches[0]
            conflicts = _candidate_conflicts(candidate, incoming)
            cross_conflicts, conflicting_candidates = _cross_candidate_conflicts(
                candidate,
                incoming,
                candidates,
            )
            conflicts += cross_conflicts
            if conflicts:
                return self._review(
                    incoming,
                    (candidate, *conflicting_candidates),
                    "strong_identifier_conflict",
                    "An exact strong identifier matched, but other strong evidence conflicts.",
                    conflicts,
                )
            rule = (
                "exact_scanner_uuid",
                "exact_hardware_uuid",
                "exact_mac",
                "exact_fqdn",
            )[index]
            return self._match(
                candidate,
                incoming,
                rule,
                f"A unique {rule.replace('_', ' ')} association matched.",
            )
        return None

    def _resolve_ip(
        self,
        incoming: tuple[IncomingIdentifier, ...],
        candidates: Sequence[AssetCandidate],
        observed_at: datetime,
    ) -> IdentityDecision | None:
        incoming_ips = {
            (item.identifier_type, item.normalized_value)
            for item in incoming
            if item.identifier_type in _IP_TYPES
        }
        if not incoming_ips:
            return None

        eligible: dict[str, AssetCandidate] = {}
        recent: dict[str, AssetCandidate] = {}
        cutoff = observed_at - timedelta(days=self.staleness_days)
        for candidate in candidates:
            for association in candidate.identifiers:
                key = (association.identifier_type, association.normalized_value)
                if key not in incoming_ips or association.shared_or_non_identifying:
                    continue
                if _ensure_aware(association.last_observed_at) >= cutoff:
                    recent[candidate.asset_id] = candidate
                if association.active:
                    eligible[candidate.asset_id] = candidate

        if not eligible and not recent:
            return None
        if len(eligible) != 1 or len(recent) != 1 or set(eligible) != set(recent):
            return self._review(
                incoming,
                tuple({**recent, **eligible}.values()),
                "ambiguous_ip_history",
                "The IP address does not have exactly one active, recent, non-shared association.",
            )

        candidate = next(iter(eligible.values()))
        conflicts = _candidate_conflicts(candidate, incoming)
        if conflicts:
            return self._review(
                incoming,
                (candidate,),
                "ip_conflicts_with_stronger_evidence",
                "The IP history is unique, but the current observation conflicts with stronger evidence.",
                conflicts,
            )
        confidence = _CONFIDENCE_BY_RULE["unique_ip_history"]
        if confidence < self.auto_match_threshold:
            return self._review(
                incoming,
                (candidate,),
                "ip_below_confidence_threshold",
                "The unique IP association did not meet the configured auto-match threshold.",
            )
        return self._match(
            candidate,
            incoming,
            "unique_ip_history",
            "The IP address has one active, recent, non-conflicting asset association.",
        )

    def _resolve_weighted(
        self,
        incoming: tuple[IncomingIdentifier, ...],
        candidates: Sequence[AssetCandidate],
        *,
        operating_system: str | None,
    ) -> IdentityDecision | None:
        incoming_values = defaultdict(set)
        for item in incoming:
            incoming_values[item.identifier_type].add(item.normalized_value)
        os_value = clean_text(operating_system)
        scores: dict[str, float] = {}
        matched: dict[str, AssetCandidate] = {}
        for candidate in candidates:
            score = 0.0
            candidate_values = defaultdict(set)
            for association in candidate.identifiers:
                if association.active and not association.shared_or_non_identifying:
                    candidate_values[association.identifier_type].add(association.normalized_value)
            if incoming_values["nessus_host_id"] & candidate_values["nessus_host_id"]:
                score += 0.60
            if incoming_values["short_hostname"] & candidate_values["short_hostname"]:
                score += 0.15
            candidate_os = clean_text(candidate.operating_system)
            if (
                os_value is not None
                and candidate_os is not None
                and os_value.casefold() == candidate_os.casefold()
            ):
                score += 0.15
            if score:
                scores[candidate.asset_id] = score
                matched[candidate.asset_id] = candidate

        qualifying = [
            matched[asset_id] for asset_id, score in scores.items() if score >= self.auto_match_threshold
        ]
        if len(qualifying) == 1:
            candidate = qualifying[0]
            conflicts = _candidate_conflicts(candidate, incoming)
            if not conflicts:
                return IdentityDecision(
                    action="match",
                    asset_id=candidate.asset_id,
                    matching_rule="weighted_evidence",
                    confidence=scores[candidate.asset_id],
                    explanation="A unique weighted evidence combination exceeded the configured threshold.",
                    candidate_asset_ids=(candidate.asset_id,),
                    incoming_identifiers=incoming,
                    evidence={"score": scores[candidate.asset_id]},
                )
        if len(qualifying) > 1:
            return self._review(
                incoming,
                qualifying,
                "ambiguous_weighted_evidence",
                "More than one asset exceeded the weighted evidence threshold.",
            )
        return None

    @staticmethod
    def _matching_candidates(
        incoming: tuple[IncomingIdentifier, ...],
        candidates: Sequence[AssetCandidate],
        identifier_types: set[str],
        *,
        require_verified: bool = False,
    ) -> tuple[AssetCandidate, ...]:
        values = {
            (item.identifier_type, item.normalized_value)
            for item in incoming
            if item.identifier_type in identifier_types
        }
        if not values:
            return ()
        matches: dict[str, AssetCandidate] = {}
        for candidate in candidates:
            for association in candidate.identifiers:
                if (
                    association.active
                    and not association.shared_or_non_identifying
                    and (not require_verified or association.manually_verified)
                    and (association.identifier_type, association.normalized_value) in values
                ):
                    matches[candidate.asset_id] = candidate
        return tuple(matches.values())

    @staticmethod
    def _match(
        candidate: AssetCandidate,
        incoming: tuple[IncomingIdentifier, ...],
        rule: str,
        explanation: str,
    ) -> IdentityDecision:
        return IdentityDecision(
            action="match",
            asset_id=candidate.asset_id,
            matching_rule=rule,
            confidence=_CONFIDENCE_BY_RULE[rule],
            explanation=explanation,
            candidate_asset_ids=(candidate.asset_id,),
            incoming_identifiers=incoming,
        )

    @staticmethod
    def _review(
        incoming: tuple[IncomingIdentifier, ...],
        candidates: Iterable[AssetCandidate],
        rule: str,
        explanation: str,
        conflicts: Iterable[dict[str, Any]] = (),
    ) -> IdentityDecision:
        candidate_ids = tuple(dict.fromkeys(candidate.asset_id for candidate in candidates))
        return IdentityDecision(
            action="review",
            asset_id=None,
            matching_rule=rule,
            confidence=0.0,
            explanation=explanation,
            candidate_asset_ids=candidate_ids,
            incoming_identifiers=incoming,
            conflicting_evidence=tuple(conflicts),
        )


def _normalize_incoming(incoming: Mapping[str, object]) -> tuple[IncomingIdentifier, ...]:
    normalized: list[IncomingIdentifier] = []
    seen: set[tuple[str, str]] = set()
    for identifier_type, raw_values in incoming.items():
        if identifier_type not in IDENTIFIER_TYPES:
            continue
        values: Iterable[object] = (
            raw_values if isinstance(raw_values, (list, tuple, set, frozenset)) else (raw_values,)
        )
        for raw_value in values:
            value = normalize_identifier(identifier_type, raw_value)
            original = clean_text(raw_value)
            if value is None or original is None or (identifier_type, value) in seen:
                continue
            seen.add((identifier_type, value))
            normalized.append(
                IncomingIdentifier(
                    identifier_type=identifier_type,
                    normalized_value=value,
                    original_value=original,
                )
            )
    return tuple(normalized)


def _candidate_conflicts(
    candidate: AssetCandidate,
    incoming: tuple[IncomingIdentifier, ...],
) -> tuple[dict[str, Any], ...]:
    incoming_values: dict[str, set[str]] = defaultdict(set)
    for item in incoming:
        if item.identifier_type in _CONFLICT_SENSITIVE_TYPES:
            incoming_values[item.identifier_type].add(item.normalized_value)

    candidate_values: dict[str, set[str]] = defaultdict(set)
    for association in candidate.identifiers:
        if (
            association.active
            and not association.shared_or_non_identifying
            and association.identifier_type in _CONFLICT_SENSITIVE_TYPES
        ):
            candidate_values[association.identifier_type].add(association.normalized_value)

    conflicts: list[dict[str, Any]] = []
    for identifier_type, supplied in incoming_values.items():
        existing = candidate_values.get(identifier_type, set())
        if existing and supplied.isdisjoint(existing):
            conflicts.append(
                {
                    "identifier_type": identifier_type,
                    "incoming_values": sorted(supplied),
                    "candidate_values": sorted(existing),
                }
            )
    return tuple(conflicts)


def _cross_candidate_conflicts(
    selected: AssetCandidate,
    incoming: tuple[IncomingIdentifier, ...],
    candidates: Sequence[AssetCandidate],
) -> tuple[tuple[dict[str, Any], ...], tuple[AssetCandidate, ...]]:
    incoming_values = {
        (item.identifier_type, item.normalized_value)
        for item in incoming
        if item.identifier_type in _CONFLICT_SENSITIVE_TYPES | _IP_TYPES
    }
    conflicts: list[dict[str, Any]] = []
    conflicting_candidates: dict[str, AssetCandidate] = {}
    for candidate in candidates:
        if candidate.asset_id == selected.asset_id:
            continue
        for association in candidate.identifiers:
            key = (association.identifier_type, association.normalized_value)
            if association.active and not association.shared_or_non_identifying and key in incoming_values:
                conflicting_candidates[candidate.asset_id] = candidate
                conflicts.append(
                    {
                        "identifier_type": association.identifier_type,
                        "incoming_value": association.normalized_value,
                        "conflicting_asset_id": candidate.asset_id,
                        "selected_asset_id": selected.asset_id,
                    }
                )
    return tuple(conflicts), tuple(conflicting_candidates.values())


def _ensure_aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
