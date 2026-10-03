from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from vulnbatch.reconciliation.models import NETBOX_ASSET_ID_KINDS, AssetEvidence, Candidate, Decision

Key = tuple[str, ...]


def evidence_keys(evidence: AssetEvidence) -> tuple[Key, ...]:
    keys = [native.key for native in evidence.native_ids]
    if evidence.hardware_uuid:
        keys.append(("hardware", evidence.hardware_uuid))
    if evidence.fqdn:
        keys.append(("fqdn", evidence.fqdn))
    if evidence.short_hostname:
        keys.append(("short_hostname", evidence.short_hostname))
    if evidence.mac_address:
        keys.append(("mac", evidence.mac_address))
    keys.extend(("ip", evidence.network_scope or "", ip) for ip in evidence.ip_addresses)
    return tuple(sorted(set(keys)))


def _aware(time: datetime) -> datetime:
    return time.replace(tzinfo=UTC) if time.tzinfo is None else time.astimezone(UTC)


@dataclass(slots=True)
class TimeBounds:
    earliest: datetime | None = None
    latest: datetime | None = None
    unknown: bool = False

    def include(self, observed_at: datetime | None) -> None:
        if observed_at is None:
            self.unknown = True
            return
        time = _aware(observed_at)
        self.earliest = min(self.earliest, time) if self.earliest else time
        self.latest = max(self.latest, time) if self.latest else time

    def fresh(self, cutoff: datetime, now: datetime) -> bool:
        return (
            not self.unknown
            and self.earliest is not None
            and self.latest is not None
            and self.earliest >= cutoff
            and self.latest <= now
        )


class EvidenceIndex:
    """Exact evidence index; weak values suggest review and never establish identity."""

    def __init__(self, candidates: Iterable[Candidate], *, staleness_days: int = 90) -> None:
        if staleness_days < 1:
            raise ValueError("staleness_days must be positive")
        self.staleness_days = staleness_days
        self.buckets: dict[Key, dict[str, TimeBounds]] = defaultdict(dict)
        self.stable_values: dict[str, dict[Key, set[str]]] = defaultdict(dict)
        self.blocked_keys: set[Key] = set()
        self.candidate_checks = 0
        for candidate in candidates:
            self.add(candidate)

    def add(self, candidate: Candidate) -> None:
        for native in candidate.evidence.native_ids:
            self.stable_values[candidate.asset_id].setdefault(native.key[:-1], set()).add(native.value)
        if candidate.evidence.hardware_uuid:
            self.stable_values[candidate.asset_id].setdefault(("hardware",), set()).add(
                candidate.evidence.hardware_uuid,
            )
        for key in evidence_keys(candidate.evidence):
            self.buckets[key].setdefault(candidate.asset_id, TimeBounds()).include(candidate.observed_at)

    def resolve(self, incoming: AssetEvidence, *, observed_at: datetime | None, now: datetime) -> Decision:
        keys = evidence_keys(incoming)
        hits = {key: self.buckets[key] for key in keys if key in self.buckets}
        candidates = tuple(sorted({asset_id for bucket in hits.values() for asset_id in bucket}))
        self.candidate_checks += len(candidates)
        stable_hits = {
            key: bucket
            for key, bucket in hits.items()
            if key[0] == "hardware"
            or (key[0] == "native" and (key[1] != "netbox" or key[3] in NETBOX_ASSET_ID_KINDS))
        }
        stable_ids = {asset_id for bucket in stable_hits.values() for asset_id in bucket}
        matched_keys = tuple(sorted(hits))

        def review(rule: str, explanation: str) -> Decision:
            return Decision(
                action="review",
                rule=rule,
                explanation=explanation,
                confidence=0.0,
                candidate_ids=candidates,
                matched_keys=matched_keys,
            )

        if any(
            native.source == "netbox" and native.kind not in NETBOX_ASSET_ID_KINDS
            for native in incoming.native_ids
        ):
            return review(
                "unsupported_netbox_identity",
                "NetBox asset identity requires a device or VM namespace; "
                "IP/interface object IDs need join evidence.",
            )

        if set(keys) & self.blocked_keys:
            return review(
                "conflicting_ids_within_bundle", "This bundle contains conflicting native/hardware IDs."
            )
        if len(stable_ids) > 1:
            return review("duplicate_or_conflicting_stable_ids", "Stable evidence points to multiple assets.")
        if stable_ids:
            selected = next(iter(stable_ids))
            values = self.stable_values[selected]
            incoming_stable = [(native.key[:-1], native.value) for native in incoming.native_ids]
            if incoming.hardware_uuid:
                incoming_stable.append((("hardware",), incoming.hardware_uuid))
            if any(values.get(namespace, set()) - {value} for namespace, value in incoming_stable):
                return review(
                    "conflicting_stable_evidence", "Stable IDs conflict; possible reimage or cloned agent."
                )
            if set(candidates) - {selected}:
                return review("cross_asset_conflict", "Other asset history claims an incoming identifier.")
            cutoff = _aware(now) - timedelta(days=self.staleness_days)
            if observed_at is None or not cutoff <= _aware(observed_at) <= _aware(now):
                return review(
                    "unknown_stale_or_future_time", "Incoming time is missing, stale or in the future."
                )
            if any(not bucket[selected].fresh(cutoff, _aware(now)) for bucket in stable_hits.values()):
                return review(
                    "unknown_stale_or_future_history", "Stable evidence has unknown, stale or future time."
                )
            return Decision(
                action="match",
                rule="unique_scoped_stable_id",
                explanation="One fresh asset has stable evidence with no observed conflicts.",
                confidence=0.95,
                candidate_ids=(selected,),
                matched_keys=matched_keys,
            )
        if candidates:
            return review(
                "weak_identifier_only", "Weak identifiers require review; reuse and aliases are possible."
            )
        if not keys:
            return review("no_usable_identity", "No usable identity evidence is available.")
        return Decision(
            action="create",
            rule="no_safe_match",
            confidence=0.0,
            explanation="No existing evidence matched; suggest a separate provisional asset.",
        )
