from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from vulnbatch.reconciliation.matching import EvidenceIndex, Key
from vulnbatch.reconciliation.models import Observation


class ConflictKeys:
    """Retain unresolved conflict evidence across both historical and incoming records."""

    def __init__(self) -> None:
        self.native_hardware: dict[Key, set[str]] = defaultdict(set)
        self.simultaneous_names: dict[tuple[Key, datetime], set[str]] = defaultdict(set)
        self.hardware_native: dict[Key, dict[Key, set[str]]] = defaultdict(dict)

    def include(self, observation: Observation) -> None:
        evidence = observation.asset
        name = evidence.fqdn or evidence.short_hostname
        if name and observation.observed_at:
            for native in evidence.native_ids:
                self.simultaneous_names[(native.key, observation.observed_at)].add(name)
            if evidence.hardware_uuid:
                self.simultaneous_names[(("hardware", evidence.hardware_uuid), observation.observed_at)].add(
                    name
                )
        if evidence.hardware_uuid:
            hardware_key: Key = ("hardware", evidence.hardware_uuid)
            for native in evidence.native_ids:
                self.native_hardware[native.key].add(evidence.hardware_uuid)
                self.hardware_native[hardware_key].setdefault(native.key[:-1], set()).add(native.value)

    def apply(self, index: EvidenceIndex) -> None:
        for key, values in self.native_hardware.items():
            if len(values) > 1:
                index.blocked_keys.add(key)
        for (key, _), names in self.simultaneous_names.items():
            if len(names) > 1:
                index.blocked_keys.add(key)
        for hardware_key, namespaces in self.hardware_native.items():
            for namespace, values in namespaces.items():
                if len(values) > 1:
                    index.blocked_keys.add(hardware_key)
                    index.blocked_keys.update((*namespace, value) for value in values)
