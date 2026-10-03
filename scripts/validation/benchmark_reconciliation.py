"""Reproducible in-memory offline preview benchmark, entirely synthetic and offline."""

from __future__ import annotations

import argparse
import json
import platform
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from io import StringIO

from vulnbatch.reconciliation.adapters import parse_rows
from vulnbatch.reconciliation.matching import EvidenceIndex
from vulnbatch.reconciliation.models import AssetEvidence, Candidate, IdentityEvidence, SourceOptions
from vulnbatch.reconciliation.preview import summarize

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def measure(assets: int) -> dict[str, object]:
    candidates = [
        Candidate(
            asset_id=f"synthetic-asset-{number}",
            observed_at=NOW,
            evidence=AssetEvidence(
                native_ids=(
                    IdentityEvidence(
                        source="inventory",
                        instance="synthetic-benchmark",
                        kind="inventory_id",
                        value=f"synthetic-{number}",
                    ),
                ),
                hardware_uuid=f"synthetic-hardware-{number}",
                fqdn=f"host-{number}.example.test",
                short_hostname=f"host-{number}",
                ip_addresses=(f"2001:db8::{number + 1:x}",),
                network_scope="synthetic-lab",
            ),
        )
        for number in range(assets)
    ]
    lines = ["native_id,hardware_uuid,hostname,ip,observed_at,vulnerability_id,occurrence_id"]
    duplicates = errors = 0
    for number in range(assets):
        for finding in range(3):
            line = (
                f"synthetic-{number},synthetic-hardware-{number},host-{number}.example.test,"
                f"2001:db8::{number + 1:x},2026-10-01T00:00:00Z,"
                f"SYNTHETIC-VULN-{finding},synthetic-occ-{number}-{finding}"
            )
            lines.append(line)
            if finding == 0 and number % 50 == 0:
                lines.append(line)
                duplicates += 1
        if number % 200 == 0:
            lines.append(f"synthetic-error-{number},,,,invalid-time,vuln,error-{number}")
            errors += 1
    config = SourceOptions(
        source="inventory",
        instance="synthetic-benchmark",
        format="csv",
        network_scope="synthetic-lab",
        time_meaning="source_observed",
    )
    text = "\n".join(lines)
    tracemalloc.start()
    started = time.perf_counter()
    index = EvidenceIndex(candidates)
    result = summarize(
        parse_rows(StringIO(text), config, file_hash="a" * 64, imported_at=NOW), index, now=NOW, limit=50
    )
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert result.total == assets * 3
    assert result.duplicate_rows == duplicates
    assert result.error_rows == errors
    assert result.action_counts == {"match": assets * 3}
    assert result.candidate_checks == assets * 3
    assert len(result.items) == min(50, assets * 3)
    return {
        "python": platform.python_version(),
        "platform": platform.system(),
        "assets": assets,
        "total_rows": result.total_rows,
        "unique_observations": result.total,
        "duplicate_rows": result.duplicate_rows,
        "error_rows": result.error_rows,
        "candidate_checks": result.candidate_checks,
        "response_items": len(result.items),
        "elapsed_seconds": round(elapsed, 3),
        "peak_python_mib": round(peak / (1024 * 1024), 2),
        "fixture_bytes": len(text.encode()),
        "measurement": "index, parse, normalize, preflight, match, page; tracemalloc on",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=int, default=5000)
    parser.add_argument("--history-observations", type=int, default=0)
    args = parser.parse_args()
    if not 1 <= args.assets <= 30_000:
        parser.error("assets must be between 1 and 30000")
    if not 0 <= args.history_observations <= 100_000:
        parser.error("history-observations must be between 0 and 100000")
    print(json.dumps(measure(args.assets), indent=2))
    if args.history_observations:
        evidence = AssetEvidence(
            native_ids=(
                IdentityEvidence(
                    source="inventory",
                    instance="synthetic-history",
                    kind="inventory_id",
                    value="synthetic-one",
                ),
            )
        )
        index = EvidenceIndex([Candidate(asset_id="synthetic-one", evidence=evidence, observed_at=NOW)])
        started = time.perf_counter()
        for number in range(args.history_observations):
            timestamp = NOW - timedelta(seconds=args.history_observations - number)
            assert index.resolve(evidence, observed_at=timestamp, now=NOW).action == "match"
            index.add(Candidate(asset_id="synthetic-one", evidence=evidence, observed_at=timestamp))
        print(
            json.dumps(
                {
                    "repeated_fresh_history_observations": args.history_observations,
                    "candidate_checks": index.candidate_checks,
                    "elapsed_seconds": round(time.perf_counter() - started, 3),
                    "measurement": "resolve + add of distinct timestamps on one source ID; tracing off",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
