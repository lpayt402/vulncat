"""Load only the bundled hypothetical example into an explicitly disposable local instance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vulnbatch.client.services import WorkbenchService
from vulnbatch.client.transport import ApiClient

ROOT = Path(__file__).resolve().parent


def load_example(client: ApiClient) -> dict[str, Any]:
    if client.origin not in {"http://127.0.0.1:8787", "http://localhost:8787"}:
        raise ValueError("The hypothetical loader accepts only the fixed local disposable application")
    service = WorkbenchService(client)
    profiles = json.loads((ROOT / "profiles.json").read_text(encoding="utf-8"))
    graph = json.loads((ROOT / "graph.synthetic.json").read_text(encoding="utf-8"))
    current = client._request("GET", "/api/v1/exposure/nodes", params={"q": "Cedar", "limit": 500})
    if any(item["instance"] == graph["instance"] for item in current["items"]):
        raise ValueError("This example was already loaded; use a fresh disposable instance")
    files = [str(ROOT / item["filename"]) for item in profiles]
    options = [item["options"] for item in profiles]
    preview = service.preview(files, options, limit=500)
    if preview["error_rows"]:
        raise ValueError("Bundled hypothetical source rows failed validation")
    imported = service.import_bundle(files, options, preview, "cedar-service-observations-v1")
    observations = service.observations(review_status=None, limit=500)["items"]
    by_ref = {
        item["observation"]["raw"]["fixture_ref"]: item
        for item in observations
        if item["observation"].get("raw", {}).get("fixture_ref")
    }
    mappings = json.loads((ROOT / "attributions.synthetic.json").read_text(encoding="utf-8"))
    if set(by_ref) != {item["fixture_ref"] for item in mappings}:
        raise ValueError("Use a disposable instance containing only the bundled hypothetical fixture")
    for node in graph["nodes"]:
        bound = by_ref.get(node["ref"])
        if node["kind"] in {"host", "device", "load_balancer"} and bound and bound["asset_id"]:
            node["asset_id"] = bound["asset_id"]
    graph["attributions"] = [
        {
            "observation_id": by_ref[item["fixture_ref"]]["id"],
            "node_ref": item["node_ref"],
            "status": item["status"],
            "reason": item["reason"],
            "evidence": {"synthetic_fixture_ref": item["fixture_ref"]},
        }
        for item in mappings
    ]
    graph_preview = service.exposure_preview(graph)
    applied = service.exposure_apply(
        graph,
        graph_preview,
        "cedar-service-topology-v1",
        "Reviewed hypothetical topology and source mappings",
    )
    node_ids = graph_preview["node_ids"]
    # Append older contradictory evidence without replacing the dated current projection.
    old_node = dict(next(item for item in graph["nodes"] if item["ref"] == "east-a"))
    old_node.update(expected_version=1, facts={"fingerprint": "Windows Server 2016"})
    old_graph = {
        **{
            key: value
            for key, value in graph.items()
            if key not in {"nodes", "relationships", "attributions"}
        },
        "observed_at": "2026-03-01T09:00:00Z",
        "nodes": [old_node],
        "relationships": [],
        "attributions": [],
    }
    old_preview = service.exposure_preview(old_graph)
    stale = service.exposure_apply(
        old_graph,
        old_preview,
        "cedar-service-stale-fact-v1",
        "Retain the older conflicting hypothetical fingerprint",
    )
    return {
        "synthetic": True,
        "imported": imported,
        "topology": applied,
        "stale_fact": stale,
        "node_ids": node_ids,
        "observation_ids": {ref: item["id"] for ref, item in by_ref.items()},
        "report": service.exposure_read("report", limit=500),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-file", required=True, type=Path)
    parser.add_argument("--disposable-confirm", action="store_true", required=True)
    args = parser.parse_args()
    with ApiClient(session_file=args.session_file) as client:
        result = load_example(client)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
