from __future__ import annotations

import json
from pathlib import Path

from vulnbatch.imports import (
    parse_generic_csv,
    parse_nessus_xml,
    parse_tenable_csv,
    parse_tenable_json,
    preview_generic_csv,
)

ROOT = Path(__file__).resolve().parent
MAPPING = {
    "fqdn": "Server Name",
    "ip_address": "Address",
    "plugin_id": "Check",
    "severity": "Rating",
    "first_found": "First Seen",
    "solution": "Fix",
}


def main() -> None:
    with (ROOT / "scanner.csv").open(encoding="utf-8", newline="") as stream:
        tenable = list(parse_tenable_csv(stream))
    with (ROOT / "scanner.json").open(encoding="utf-8") as stream:
        database = list(parse_tenable_json(stream))
    with (ROOT / "scanner.nessus").open("rb") as stream:
        nessus = list(parse_nessus_xml(stream))
    with (ROOT / "generic.csv").open(encoding="utf-8", newline="") as stream:
        generic = list(parse_generic_csv(stream, mapping=MAPPING))
    with (ROOT / "generic.csv").open(encoding="utf-8", newline="") as stream:
        preview = preview_generic_csv(stream, mapping=MAPPING)

    assert len(tenable) == 2 and len(database) == 1 and len(nessus) == 1 and len(generic) == 2
    assert tenable[0].asset.fqdn == nessus[0].asset.fqdn == generic[0].asset.fqdn
    assert tenable[0].asset.ipv4_address == "192.0.2.44"
    assert nessus[0].asset.ipv4_address == "192.0.2.45"
    assert tenable[0].asset.mac_address == nessus[0].asset.mac_address == "02:00:5e:10:00:02"
    assert tenable[0].finding.severity == "medium" and tenable[0].included_in_inventory
    assert tenable[1].finding.severity == "high" and not tenable[1].included_in_inventory
    assert nessus[0].finding.severity == "high" and not nessus[0].included_in_inventory
    first_found = database[0].finding.first_found
    last_found = database[0].finding.last_found
    assert first_found is not None and last_found is not None and first_found < last_found
    assert preview.unmapped_columns == ("Business Owner Note",)
    assert all(record.included_in_inventory for record in generic)
    print(json.dumps({
        "formats": 4,
        "records": 6,
        "included": 4,
        "skipped_high": 2,
        "unmapped_owner_note": True,
        "network_requests": 0,
    }))


if __name__ == "__main__":
    main()
