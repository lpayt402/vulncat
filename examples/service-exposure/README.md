# Cedar service exposure example

These synthetic records model a hypothetical application environment. Platform fingerprints use plausible software versions; host names, IDs and findings are scenario inputs, not observations from an employer or customer. `example.test` and `192.0.2.0/24` are reserved for examples. The private addresses represent two separate scopes. These canonical JSON files exercise configurable offline adapters; they are **not verified native export schemas**. Scanner observation rows here also use mapped JSON rather than claiming a native export. Native `.nessus` XML remains covered by the other bundled examples.

The hypothetical reverse proxy serves Checkout and Status through one VIP on TCP 443. Separate endpoint records carry their DNS/SNI names. Checkout has two backends; Status shares one. East and West worker A use the same private IP and hostname, but retain separate native identities and scopes. An appliance has a management endpoint on 8443 and a data-plane endpoint on 443.

| Signal | Source and observation time | Explicit target | Expected interpretation |
| --- | --- | --- | --- |
| Shared TLS weakness | Scanner, 2026-10-01 14:00 UTC | Shared VIP | Remains on the VIP; does not become two backend findings |
| HTTP header finding | Scanner, 2026-10-01 14:00 UTC | Checkout HTTPS | Shows Checkout through the confirmed `endpoint_of` relation |
| Outdated runtime | Endpoint management, 2026-10-01 14:00 UTC | East worker A | Backend evidence, with the native `Detected` status preserved |
| Management unreachable | Scanner, 2026-10-01 14:00 UTC | Appliance management | Coverage gap; does not resolve a finding or retire the appliance |
| Data plane scan completed | Scanner, 2026-10-01 14:00 UTC | Appliance data plane | Separate successful coverage; no inference about management coverage |
| Windows Server 2016 fingerprint | Endpoint security, 2026-03-01 09:00 UTC | Review needed | Stale conflicting observation remains visible |
| Directory logon evidence | Directory, 2026-10-01 14:00 UTC, **last logon** | Review needed | Does not establish current reachability; age shown as unknown |
| Undated fingerprint | Inventory, no timestamp | Review needed | Unknown age and insufficient attribution |

`profiles.json` gives one source configuration per input. `graph.synthetic.json` is a valid, source-scoped topology envelope. It can be previewed independently. `attributions.synthetic.json` uses synthetic row refs; the loader resolves actual imported observation IDs explicitly. It never matches by IP or hostname. Source-specific status strings are retained rather than treated as a common resolution lifecycle.

For a disposable local instance, create a fresh administrator in the browser, install this checkout with `python -m pip install .`, then:

```powershell
vulncat --session-file .validation-temp/demo-session.json login --username demo-admin
python examples/service-exposure/load.py --session-file .validation-temp/demo-session.json --disposable-confirm
vulncat --session-file .validation-temp/demo-session.json --format json exposure report --limit 50
vulncat --session-file .validation-temp/demo-session.json --format csv exposure report --limit 50
vulncat --session-file .validation-temp/demo-session.json --format markdown exposure report --limit 50
```

Open **Services** to inspect the same report, download its current page, and review an attribution with a node picker. The loader also appends an older Windows fingerprint to East worker A's topology history; the current Ubuntu projection remains. Under MCP, `exposure_report` returns the same report payload and the requested rendering. See [CLI/MCP setup](../../docs/cli-mcp.md).

The loader changes data, requires the explicit disposable flag, accepts only the fixed local application on port 8787, and rejects a previously loaded example. Its signed preview, revision and request keys use the ordinary authenticated API. Do not run it against an instance containing operational data.
