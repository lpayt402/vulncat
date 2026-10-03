# CLI and stdio MCP

Vulncat (Vulnerability Concatenator) uses rotating original cat art on interactive CLI launches.
Art goes to stderr only, and is suppressed whenever stdin, stdout or stderr is redirected.
Use `--quiet` (or compatible `--no-cat`) before the subcommand to hide it. Errors and mutation
confirmation prompts remain visible. The `mcp` subcommand and `vulncat-mcp` never print banners.
Use `vulncat-mcp` and `vulncat-worker` for the branded adapter and worker entry points;
their `vulnerability-workbench-*` aliases and existing MCP tool names remain compatible.

The installable CLI and MCP adapter use the authenticated HTTP API that serves the
GUI. They share one API client and the server's existing reconciliation/exposure
services, permissions, audit history, idempotency keys and concurrency checks.
New inventory and exposure operations never write directly to the database.

Install Python 3.12 or later, then install this project from a trusted local
checkout or its wheel:

```console
python -m pip install .
python -m pip install '.[mcp]'
```

The first command installs the base CLI. The second also installs the optional
official MCP SDK. `vulnerability-workbench` and `vulncat` invoke the same CLI;
legacy `create-user`, `create-admin`, and `reset-admin-password` commands retain
their database bootstrap behavior and existing arguments. Those bootstrap
commands still require backend database configuration.

The optional dependency is `mcp>=1.30,<2`. The official SDK's
[migration guide](https://py.sdk.modelcontextprotocol.io/migration/) states that
the 1.x maintenance line continues receiving critical fixes and security patches.
This adapter uses its FastMCP interface and initialization protocol; the
[1.30.0 release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v1.30.0)
is the tested minimum. SDK 2 has breaking API and dependency changes and requires
a separately tested migration. The adapter uses the official `mcp` package.

## Authentication and configuration

Start the Vulncat API first. Its default Docker/public origin is
`http://127.0.0.1:8787`. Global CLI options go **before** the command:

```console
vulncat --session-file /private/workbench-session.json login --username analyst
vulncat --session-file /private/workbench-session.json status
vulncat --session-file /private/workbench-session.json logout
vulncat discover
```

On Windows, substitute a private absolute path such as
`C:\Users\your-name\AppData\Local\workbench-session.json`; its parent directory
must already exist. Use the existing workbench username and password. Interactive
login prompts without echo. Automation can provide **one password line** through
stdin with `login --username analyst --password-stdin`. Login has no password
argument or embedded API token. Avoid putting passwords in shell command text or
history. Successful login/status outputs contain only the authenticated flag and
user summary; cookies and CSRF tokens never appear in output.

`--session-file` is explicit: the client neither searches browser storage nor
loads credentials from the working directory. Files bind the session to the
exact normalized API origin, store expiry, and reject unexpected fields,
malformed credentials, symbolic links and excessive size. New Windows session
files receive a protected DACL permitting only the current user and SYSTEM;
existing files must belong to that user and pass the same access check. POSIX
files must belong to the current user and have private `0600` permissions.
Logout revokes the backend session and removes its local file. Sessions remain
subject to backend expiry, account state, role and login throttling.

Use `--api-url https://workbench.example` to select another existing API origin.
The client rejects URL credentials, paths, queries, fragments and unsupported
protocols; HTTP is allowed only for loopback origins. The selected origin stays
fixed throughout the process. Requests do not follow redirects or discover
proxies from environment variables. `--timeout` accepts 1-120 seconds and defaults
to 30. No adapter command starts another HTTP listener.

## CLI reads and reports

```console
vulncat --session-file /private/workbench-session.json assets list --q server --limit 50
vulncat --session-file /private/workbench-session.json reconciliation review --review-status open
vulncat --session-file /private/workbench-session.json reconciliation observation --id OBSERVATION_UUID
vulncat --session-file /private/workbench-session.json reconciliation decisions
vulncat --session-file /private/workbench-session.json reconciliation decision --id DECISION_UUID
vulncat --session-file /private/workbench-session.json exposure nodes
vulncat --session-file /private/workbench-session.json exposure nodes --q gateway --kind load_balancer
vulncat --session-file /private/workbench-session.json exposure node --node-id NODE_UUID
vulncat --session-file /private/workbench-session.json exposure graph --node-id NODE_UUID
vulncat --session-file /private/workbench-session.json exposure history --node-id NODE_UUID
vulncat --session-file /private/workbench-session.json --format csv exposure report --observation-kind coverage > coverage.csv
vulncat --session-file /private/workbench-session.json --format markdown exposure report > exposure.md
```

Paged commands accept `--offset` and `--limit` (1-500). Each invocation returns
one page so a caller can inspect revision and total metadata before requesting
more. `reconciliation review` also accepts `--asset-id`, `--source`, and
`--review-status all|open|deferred|assigned|rejected`. Graph, report and history
reads accept `--node-id`; node discovery accepts `--q` and
`--kind host|device|load_balancer|vip|service|endpoint`. Node detail accepts
`--fact-offset` and `--fact-limit`; graph additionally accepts
`--relationship-offset` and `--relationship-limit` (default 100).
Report rows can additionally filter by
`--observation-kind inventory|vulnerability|coverage`.

JSON is the default machine format and keeps the complete response envelope.
CSV and Markdown render the current page's `items`. Exposure reports use the
same renderer and stable columns as the GUI/API export:

```text
observation_id, observation_kind, vulnerability_id, native_status, coverage_outcome,
source, instance, observed_at, imported_at, age_days, time_warning, time_meaning, asset_id, asset_name,
node_id, node_kind, node_label, service_id, service_label, network_scope, protocol, port,
dns_name, sni, attribution_id, attribution_version, attribution_status,
attribution_reason, evidence
```

JSON null remains null. Tabular null/missing cells are empty; nested cells use
compact JSON with sorted keys. CSV quotes commas, quotes and newlines correctly.
For spreadsheet safety, formula-looking **string** cells beginning with `=`,
`+`, `-`, or `@` after whitespace receive a leading apostrophe; numeric negative
values retain their numeric text. Markdown escapes pipes and HTML and renders
line breaks as `<br>`. Control characters unsafe for terminals are escaped.
Generic tabular read commands infer a sorted column set from the returned page;
use JSON when exact metadata or optional fields matter.

Inventory, vulnerability and coverage observations remain separate report
kinds. A failed/unreachable scan is coverage evidence, not proof that a
vulnerability is absent. Native source statuses, source/instance, timestamps,
time meaning, attribution status and evidence are retained.
Future source timestamps leave age unknown and include a `time_warning` for clock
review; the client preserves that warning rather than inventing a negative age.

Stdout contains results; diagnostics go to stderr. Exit codes are `0` success,
`2` invalid input or missing explicit confirmation, `3` authentication/permission
or throttling, `4` stale/conflicting state, and `5` transport/server failures.
Piped help and machine output contain no decoration. A small original cat may
appear only in interactive help/about; `--no-cat` disables it.

## Reconciliation preview and import

Create an `options.json` array with one SourceOptions object per file, in the
same order as repeated `--file` arguments. Example for a synthetic CSV:

```json
[
  {
    "source": "inventory",
    "instance": "synthetic-lab",
    "format": "csv",
    "time_meaning": "source_observed",
    "mapping": {"native_id": "id", "hostname": "hostname", "observed_at": "observed_at"}
  }
]
```

Sources are `crowdstrike`, `pdq_connect`, `nessus`, `netbox`, `active_directory`,
or `inventory`. Formats are `csv`, `json`, `ndjson`, or `nessus_xml`. Use explicit
column mappings for the actual export format; source labels do not assert a
verified vendor schema. JSON envelopes can specify `records_path`. Optional
`network_scope` prevents mixing address/name scopes. `time_meaning` supports
`source_observed`, `record_updated`, `last_logon`, `export_snapshot`, or `unknown`.
Nessus XML requires source `nessus` and the fixed adapter, without a mapping.

```console
vulncat --session-file /private/workbench-session.json reconciliation columns --file inventory.csv --input-format csv
vulncat --session-file /private/workbench-session.json reconciliation preview --file inventory.csv --options options.json > preview.json
vulncat --session-file /private/workbench-session.json reconciliation import --file inventory.csv --options options.json --preview preview.json --request-key lab-import-001 --confirm
```

Inspect the preview before importing. Keep its JSON `revision` and signed
`preview_token`. Import submits the exact file bytes and source options with
that token, expected revision and a unique request key. The server checks that
the reviewed payload and actor match. A changed file, stale revision, invalid
token or expired preview must be reviewed again. Retry the exact same operation
with the same request key when its result is uncertain; do not reuse a key for
a different operation.

File operations accept 1-8 nonempty regular local files, each at most 10 MiB and
at most 30 MiB combined. JSON configuration/decision/graph documents are limited
to 2 MiB. API responses are limited to 8 MiB; request a smaller page if needed.
Input files, session files and MCP input roots reject UNC, device and URI paths
before filesystem lookup. Paths must not traverse symbolic links, junctions or
other reparse points. MCP checks lexical root containment before metadata and
checks resolved containment before reading; paths on another drive are outside
the configured root. Regular relative local files remain supported.

All new persistent CLI mutations need `--confirm` or interactive typed `yes` on
a terminal. An unattended command without `--confirm` exits before sending a
write. This does not override the administrator role or CSRF checks. Preview and
column discovery are transient but use the existing API's administrator
authorization requirement.

Reconciliation decisions use the existing DecisionRequest shape:

```json
{
  "action": "defer",
  "request_key": "lab-defer-001",
  "reason": "Review the source evidence before choosing an asset",
  "expected_revision": 12,
  "observation_ids": ["00000000-0000-4000-8000-000000000001"],
  "expected_versions": {"00000000-0000-4000-8000-000000000001": 1}
}
```

```console
vulncat --session-file /private/workbench-session.json reconciliation decide --document decision.json --confirm
```

Replace the illustrative UUID/revision/version with the current review response.
Supported actions are `assign`, `create`, `reject`, `defer`, `merge`, `split`, and
`undo`. Depending on the action, include `source_asset_id`, `target_asset_id`, or
`undo_decision_id`. The backend validates applicable IDs, observation versions,
reason, revision, conflicts and undo eligibility exactly as it does for the GUI.

## Exposure preview, apply and undo

An exposure graph document uses GraphEnvelope: `source`, `instance`, optional
`observed_at`/`source_version`, `time_meaning`, `intent`, and arrays `nodes`, `relationships`,
and `attributions`. Node refs are local graph references or existing node UUIDs.
Node facts include kind/label, optional canonical `asset_id`, protocol/port,
DNS/SNI/IP/network scope, native ID, active state and expected version.
Relationships use `endpoint_of`, `backed_by`, `routes_to`, `hosted_on`, or
`management_of`, `from_node`, `to_node`, optional versions and evidence.
Attributions include observation ID, node ref when attributing, status
`attributed` or `review_needed`, reason, expected version and evidence. Graph
time meaning is `source_observed`, `export_generated`, or `unknown`.

`intent` is `source_facts` by default. Use it for source exports and retain their
actual observation time and time meaning. Imports with unknown or stale dates
append immutable evidence while preserving current node, relationship and
attribution state. Do not replace missing source times with the import time to
make an old export appear newer.

For a deliberate human correction, set `"intent": "manual_correction"` in the
graph JSON. This explicitly authorizes the reviewed change to asset bindings,
active state or observation attributions while retaining newer dated source
facts and their provenance. Include the current expected versions for existing
nodes, relationships or attributions; preview the correction and inspect its
before/after changes before applying it with the signed token and revision.
The CLI and MCP pass this intent through to the same backend rules as the GUI.

```console
vulncat --session-file /private/workbench-session.json exposure preview --graph graph.json > graph-preview.json
vulncat --session-file /private/workbench-session.json exposure apply --graph graph.json --preview graph-preview.json --request-key lab-graph-001 --reason "Reviewed lab service relationships" --confirm
vulncat --session-file /private/workbench-session.json exposure undo --decision-id DECISION_UUID --expected-revision 14 --request-key lab-undo-001 --reason "Undo reviewed lab graph change" --confirm
```

Apply sends the signed token and revision from the preview, the exact graph, an
audit reason, request key and `confirmed=true`. Undo uses the current revision
and decision ID and is also explicitly confirmed. Preview shows proposed
before/after changes and warnings; history retains immutable decisions.

## Stdio MCP setup

Log in with the CLI first. Configure any stdio-capable MCP host to start the
installed executable; use absolute paths that the host can access:

```json
{
  "mcpServers": {
    "vulncat": {
      "command": "/absolute/path/to/vulncat-mcp",
      "args": [
        "--api-url", "http://127.0.0.1:8787",
        "--session-file", "/private/workbench-session.json",
        "--input-root", "/private/reviewed-imports"
      ]
    }
  }
}
```

The equivalent CLI startup is:

```console
vulncat --session-file /private/workbench-session.json mcp --input-root /private/reviewed-imports
```

This starts FastMCP over stdio only. Stdout is reserved for MCP protocol messages.
There is no HTTP/SSE listener, arbitrary HTTP request tool, login-password tool,
or per-call API-origin override. The host selects the origin and session at
startup. Local upload paths must resolve under `--input-root`, which defaults to
the process working directory.

Tools are `workbench_status`, `workbench_discover`, `assets_list`,
`reconciliation_columns`, `reconciliation_preview`, `reconciliation_import`,
`reconciliation_review`, `reconciliation_observation`, `reconciliation_decisions`,
`reconciliation_decision`, `reconciliation_decide`, `exposure_nodes`, `exposure_node`,
`exposure_graph`, `exposure_report`, `exposure_history`, `exposure_preview`,
`exposure_apply`, and `exposure_undo`. Their schemas are advertised by `tools/list`;
unknown arguments and invalid bounds are rejected.

Every tool returns structured content shaped as
`{"ok": true, "data": {...}, "error": null, "formatted": null}`. Read tools
supporting `format: "json"|"csv"|"markdown"` can also return formatted text,
without changing the structured `data`. Errors set `isError=true` and return
`{"ok": false, "data": null, "error": {"code": 3, "message": "..."}, "formatted": null}`,
using the same error codes as the CLI. Diagnostics avoid reflecting raw server
details or invalid caller arguments.

Persistent MCP writes are disabled at startup by default, even for administrators.
To authorize writes, add `--enable-writes` to the startup arguments. Each mutation
must also carry the literal boolean `confirm: true`; strings or integers are
rejected. Imports and exposure apply still require signed preview and revision.
Decision tools still require the API's request keys, revisions and versions.
For example, call `exposure_preview` with `{"graph": {...}}`, inspect
`structuredContent.data`, then pass that **data object** as the `preview`
argument to `exposure_apply` together with graph, request key, reason and
`confirm: true`. Do the same for reconciliation preview/import; do not pass the
outer MCP response envelope as the preview.

## Verification

```console
python -m pytest tests/unit/test_cli_client.py tests/unit/test_mcp_protocol.py
```

Protocol tests use the declared official SDK 1.30 minimum and launch an actual
stdio subprocess: initialize, list tools, call tools, structured output, invalid
parameters, authentication failures, conflict handling and disabled writes.
Client/parser tests exercise session permissions, origin restrictions, bounded
files/output, exact multipart uploads, signed-preview/revision propagation,
confirmation gates, credential redaction, report escaping and legacy bootstrap
commands. Their credentials and observations are disposable synthetic fixtures.
