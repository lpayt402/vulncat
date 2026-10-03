# Offline source formats and schema verification

Checked against official documentation on 2026-10-02. Offline reconciliation previews mapped files before **Save evidence** persists their observations and locators. Existing Tenable/Nessus/generic durable imports retain their workflows. No live directory, inventory, vendor connection or active probe is used.

All new mapped inputs require a source instance (the tenant, directory, infrastructure inventory installation or spreadsheet collection). Choose a consistent label. Native identifiers remain scoped by source, instance and native ID kind; never put these IDs into Tenable or generic agent UUID fields. For NetBox, distinguish `dcim.device` and `virtualization.virtualmachine`: their numeric IDs can overlap. Without an ID-kind column, its object IDs remain review evidence.


## Source labels and compatibility identifiers

The interface uses generic source categories. Existing API identifiers remain unchanged
so saved observations, scripts and source-scoped identities keep working. A category
does not add adapters or certify a native vendor export. Configure the documented mappings
for the actual supplied file; use the schema limits below. These supported identifiers
describe compatibility, not any author's, employer's or customer's software stack.

| Interface category | Existing API source | Native identifier kind |
| --- | --- | --- |
| Endpoint security | `crowdstrike` | `aid` |
| Endpoint management | `pdq_connect` | `device_id` |
| Scanner observations | `nessus` | `host_id` |
| Infrastructure inventory | `netbox` | Explicit `dcim.device` or `virtualization.virtualmachine` for automatic matching |
| Directory records | `active_directory` | `object_guid` |
| Inventory | `inventory` | `inventory_id` |

Scanner XML (.nessus) is the documented Nessus XML subset, with source `nessus`,
format `nessus_xml` and fixed field mapping. It does not accept arbitrary scanner XML.

## Supported input contract

- UTF-8 CSV with exact column mappings; JSON arrays; JSON envelopes with a selected records path; streaming NDJSON; a documented subset of Nessus ReportHost/ReportItem XML.
- Each logical record describes inventory, a vulnerability occurrence or scan coverage. Inventory rows require no vulnerability. Vulnerability rows need `vulnerability_id`, with separate optional native occurrence ID, package/version and port/protocol. All native statuses are retained without interpreting them as remediation.
- Source observation times must be ISO 8601 with an explicit timezone. Missing time remains unknown; malformed or naive time is a row error. Source record update, export time and last-logon time are recorded but do not establish freshness for automatic matching. Nessus timezone-free text timestamps remain raw and unknown; ISO timestamps or epoch seconds have explicit interpretation.
- IP addresses accept CIDR or bare address, lists in JSON or semicolon-separated CSV values. A network scope distinguishes overlapping address spaces. Hostnames retain normalized FQDN and shortname separately. Neither hostnames nor IP/MAC addresses can automatically identify assets.
- Canonical field names in [adapters.py](../backend/vulnbatch/reconciliation/adapters.py) describe an application contract, not vendor CSV header names. Choose columns through the UI. `records_path` selects an envelope such as `resources` or `results`; mappings support dotted nested JSON fields.
- Exact duplicate event fingerprints are counted without extra proposals. Fingerprints include source/instance, parser/mapping configuration and raw evidence, excluding file position/hash and import time. Saved evidence deduplicates observations while retaining each supported row's locator. Actor/payload-bound import request keys replay the original result; see [persistent reconciliation](persistent-reconciliation.md).
- Limits: eight files, 10 MiB per file, 30 MiB combined, 100,000 logical records, response pages of 1-500 records (UI 50), and at most 50 reported row errors. CSV/NDJSON parse as iterators; the bounded preview stages observations to detect conflicts anywhere in the bundle. JSON arrays load in memory. Pagination recomputes the preview; there is no durable preview session.

## Explicit validation policy (offline-v2)

An invalid configuration returns HTTP 422. A bad logical record is included in the preview's error count and error sample, with no successful observation or identity proposal for that record; supported later records continue. HTTP 200 for a completed preview does not mean every row was supported. Check both the error count and the explanations.

| Input condition | Policy |
|---|---|
| Unknown configuration option or canonical mapping key | Reject the configuration. Vendor CSV headers belong on the mapping's source-column side, not its canonical-field side. |
| Blank/whitespace configured mapping path | Reject the configuration; omit unused mappings. Exact CSV headers and exact JSON keys win before dotted-path traversal. |
| Configured source path missing from a JSON/NDJSON record | Row error names the canonical field and unresolved path, including optional fields. A missing key, scalar/list intermediate value or null intermediate object cannot silently become an empty mapped leaf. Split incompatible export shapes or flatten them offline into the declared contract. |
| Configured CSV header missing | Reject the file. Blank cells are different from absent headers. |
| No custom mapping | Read canonical field names only. Absent optional canonical fields remain absent; there is no guessing of vendor header names or nested schemas. |
| Present null or blank optional scalar leaf | Retain raw input and treat the optional normalized value as absent. Missing/null observation time stays unknown and never substitutes import time. A null intermediate object does not satisfy a nested leaf mapping. |
| Unsupported scalar shapes | Objects/lists mapped to scalar fields are row errors even when empty or attached to inventory. Boolean JSON native/hardware IDs reject instead of becoming the shared text identifiers True/False; integer native IDs remain supported. |
| Required values | At least one usable asset identifier is required. Vulnerability records require a nonblank `vulnerability_id`; coverage records require an explicit `coverage_outcome` (use `unknown` when appropriate). A present/mapped `kind` must be nonblank and one of the three supported values. |
| CVE values | Accept a string separated by commas/semicolons or a JSON list of nonempty strings; trim, uppercase and deduplicate. A whole null/blank field or empty list means no CVEs supplied. Objects, nested lists, numbers, booleans and null/blank list members are row errors, never stringified into CVE evidence. This validates representation, not existence in a CVE registry. |
| Extra unmapped vendor fields | Preserve them in raw evidence; they do not establish normalized identity, findings, coverage or vendor compatibility. Explicitly mapped unsupported structures reject. |

When `kind` is omitted, nonempty canonical vulnerability fields or declared vulnerability mappings imply a vulnerability record, and coverage fields/mappings imply coverage. Vulnerability details without an ID reject; a configured null vulnerability ID cannot quietly become inventory. If neither category is declared, infer inventory. A record declaring both categories without an explicit kind rejects. An explicit kind rejects nonempty fields from another category: for example, inventory plus `vulnerability_id`, or vulnerability plus `coverage_outcome`. Optional null/blank fields from another category carry no assertion. `False` and port zero are supplied values, not blanks: inventory plus `complete=false` is a kind conflict. `title`, `severity`, software/package, occurrence, CVE and port/protocol fields in this contract describe vulnerabilities, not arbitrary inventory labels.

Failed/unreachable/DNS-failed/partial/unknown coverage cannot claim completeness. No outcome is inferred from a record update or from vulnerability absence. Mixed export tables should supply a valid `kind` per row and null/blank values for inapplicable optional fields, or be separated into files with consistent mappings.

`records_path` is supported **only for JSON document envelopes**, must be nonblank when provided and must select an array. Omit it for a top-level JSON array. CSV, NDJSON and Nessus XML reject it, including an explicitly provided empty string. Nessus XML also requires source `nessus` and its fixed adapter; custom mappings reject. The UI hides the path control for other formats and clears incompatible paths/mappings when changing formats. Parser provenance is `offline-v2`, so fingerprints explicitly distinguish this stricter normalization contract from earlier previews. The approved additive persistence and review workflow is described in [persistent reconciliation](persistent-reconciliation.md).

For NetBox, only `dcim.device` and `virtualization.virtualmachine` native namespaces can support automatic asset matching. Explicit IP/interface/other object types reject as unsupported asset inputs. An omitted type is retained as `unspecified_object_type` and always requires review, even if hardware evidence also matches. IP records alone cannot establish device identity. Prepare independently justified device/VM join evidence and map the resulting asset ID; never rename an IP object ID as a device ID. Device and VM numeric IDs remain separate namespaces.

## Vendor references and mapping limits

| Source | Verified public shape or semantics | Mapping and compatibility gaps |
|---|---|---|
| CrowdStrike Spotlight | [Current reference](https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/) documents `resources[]`, top-level `aid`, `cid`, finding `id`, `status`, `created_timestamp`, `updated_timestamp`, `closed_timestamp` and distinct vulnerability IDs. | Full nested host/CVE/app fields and current status enums are not defined in public examples. Spotlight vulnerabilities differ from Falcon EDR detections. Fixtures use application-defined mapped fields; configure mappings for the actual authorized offline export. Update time alone is not host last seen. |
| PDQ Connect | [Reports](https://connect.pdq.com/hc/en-us/articles/19461944049947-Introduction-to-Reports) support CVE summary/device breakdown CSV templates, last-run data and time-window/resolved inclusion scope. [Vulnerabilities](https://connect.pdq.com/hc/en-us/articles/27819352522267-Vulnerabilities) distinguishes Vulnerable, Ignored and Resolved. | Exact CSV headers/IDs/timestamps are not published in article text. A CVE aggregate summary does not establish device occurrences. Ignored means accepted risk, not remediation. [API overview](https://connect.pdq.com/hc/en-us/articles/22929727991451-PDQ-Connect-API) does not establish a verified JSON export profile here. |
| NetBox | [REST format](https://netboxlabs.com/docs/netbox/integrations/rest-api/) uses numeric `id`, `results`, `count`, `next` and `previous`; IPs contain CIDR `address`, VRF and interface assignment fields. [CSV customization](https://netboxlabs.com/docs/netbox/features/customization/) permits view/custom templates. | Pin a mapping to the exported version and object type. Names and configurable status choices are not global identity. Interfaces/IP rows need explicit device/VM join evidence; an IP object ID cannot identify the assigned device. Fixtures cover mapped device records, not automatic interface joins or every NetBox object. |
| AD computers | [Get-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps) exposes ObjectGUID, SID, DNSHostName and selected properties. [Object model](https://learn.microsoft.com/en-us/powershell/module/activedirectory/about/about_activedirectory_objectmodel?view=windowsserver2025-ps) describes derived properties. | CSV columns/delimiters/date formats depend on [Export-Csv](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-csv?view=powershell-7.5) choices. This increment requires comma-delimited UTF-8 and timezone-qualified times; legacy #TYPE/UTF-16/culture-formatted exports must be converted offline. AD IPv4/IPv6 properties are DNS-derived, not authoritative historical address assignments. [Last-logon timestamps can lag](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/discovery/lastlogontimestamp-not-accurate); account enabled/disabled does not prove reachability or retirement. |
| Nessus | [Official export formats](https://developer.tenable.com/docs/export-file-formats) describe ReportHost/ReportItem XML; [Nessus export](https://docs.tenable.com/nessus/Content/ScanReportFormats.htm) includes targets, policy and scan results. | Fixed adapter reuses the existing normalized property/item extraction and hardened XML parser, while separately retaining full raw ReportHost attributes and HostProperties (including unknown and repeated properties) in the event fingerprint. It retains empty hosts as inventory, never clean scans. Does not interpret plugin output as coverage completeness/authentication or ingest every XML extension. Mapped Nessus CSV/JSON also work through the common contract. |
| Inventory spreadsheets | Application-defined mapped CSV preserves native inventory IDs and original rows. | Save a selected sheet as UTF-8 CSV; direct XLSX import, formulas, multiple sheets and fuzzy unreviewed matching are outside this increment. |

## Matching and status policy

The score `0.95` is a deterministic policy score for a unique fresh stable match, not a measured probability or a guarantee of vendor reliability. Every source mapping remains unverified unless independently validated. Native ID/hardware conflicts anywhere in the bundle are flagged before suggestions. Duplicate IDs across existing assets, reimage evidence, weak matches and stale/unknown/future time require review; saved observations remain in the durable review queue. A source-observed timestamp is an explicit import assertion; it is not independently verified.

`failed`, `unreachable`, `dns_failed`, `partial`, `unknown`, disabled AD objects, stale NetBox records, PDQ Ignored/Resolved and CrowdStrike expired/closed status remain source evidence. The preview does not retire assets, mark absence, close findings or execute a merge/split. Existing durable review/merge/split/undo remains separate and has its documented integration gaps. The additive migration was approved for this increment; see [persistent evidence and review](persistent-reconciliation.md) and [the architecture proposal](offline-reconciliation-design.md).

## Synthetic examples

[examples/offline-reconciliation](../examples/offline-reconciliation/README.md) models a hypothetical environment with synthetic hosts and documentation addresses. Endpoint-security and infrastructure JSON fixtures exercise explicit application mappings, not verified native exports. Endpoint-management and directory CSV fields are also application-defined mappings. Do not request or commit employer exports to validate these examples.
