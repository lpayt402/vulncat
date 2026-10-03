# Synthetic offline reconciliation examples

These synthetic records represent a hypothetical environment. These examples test the application contract; they do **not** certify vendor CSV/JSON compatibility. All hosts use `.example.test`; addresses are reserved for documentation. No employer data is included.

Open **Imports → Offline reconciliation preview**, select the example files, and configure each file's source and instance. Use `profiles.json` as a readable mapping reference (it is also consumed by the fixture tests). Map columns with the dropdowns. The JSON files have `resources` or `results` envelopes; select the indicated records path. Infrastructure inventory maps a separate object type column to distinguish device and VM IDs.

The examples include a renamed endpoint-security asset, conflicting hardware on a duplicated agent ID, endpoint management vulnerable/ignored source statuses, an infrastructure-inventory update timestamp, a directory last-logon/DNS-derived IP, repeated inventory observations, a malformed inventory row and DNS/scan coverage failures. Empty scanner XML hosts remain inventory evidence. Compare the review explanations; nothing is written to inventory, findings or the existing identity review queue.

Configured JSON paths must exist in each record. The synthetic endpoint-security rows with no software detail include explicit null `app.name`/`app.version` leaves; a missing `app` object would instead be a mapping error. These leaves demonstrate the application policy, not a verified vendor export shape. See the [null, missing-field, record-kind and format policies](../../docs/offline-source-formats.md#explicit-validation-policy-offline-v2). Infrastructure inventory IP/interface object IDs are unsupported asset identifiers; only device/VM namespaces qualify for automatic matching.

Run the reproducible 5,000-asset benchmark from the repository root:

```powershell
$env:PYTHONPATH='backend'
python scripts/validation/benchmark_reconciliation.py --assets 5000
```

The benchmark uses in-memory synthetic source evidence and reports elapsed time, peak Python allocations, row/error/duplicate counts, candidate checks and response page size. It does not measure production database throughput or browser interaction time.
