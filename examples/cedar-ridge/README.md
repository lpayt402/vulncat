# Hypothetical shipment-processing triage

This hypothetical shipment-processing environment illustrates what to verify before putting a finding into a maintenance plan. Host records, participant labels, scanner outputs, plugin IDs and exception notes are synthetic inputs for the scenario. Addresses use RFC 5737 documentation ranges and hostnames use `.test`. These files are parser inputs, not scan targets or vendor advisory claims.

## What the inputs show

| Input | Situation | What to check |
| --- | --- | --- |
| `scanner.csv` | Parcel Label Service offers TLS 1.0. The same host also has a High finding. | Keep the Medium backlog item; show the High row in import counts even though the default inventory scope skips it. |
| `scanner.nessus` | A second scanner reports the same label service at a changed IP and assigns TLS a higher severity. | Review identifier history and source evidence. Scanner source is part of finding identity; do not collapse the two reports into one assertion. |
| `scanner.json` | A database listener has a Low finding with an older First Found date. | SLA age starts from First Found, not the later scan/upload date. |
| `generic.csv` | One row has an owner note and another says no owner field was exported. | The note column is deliberately unmapped. Assign ownership only after review; an absent owner remains unknown. |
| `triage-notes.csv` | A proposed maintenance date and a time-limited exception need follow-up. | These are companion notes, not automatically imported fields or enforced exception expiry. |

Plugin IDs are synthetic and CVE fields are blank. Participant names are example labels, not customer or employer identities.

## Try the offline parser check

From the project root, with the backend dependencies installed:

```powershell
$env:PYTHONPATH='backend'
python examples/cedar-ridge/validate.py
```

The check reads only these local files. It verifies normalized identifiers, source-specific severity, skipped High rows, dates, and the unmapped owner note.

To review them in the application, start a fresh disposable instance, import each supported file, and inspect Imports, Hosts, Findings, and Identity review. Do not mark a partial weekly export as complete/comparable solely to clear missing findings. Record ownership and acceptance decisions in the supported host/finding notes after reviewing them. A scheduled change or accepted exception is not evidence that a fix happened.
