# Vulncat: Vulnerability Concatenator

```text
   /\_/\
  ( o.o )   Vulncat
   > ^ <    Vulnerability Concatenator
   /| |\
```

Vulncat combines offline vulnerability findings, inventory records and scan coverage. Each
observation retains its source, timestamps and uncertainty. Hosts, application endpoints
and shared VIPs have separate findings and coverage, even when they share an address.

Import supported scanner files or map offline endpoint-security, endpoint-management,
infrastructure-inventory, directory and other inventory records. Review uncertain asset
matches and conflicting observations.
A finding on a shared VIP stays on that VIP until evidence supports another attribution.
Failed scans, stale DNS and missing observations remain evidence gaps; they cannot retire
assets or resolve findings.

In Imports, Offline reconciliation preview shows proposed matches. Save evidence retains
immutable source observations for reversible assignment, correction, merge and split
decisions. Services supports topology imports, per-row attribution review, source history
and guarded undo. [Format support](docs/offline-source-formats.md) identifies tested adapters
and configurable mappings whose source schemas remain unverified. Bundled examples describe
hypothetical environments using synthetic data; they do not describe an employer or customer stack.

The [CLI and optional stdio MCP adapter](docs/cli-mcp.md) use the browser's API and
permissions. A shared formatter exports exposure report pages as JSON, CSV or Markdown.
The [Cedar service examples](examples/service-exposure/README.md) cover VIPs, SNI,
load-balanced applications, appliance planes, scope collisions and conflicting fingerprints.
See [service exposure](docs/service-exposure.md) for attribution, report and migration rules.

Vulncat processes supplied files and topology. Live source connectors,
active probes and additional hosted services are not implemented. The Medium/Low
maintenance backlog and XLSX, CSV ZIP and printable HTML reports remain available.

Interactive CLI launches choose from three original cat banners and write art only to
stderr. Use `vulncat --quiet ...` or `--no-cat` to suppress it. Redirecting any standard
stream also suppresses art. JSON, CSV and Markdown exports and stdio MCP remain banner-free.

## Installation compatibility

The repository is `lpayt402/vulncat`. The Python distribution
`vulnerability-workbench`, module `vulnbatch`, Workbench-named Windows shortcuts, Docker
Compose project and volumes, database defaults, session cookies, environment variables
and MCP tool names retain their identifiers. Existing installations and stored data remain
accessible. Preferred commands are `vulncat`, `vulncat-mcp` and `vulncat-worker`; the
original commands and launcher shortcuts also work. Storage migration requires a
separate operation.

## Local Windows setup

You need:

1. A Windows 10 or 11 computer.
2. [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
3. This entire Vulncat folder. Do not move only the `.bat` files.

Then:

1. Double-click **`Start Vulncat.bat`**.
2. Keep the window open during the first build. The first start can take several minutes.
3. Your browser opens to [http://localhost:8787](http://localhost:8787).
4. Create your administrator account. There is no default username or password.

During startup, the launcher:

- starts Docker Desktop when it can;
- creates `.env` with unique random secrets on the first run;
- checks the configuration;
- builds and starts the database, web application, and background worker;
- applies database migrations; and
- waits for the readiness check to pass.

The launcher starts the local Docker application. Image builds download dependencies; the running application does not call scanner APIs or send telemetry. Use the launcher under your existing Windows execution policy.

## Daily use

- Start: double-click **`Start Vulncat.bat`**.
- Open: visit [http://localhost:8787](http://localhost:8787).
- Check: double-click **`Vulncat Status.bat`**.
- Stop: double-click **`Stop Vulncat.bat`**.

Stopping Vulncat preserves its database, uploads, and reports. Starting it again brings the same data back.

Never run `docker compose down -v` with important data. The `-v` option permanently deletes the Vulncat
database, original uploads, and generated reports.

## Import scans and generate a report

1. Sign in as the administrator.
2. Open **Imports**.
3. Choose Scanner CSV, Scanner JSON, Scanner XML (.nessus), or Generic CSV with mapping.
   The fixed scanner formats and accepted schemas are listed in [import formats](docs/import-formats.md).
4. Upload the file. Generic CSV first shows a mapping preview.
5. Review the import summary and any identity-review warnings.
6. Open **Identity review** and resolve ambiguous hosts. Vulncat does not silently merge ambiguous assets.
7. Open **Hosts** to filter the full server-side inventory.
8. Select rows on the current page, or choose **Export all matching** to include the full filtered result.
9. Review the host and finding counts, submit the report, and download it from **Exports**.

Reports are available as XLSX, a ZIP of CSV files, and printable HTML. XLSX includes **Host Summary**,
**Finding Detail**, and **Export Metadata** sheets.

## Accounts

The first person creates the first administrator account in the browser. Administrators can add named
administrator or read-only accounts under **Users**.

Use a password with at least 14 characters. Do not share one administrator account among several people.
Read-only users can view data and create/download their own reports, but cannot import data, resolve identity,
change settings, or manage users.

## Backups

Double-click **`Back Up Vulncat.bat`** to create a timestamped PostgreSQL database dump and checksum in the
`backups` folder.

A complete recovery set includes the original-upload and generated-report Docker volumes as
well as the database dump. The backup shortcut prints that requirement when it finishes.
Follow [backup and restore](docs/backup-restore.md) before upgrading. Restore runs from the
command line and requires confirmation because it replaces the target database.

## Updating or rebuilding

After replacing application files with a newer Vulncat version:

1. Take a complete backup.
2. Double-click **`Stop Vulncat.bat`**.
3. Double-click **`Start Vulncat.bat`**.

The launcher rebuilds the local image and applies forward database migrations. Do not replace `.env` unless
you are rotating the application secrets and have planned for the session and database consequences.

## Startup troubleshooting

Try these in order:

1. Open Docker Desktop and wait until it says the engine is running.
2. Double-click **`Start Vulncat.bat`** again.
3. Double-click **`Vulncat Status.bat`**.
4. Confirm another application is not using port 8787.
5. Read [Troubleshooting](docs/troubleshooting.md).

The launcher does not delete data when it fails. Recent service logs are shown when startup cannot complete.

## Start from a terminal

Run this command from the repository root:

```powershell
.\scripts\Start-Vulnerability-Workbench.ps1
```

To validate Compose configuration and build the application directly:

```powershell
docker compose config --quiet
docker compose up -d --build
```

The default application address is `http://localhost:8787`. Interactive OpenAPI documentation is available
locally at `http://localhost:8787/docs`; do not expose the default localhost deployment to an untrusted
network.

## Development and validation

Backend checks use Python 3.12 or newer and the development dependencies in `pyproject.toml`:

```powershell
$env:PYTHONPATH='backend'
python -m pip install '.[dev,mcp]'
python -m pytest -q
python -m ruff check backend tests scripts/validation examples
python -m mypy backend
python examples/cedar-ridge/validate.py
```

Frontend checks use the committed lockfile:

```powershell
npm --prefix frontend ci --ignore-scripts
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
```

The API validators change application data. Run them only against a disposable stack populated with synthetic inputs. Set `VULNERABILITY_WORKBENCH_DISPOSABLE_TEST=1` and an explicit `VULNERABILITY_WORKBENCH_TEST_BASE_URL`. Supply fresh test credentials through environment variables; no fixed validation passwords are included.

The original import checks are recorded in [VALIDATION.md](VALIDATION.md). Later
[persistence](docs/persistent-validation.md) and [service/CLI/MCP checks](docs/service-validation.md)
have their own evidence records. Production capacity, streaming JSON imports and complete
browser coverage remain unverified. See [the feature map](docs/requirements-traceability.md)
for implementation and validation gaps.

## Documentation

- [Requirements traceability](docs/requirements-traceability.md)
- [Architecture](docs/architecture.md)
- [CLI and MCP](docs/cli-mcp.md)
- [Service exposure](docs/service-exposure.md)
- [Service/CLI/MCP validation](docs/service-validation.md)
- [Asset identity](docs/asset-identity.md)
- [Finding lifecycle, maturity, and SLA](docs/finding-lifecycle.md)
- [Host query and exports](docs/host-query-exports.md)
- [Import formats](docs/import-formats.md)
- [Security](docs/security.md)
- [Backup and restore](docs/backup-restore.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

The repository is private and has no project license file. Dependency names and license
metadata are retained. Confirm source ownership and choose a project license before public release.
