# Backup and restore

## Recovery data

A complete Vulncat recovery set contains three independent data classes:

1. PostgreSQL (`vulnerability-workbench_postgres_data`): users, audit history, imports, normalized evidence, assets,
   findings, identity decisions, jobs, saved views, and export metadata.
2. Immutable source uploads (`vulnerability-workbench_uploads`): the original scan files referenced by database storage
   paths.
3. Generated reports (`vulnerability-workbench_reports`): downloadable export artifacts referenced by export metadata.

A PostgreSQL dump alone is not a complete backup because it does not contain the original uploads or generated
reports. Report files can be regenerated only while the necessary snapshot data remains; original uploads are
required evidence and should not be assumed reproducible.

## PostgreSQL backup

Run from the repository root while `db` is healthy. The helper writes a compressed PostgreSQL custom-format
dump inside the database container directly to the host `BACKUP_DIR`. It also writes a SHA-256 sidecar when
`sha256sum` is available.

PowerShell:

```powershell
.\scripts\backup-db.ps1
```

POSIX:

```sh
./scripts/backup-db.sh
```

Choose a stable filename:

```powershell
.\scripts\backup-db.ps1 -FileName vulnerability-workbench-before-upgrade.dump
```

Equivalent direct command:

```powershell
docker compose exec -T db sh -c 'umask 077; pg_dump --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --format=custom --compress=6 --no-owner --no-acl --file=/backups/vulnerability-workbench.dump'
```

Do not redirect a custom-format dump through Windows PowerShell. Windows PowerShell 5 may treat native
standard output as text and corrupt the binary dump.

## Upload and report volume backup

Use a storage-level snapshot or Docker volume backup process approved for the host. For a consistent
application backup, stop writers first:

```powershell
docker compose stop web worker
.\scripts\backup-db.ps1 -FileName vulnerability-workbench-consistent.dump
```

Then snapshot or archive both `vulnerability-workbench_uploads` and `vulnerability-workbench_reports` before restarting:

```powershell
docker compose up -d web worker
```

If the Docker platform provides volume snapshot/export features, use them. Otherwise, copy from stopped
containers into a protected backup location:

```powershell
docker compose cp -a web:/data/uploads .\backups\volume-copy\
docker compose cp -a web:/data/reports .\backups\volume-copy\
```

Test the exact volume-copy procedure on the deployment platform. Preserve file names, content, and directory
structure. Encrypt backups at rest, restrict access, and store at least one recovery copy outside the Docker
host.

## Restore safety

Restore is destructive. Always:

- restore into a disposable environment first;
- retain the current database and volume backups until verification completes;
- use the same or a newer Vulncat application version;
- verify the dump checksum;
- stop `web` and `worker` so no writes occur;
- restore uploads and reports from the same recovery set;
- let web apply forward-only Alembic migrations after the restore;
- validate counts, evidence downloads, audit history, and an export before reopening access.

The helpers require an explicit confirmation flag, stop writers, replace the configured database, restore with
`--exit-on-error`, and restart web and worker only after `pg_restore` succeeds.

PowerShell:

```powershell
.\scripts\restore-db.ps1 -FileName vulnerability-workbench-consistent.dump -ConfirmReplaceDatabase
```

POSIX:

```sh
./scripts/restore-db.sh vulnerability-workbench-consistent.dump --confirm-replace-database
```

If restore fails, web and worker remain stopped. Inspect the error before retrying. Do not initialize a blank
replacement and declare recovery complete.

## Restoring upload and report volumes

Restore the matching upload and report archives before allowing users to sign in. With stopped application
containers and a previously created `docker compose cp` backup:

```powershell
docker compose cp -a .\backups\volume-copy\uploads\. web:/data/uploads/
docker compose cp -a .\backups\volume-copy\reports\. web:/data/reports/
```

Verify ownership and write access by starting web and checking `/readyz`, then run a disposable upload and
export test. If Docker changes copied ownership on the deployment platform, use the platform's volume-restore
facility rather than running the application container as root.

## Recovery verification

After restore:

```powershell
docker compose ps
Invoke-RestMethod http://localhost:8787/readyz
docker compose logs --tail 100 web worker db
```

Verify:

- administrator login and role boundaries;
- import, asset, finding, identity-review, export, and audit counts;
- original source-file download/read access and SHA-256 values;
- a previously generated report and its recorded hash;
- creation and download of a new report;
- worker queue progress;
- Alembic is current: `docker compose exec web alembic current --check-heads`.

Document the recovery point, dump hash, volume snapshot identifiers, application version, validation results,
and operator.

## Retention

Default policy keeps original uploads, normalized import evidence, and audit logs indefinitely. Blank
`UPLOAD_RETENTION_DAYS`, `IMPORT_EVIDENCE_RETENTION_DAYS`, and `AUDIT_RETENTION_DAYS` values mean no automatic
deletion. Generated reports default to 30 days through `EXPORT_RETENTION_DAYS`; export metadata and audit
history remain after artifact expiry.

Retention is not a backup. Take backups before upgrades and before enabling or changing any destructive
cleanup policy.
