# Troubleshooting

## Startup diagnostics

From the repository root:

```powershell
docker compose config
docker compose ps
docker compose logs --tail 150 db web worker
```

Do not post `.env`, scan contents, database dumps, exported reports, session cookies, source-file hashes, or
real host identifiers in public support channels.

## Compose reports a missing variable

`POSTGRES_PASSWORD` and `SECRET_KEY` are required and intentionally have no default. Copy `.env.example` to
`.env`, generate independent random values, and rerun `docker compose config`. Do not fill these with the
example variable names or a shared administrator password.

Use a hexadecimal PostgreSQL password. Characters such as `@`, `:`, `/`, `#`, or `%` require URL encoding
because the password is embedded in `DATABASE_URL`.

## Port 8787 is unavailable

Find the process or container using the port, or set a different host port:

```text
VULNERABILITY_WORKBENCH_PORT=8877
PUBLIC_URL=http://localhost:8877
```

Restart with `docker compose up -d`. The container still listens on 8787. The default bind address is
`127.0.0.1`; set `VULNERABILITY_WORKBENCH_BIND_ADDRESS` only when remote access and firewall/TLS controls are ready.

## Database never becomes healthy

Check:

```powershell
docker compose logs --tail 150 db
docker compose exec db pg_isready -U workbench -d workbench
```

Common causes are an invalid existing database password, a full disk, damaged volume, or insufficient memory.
Changing `POSTGRES_PASSWORD` in `.env` does not change the password stored in an already initialized
PostgreSQL volume.

Do not delete `vulnerability-workbench_postgres_data` to fix an authentication error. That destroys the application
database. Restore or rotate the database role password deliberately.

## Web exits during migration

Web waits for PostgreSQL and runs `alembic upgrade head` before Uvicorn. Inspect:

```powershell
docker compose logs --tail 200 web
docker compose run --rm --no-deps --entrypoint alembic web current
docker compose run --rm --no-deps --entrypoint alembic web heads
```

Back up before repairing a failed migration. Never stamp a revision merely to suppress an error unless the
database schema has been independently proven equivalent. Migrations must not silently merge, delete, or
reinterpret assets or findings.

## Worker refuses to start

Worker checks every Alembic head and exits if the database is not current. Start or repair web first:

```powershell
docker compose up -d web
docker compose logs --tail 150 web
docker compose up -d worker
```

If jobs remain queued, inspect worker logs and database/storage capacity. Retry must be idempotent; do not
manually mark jobs complete or duplicate export files.

## Health and readiness differ

- `/healthz` proves the application process is responding.
- `/readyz` also checks PostgreSQL and is the Docker health check.

A healthy process with failed readiness normally indicates database connectivity or migration trouble.

```powershell
Invoke-RestMethod http://localhost:8787/healthz
Invoke-RestMethod http://localhost:8787/readyz
```

## Upload fails

Check `MAX_UPLOAD_BYTES`, free space in `vulnerability-workbench_uploads`, file permissions, and the application import log.
The application rejects unsupported types, malformed records, oversized files, and unsafe XML. Renaming a file
extension does not make it a supported format.

Duplicate hashes return the earlier import rather than duplicating observations. Use force reprocessing only
for troubleshooting; it references the same immutable source file.

## Import is slow or appears stalled

Imports run asynchronously in worker. Check worker health, job progress, database CPU/I/O, and upload volume
space. For the required 100,000-row validation, start with:

```text
WORKER_CPU_LIMIT=2.0
WORKER_MEMORY_LIMIT=2G
DB_CPU_LIMIT=2.0
DB_MEMORY_LIMIT=2G
```

Increase limits only after measuring the synthetic load test. Streaming avoids whole-file memory use but does
not eliminate PostgreSQL index and workbook-generation memory. Do not promise a processing-time target without
benchmark evidence.

## Export fails or expires

Inspect export status/failure reason in the UI and worker logs. Export generation reads persisted asset and
finding snapshots; it must not re-run a mutable host query. A safe retry must reuse the snapshot and avoid
conflicting artifacts.

Confirm free space in `vulnerability-workbench_reports`, worker memory, and the configured large-export confirmation
threshold. Expired report files are removed according to `EXPORT_RETENTION_DAYS`, while audit/export metadata
remains.

Spreadsheet values beginning with formula markers are intentionally neutralized. This is not data corruption.

## Secure-cookie login loop

`SECURE_COOKIES=true` requires HTTPS. For the default plain HTTP localhost deployment use
`SECURE_COOKIES=false`. Behind a proxy, ensure:

- `PUBLIC_URL` is the externally visible HTTPS origin;
- the proxy forwards the original scheme and host;
- `FORWARDED_ALLOW_IPS` contains only trusted proxy addresses;
- HTTP and HTTPS origins are not mixed.

## Read-only filesystem error

The application root filesystem is intentionally read-only. Only `/tmp`, `/data/uploads`, and `/data/reports`
are writable. Code that attempts to write beside application modules is a defect; do not disable the
read-only root filesystem as a routine workaround.

## Backup or restore failure

Confirm `BACKUP_DIR` exists, has free space, and is writable by Docker Desktop/Engine. The database service
must be running for backup and checksum verification. Restore intentionally stops web and worker and leaves
them stopped when a destructive step fails.

See `docs/backup-restore.md`. Validate restoration in a disposable Compose project before using a production
recovery set.

## Data survives restart but not volume removal

`docker compose restart` and `docker compose down` preserve named volumes. `docker compose down -v` deletes the
database, uploads, and reports. Never use `-v` unless irreversible deletion is explicitly intended and a
verified recovery set exists.
