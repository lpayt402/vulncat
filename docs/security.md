# Security

## Deployment and sensitive data

Vulncat is designed for an internal administrative network or a security administrator workstation. The
default Compose configuration publishes only the web service, binds it to `127.0.0.1:8787`, and does not
publish PostgreSQL. Normal operation performs no telemetry, analytics, reverse DNS, scanner API access, or
other external enrichment.

Vulnerability scan files contain sensitive infrastructure details. Treat the PostgreSQL volume, upload
volume, report volume, backups, screenshots, and logs as confidential security data.

## Authentication and authorization

- Users are local database accounts. Passwords are hashed with Argon2id.
- No universal administrator username or password is included.
- Create the first administrator with a user-supplied password:

  ```powershell
  docker compose exec web vulnerability-workbench create-admin --username admin --display-name "Vulncat Admin"
  ```

- Reset an administrator password interactively:

  ```powershell
  docker compose exec web vulnerability-workbench reset-admin-password --username admin
  ```

- `administrator` users can import scans, change identity decisions and finding state, administer users and
  settings, and create exports.
- `read_only` users cannot mutate inventory or configuration. Export preview, status, and download still
  require an authenticated, permission-checked request.
- Server-side session tokens are random; only their hashes are stored. Session cookies are HttpOnly,
  SameSite=Lax, and Secure when `SECURE_COOKIES=true`.
- State-changing browser requests require the per-session CSRF token. Login attempts are throttled using the
  normalized username and client address.

For HTTPS deployment, terminate TLS at a trusted reverse proxy, set `PUBLIC_URL` to the HTTPS URL, set
`SECURE_COOKIES=true`, and set `FORWARDED_ALLOW_IPS` only to the proxy address or trusted proxy network. Do
not use `*` unless every direct connection to the container is trusted.

## Secrets

`.env.example` leaves `POSTGRES_PASSWORD` and `SECRET_KEY` blank. Compose fails closed when
either is missing. Generate independent random values, store them in the untracked `.env` file, and restrict
access to that file.

Use a URL-safe hexadecimal PostgreSQL password because Compose builds `DATABASE_URL` from it. Rotating the
database password requires updating the PostgreSQL role and `.env` together. Rotating `SECRET_KEY` invalidates
existing sessions and must be performed during a maintenance window.

Do not put scan exports, report files, `.env`, database dumps, tokens, or real organization identifiers in
source control, fixtures, screenshots, or support bundles.

## CLI and stdio MCP

CLI and MCP use the existing authenticated API, session cookie and CSRF checks. Their default origin is loopback; non-loopback HTTP, URL credentials and redirects are rejected. Session storage is explicit, origin-bound and private to the current user (POSIX mode 0600; protected current-user/SYSTEM Windows ACL). Passwords and session tokens are omitted from output. Legacy account bootstrap/reset commands remain explicit local database operations.

MCP is an optional stdio adapter, with no listening socket or additional service. Persistent writes are disabled unless started with `--enable-writes`, and every mutation also requires `confirm=true`. The existing administrator role, signed preview, global revision, per-entity versions and actor-bound idempotency keys still apply. Local input paths are bounded to the configured MCP root; network/device path forms are rejected before filesystem access. Keep MCP input roots limited to intentionally exported files.

Report JSON retains evidence and page metadata. CSV neutralizes formula-looking strings; Markdown escapes table/HTML content. Both tabular formats use the same rows as JSON, with documented null/nested-value representation. Tool failures are structured, and protocol stdout carries no CLI decorations or diagnostics.

## Container hardening

The application image is multi-stage: Node and Python build dependencies are absent from the runtime image.
The web and worker run as UID/GID `10001`, with all Linux capabilities dropped, `no-new-privileges`, a
read-only root filesystem, a bounded `/tmp` tmpfs, PID limits, health/readiness checks, and explicit CPU/memory
limits. Writable paths are limited to the upload and report volumes.

The worker uses the same immutable image as web. Web applies Alembic migrations before serving traffic.
Worker startup checks that the database is at every current Alembic head and refuses to process jobs
otherwise. Compose does not start worker until web is healthy.

PostgreSQL uses SCRAM host authentication and is reachable only on the internal Compose network. The backup
directory is mounted into the database service so binary custom-format dumps are written without host-shell
encoding conversion.

## Input and output controls

- Upload size is bounded by `MAX_UPLOAD_BYTES`.
- The application validates file type and content; a filename extension alone is not trusted.
- Nessus XML must use `defusedxml`; external entities and network resolution are disabled.
- Parser values are treated as untrusted data. Database access is parameterized through SQLAlchemy.
- Host-query fields and sort fields use typed allowlists. Free text is data, not executable SQL.
- Scanner-controlled and user-controlled values are output-encoded.
- Every spreadsheet cell that could begin with a formula marker is neutralized before XLSX or CSV output.
- Export download authorization is checked independently of export creation authorization.
- Errors returned to clients omit stack traces and secrets and include a request ID for server-log correlation.

## Audit and evidence

Audit events cover authentication-sensitive administrative activity, imports, exports, downloads, identity
decisions, status changes, and settings/user changes. Polling is not audited on every request. Original uploads
are immutable and hash-addressed; normalized records and identifier/finding observations preserve source
provenance.

Audit records and immutable evidence should have no automatic expiry by default. Report artifacts may expire
after `EXPORT_RETENTION_DAYS`, but their export and audit metadata should remain.

## Deployment checklist

Before allowing non-local access:

1. Generate unique `POSTGRES_PASSWORD` and `SECRET_KEY` values.
2. Use HTTPS and enable secure cookies.
3. Restrict the reverse proxy and host firewall to approved administrator networks.
4. Set `FORWARDED_ALLOW_IPS` narrowly.
5. Create named user accounts; do not share an administrator account.
6. Validate backup and restore in a disposable environment.
7. Monitor database, upload, report, and backup storage capacity.
8. Review retention settings before enabling any destructive cleanup.
9. Run unauthorized-access, role, CSRF, malicious XML, oversized upload, and formula-injection tests after
   upgrades.
