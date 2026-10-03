[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FileName,
    [switch]$ConfirmReplaceDatabase,
    [string]$BackupDirectory = "./backups",
    [string]$ComposeFile = "compose.yaml"
)

$ErrorActionPreference = "Stop"

if (-not $ConfirmReplaceDatabase) {
    throw "Restore replaces the configured database. Re-run with -ConfirmReplaceDatabase."
}
if ($FileName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $FileName.Contains("..")) {
    throw "Backup filename may contain only letters, digits, dot, underscore, and hyphen."
}

$backupPath = Resolve-Path -LiteralPath $BackupDirectory
$dumpPath = Join-Path $backupPath.Path $FileName
if (-not (Test-Path -LiteralPath $dumpPath -PathType Leaf)) {
    throw "Backup file not found: $dumpPath"
}

$env:BACKUP_DIR = $backupPath.Path
$composeArgs = @("compose", "-f", $ComposeFile)

& docker @composeArgs up -d db
if ($LASTEXITCODE -ne 0) {
    throw "Unable to start database service."
}

$checksumPath = "$dumpPath.sha256"
if (Test-Path -LiteralPath $checksumPath -PathType Leaf) {
    & docker @composeArgs exec -T db sh -eu -c @'
cd /backups
sha256sum --check "$1.sha256"
'@ sh $FileName
    if ($LASTEXITCODE -ne 0) {
        throw "Backup checksum validation failed."
    }
}

Write-Host "Stopping writers before destructive database restore."
& docker @composeArgs stop web worker
if ($LASTEXITCODE -ne 0) {
    throw "Unable to stop web and worker."
}

$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    & docker @composeArgs exec -T db sh -eu -c 'pg_isready --username="$POSTGRES_USER" --dbname=postgres' *> $null
    if ($LASTEXITCODE -eq 0) {
        $ready = $true
        break
    }
    Start-Sleep -Seconds 2
}
if (-not $ready) {
    throw "PostgreSQL did not become ready. Web and worker remain stopped."
}

& docker @composeArgs exec -T db sh -eu -c @'
maintenance_db=postgres
if [ "$POSTGRES_DB" = "postgres" ]; then
    maintenance_db=template1
fi
dropdb \
    --username="$POSTGRES_USER" \
    --maintenance-db="$maintenance_db" \
    --if-exists \
    --force \
    "$POSTGRES_DB"
createdb \
    --username="$POSTGRES_USER" \
    --maintenance-db="$maintenance_db" \
    "$POSTGRES_DB"
pg_restore \
    --username="$POSTGRES_USER" \
    --dbname="$POSTGRES_DB" \
    --exit-on-error \
    --no-owner \
    --no-acl \
    "/backups/$1"
'@ sh $FileName

if ($LASTEXITCODE -ne 0) {
    throw "Database restore failed. Web and worker remain stopped."
}

& docker @composeArgs up -d web worker
if ($LASTEXITCODE -ne 0) {
    throw "Restore succeeded, but the application services did not start."
}

Write-Host "Database restore completed. Verify /readyz, application data, and audit history before use."
