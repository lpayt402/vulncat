[CmdletBinding()]
param(
    [string]$FileName = ("vulnerability-workbench-{0}.dump" -f (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")),
    [string]$BackupDirectory = "./backups",
    [string]$ComposeFile = "compose.yaml"
)

$ErrorActionPreference = "Stop"

if ($FileName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $FileName.Contains("..")) {
    throw "Backup filename may contain only letters, digits, dot, underscore, and hyphen."
}

$backupPath = New-Item -ItemType Directory -Force -Path $BackupDirectory
$env:BACKUP_DIR = $backupPath.FullName
$composeArgs = @("compose", "-f", $ComposeFile)

& docker @composeArgs exec -T db sh -eu -c @'
umask 077
pg_dump \
    --username="$POSTGRES_USER" \
    --dbname="$POSTGRES_DB" \
    --format=custom \
    --compress=6 \
    --no-owner \
    --no-acl \
    --file="/backups/$1"
if command -v sha256sum >/dev/null 2>&1; then
    cd /backups
    sha256sum "$1" >"$1.sha256"
fi
'@ sh $FileName

if ($LASTEXITCODE -ne 0) {
    throw "pg_dump failed with exit code $LASTEXITCODE."
}

Write-Host "Database backup created: $($backupPath.FullName)\$FileName"
Write-Host "Back up the uploads and reports volumes separately; see docs/backup-restore.md."
