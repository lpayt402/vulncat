#!/bin/sh
set -eu

compose_file="${COMPOSE_FILE:-compose.yaml}"
backup_dir="${BACKUP_DIR:-./backups}"
filename="${1:-vulnerability-workbench-$(date -u +%Y%m%dT%H%M%SZ).dump}"

case "$filename" in
    *[!A-Za-z0-9._-]* | "" | .* | *..*)
        echo "Backup filename may contain only letters, digits, dot, underscore, and hyphen." >&2
        exit 2
        ;;
esac

mkdir -p "$backup_dir"
backup_dir="$(cd "$backup_dir" && pwd)"
export BACKUP_DIR="$backup_dir"

docker compose -f "$compose_file" exec -T db sh -eu -c '
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
' sh "$filename"

echo "Database backup created: $backup_dir/$filename"
echo "Back up the uploads and reports volumes separately; see docs/backup-restore.md."
