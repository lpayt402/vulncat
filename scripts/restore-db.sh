#!/bin/sh
set -eu

compose_file="${COMPOSE_FILE:-compose.yaml}"
backup_dir="${BACKUP_DIR:-./backups}"
filename="${1:-}"
confirmation="${2:-}"

if [ -z "$filename" ] || [ "$confirmation" != "--confirm-replace-database" ]; then
    echo "Usage: scripts/restore-db.sh BACKUP.dump --confirm-replace-database" >&2
    exit 2
fi

case "$filename" in
    *[!A-Za-z0-9._-]* | "" | .* | *..*)
        echo "Backup filename may contain only letters, digits, dot, underscore, and hyphen." >&2
        exit 2
        ;;
esac

if [ ! -f "$backup_dir/$filename" ]; then
    echo "Backup file not found: $backup_dir/$filename" >&2
    exit 2
fi

backup_dir="$(cd "$backup_dir" && pwd)"
export BACKUP_DIR="$backup_dir"

docker compose -f "$compose_file" up -d db

if [ -f "$backup_dir/$filename.sha256" ]; then
    docker compose -f "$compose_file" exec -T db sh -eu -c '
        cd /backups
        sha256sum --check "$1.sha256"
    ' sh "$filename"
fi

echo "Stopping writers before destructive database restore."
docker compose -f "$compose_file" stop web worker

attempt=0
until docker compose -f "$compose_file" exec -T db sh -eu -c \
    'pg_isready --username="$POSTGRES_USER" --dbname=postgres' >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "PostgreSQL did not become ready. Web and worker remain stopped." >&2
        exit 1
    fi
    sleep 2
done

docker compose -f "$compose_file" exec -T db sh -eu -c '
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
' sh "$filename"

docker compose -f "$compose_file" up -d web worker
echo "Database restore completed. Verify /readyz, application data, and audit history before use."
