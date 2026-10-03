#!/bin/sh
set -eu

umask 027

python /app/scripts/runtime/wait-for-database.py

mkdir -p "${UPLOAD_DIR:-/data/uploads}" "${REPORT_DIR:-/data/reports}"

echo "Applying database migrations."
alembic upgrade head

echo "Starting Vulncat web service."
exec uvicorn vulnbatch.main:app \
    --host 0.0.0.0 \
    --port 8787 \
    --workers "${WEB_CONCURRENCY:-2}" \
    --proxy-headers \
    --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}"
