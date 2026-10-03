FROM node:22-bookworm-slim AS frontend-build

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --ignore-scripts; else npm install --ignore-scripts; fi
COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim-bookworm AS python-build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY backend/ ./backend/
RUN python -m pip wheel --wheel-dir /wheels .


FROM python:3.12-slim-bookworm AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/usr/local/bin:${PATH}" \
    STATIC_DIR=/app/static \
    UPLOAD_DIR=/data/uploads \
    REPORT_DIR=/data/reports

RUN groupadd --gid "${APP_GID}" workbench \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin workbench

COPY --from=python-build /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels vulnerability-workbench \
    && rm -rf /wheels

WORKDIR /app
COPY alembic.ini ./
COPY alembic/ ./alembic/
COPY scripts/ ./scripts/
COPY --from=frontend-build /build/frontend/dist ./static/

RUN mkdir -p /data/uploads /data/reports /app/static \
    && chmod 0555 /app/scripts/*.sh \
    && chown -R workbench:workbench /app /data

USER workbench:workbench

EXPOSE 8787
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8787/readyz', timeout=3).read()"]

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
