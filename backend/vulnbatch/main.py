from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, Response

from vulnbatch import __version__
from vulnbatch.api.routes import (
    assets,
    audit,
    auth,
    dashboard,
    exports,
    exposure,
    exposure_exports,
    findings,
    health,
    identity,
    imports,
    reconciliation,
    reconciliation_storage,
    saved_views,
    users,
)
from vulnbatch.api.routes import (
    settings as settings_routes,
)
from vulnbatch.core.config import get_settings
from vulnbatch.core.static import FrontendStaticFiles

app_settings = get_settings()
logging.basicConfig(
    level=getattr(logging, app_settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    app_settings.upload_dir.mkdir(parents=True, exist_ok=True)
    app_settings.report_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="Vulncat API",
    version=__version__,
    description="Offline vulnerability, inventory, coverage and service exposure evidence API.",
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def request_context_and_security_headers(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    request.state.request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logging.getLogger("vulnerability_workbench").exception(
        "Unhandled request error request_id=%s path=%s", request.state.request_id, request.url.path
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred.", "request_id": request.state.request_id},
    )


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(imports.router)
app.include_router(reconciliation.router)
app.include_router(reconciliation_storage.router)
app.include_router(exposure.router)
app.include_router(exposure_exports.router)
app.include_router(identity.router)
app.include_router(assets.router)
app.include_router(saved_views.router)
app.include_router(exports.router)
app.include_router(dashboard.router)
app.include_router(findings.router)
app.include_router(audit.router)
app.include_router(settings_routes.router)
app.include_router(users.router)

app.mount(
    "/",
    FrontendStaticFiles(directory=app_settings.static_dir, html=True, check_dir=False),
    name="frontend",
)
