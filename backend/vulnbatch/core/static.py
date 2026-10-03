from __future__ import annotations

from pathlib import PurePosixPath

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

FRONTEND_ROUTES = frozenset({
    "login", "setup", "hosts", "findings", "imports", "identity-review",
    "saved-views", "reports", "exports", "audit", "settings", "users", "services",
})


class FrontendStaticFiles(StaticFiles):
    """Serve the SPA entry point for known client routes after a file miss."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        route_path = path.replace("\\", "/")
        is_frontend_route = (
            route_path.strip("/").split("/", 1)[0] in FRONTEND_ROUTES
            and not PurePosixPath(route_path).suffix
        )
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or not is_frontend_route:
                raise
        else:
            if response.status_code != 404 or not is_frontend_route:
                return response
        return await super().get_response("index.html", scope)
