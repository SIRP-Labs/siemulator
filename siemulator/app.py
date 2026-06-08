"""FastAPI app factory."""

from __future__ import annotations

from fastapi import FastAPI

from siemulator import __version__
from siemulator.config import (
    MOCK_SOURCE,
    access_log_enabled,
    logscale_prefix,
    qradar_prefix,
    ui_enabled,
)
from siemulator.logscale import build_router as build_logscale_router
from siemulator.qradar import build_router as build_qradar_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="siemulator",
        version=__version__,
        description=(
            "Synthetic SIEM endpoints in real-vendor shapes for SOAR/agent "
            "integration testing. Two parallel surfaces (LogScale + QRadar) "
            "from one detection-template pool."
        ),
    )

    _METADATA = {
        "name": "siemulator",
        "version": __version__,
        "x-mock-source": MOCK_SOURCE,
        "surfaces": ["logscale", "qradar"],
        "docs": "/docs",
    }

    # JSON metadata always lives at /api/info — machine-readable, stable,
    # never returns HTML. Useful for liveness probes that don't want
    # content negotiation surprises.
    @app.get("/api/info")
    async def api_info():
        return _METADATA

    if ui_enabled():
        # Web UI at /. Mounts a router rather than defining the route
        # inline so the rendered HTML can capture the current prefixes.
        from siemulator.ui import build_router as build_ui_router

        app.include_router(build_ui_router())
    else:
        # Pure-API mode — / returns the same JSON metadata as /api/info.
        @app.get("/")
        async def root():
            return _METADATA

    app.include_router(build_logscale_router())
    app.include_router(build_qradar_router())

    if access_log_enabled():
        # Register middleware AFTER routers so it wraps every handled
        # request, and register the admin router so /api/access-log[/*]
        # is reachable.
        from siemulator.access_log import AccessLogMiddleware
        from siemulator.access_log import build_router as build_access_log_router

        app.add_middleware(
            AccessLogMiddleware,
            bound_prefixes=(logscale_prefix(), qradar_prefix()),
        )
        app.include_router(build_access_log_router())

    return app
