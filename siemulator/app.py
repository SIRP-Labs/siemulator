"""FastAPI app factory."""

from __future__ import annotations

from fastapi import FastAPI

from siemulator import __version__
from siemulator.config import MOCK_SOURCE
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

    @app.get("/")
    async def root():
        return {
            "name": "siemulator",
            "version": __version__,
            "x-mock-source": MOCK_SOURCE,
            "surfaces": ["logscale", "qradar"],
            "docs": "/docs",
        }

    app.include_router(build_logscale_router())
    app.include_router(build_qradar_router())
    return app
