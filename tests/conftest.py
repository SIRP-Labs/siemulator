"""Shared pytest fixtures."""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _set_env(logscale: str, qradar: str) -> None:
    os.environ["SIEMULATOR_LOGSCALE_TOKEN"] = logscale
    os.environ["SIEMULATOR_QRADAR_TOKEN"] = qradar
    os.environ["SIEMULATOR_LOGSCALE_PREFIX"] = "/logscale"
    os.environ["SIEMULATOR_QRADAR_PREFIX"] = "/qradar"


@pytest.fixture
def logscale_client():
    """Returns a factory: ``logscale_client(token=...)`` → TestClient."""

    def factory(token: str = "logscale-tok") -> TestClient:
        _set_env(token, "qradar-tok")
        from siemulator.logscale import build_router

        app = FastAPI()
        app.include_router(build_router())
        return TestClient(app)

    return factory


@pytest.fixture
def qradar_client():
    """Returns a factory: ``qradar_client(token=...)`` → TestClient."""

    def factory(token: str = "qradar-tok") -> TestClient:
        _set_env("logscale-tok", token)
        from siemulator.qradar import build_router

        app = FastAPI()
        app.include_router(build_router())
        return TestClient(app)

    return factory


@pytest.fixture
def both_clients():
    """For cross-token tests — returns the QRadar client with both env vars set."""

    def factory(*, logscale: str, qradar: str) -> TestClient:
        _set_env(logscale, qradar)
        from siemulator.qradar import build_router

        app = FastAPI()
        app.include_router(build_router())
        return TestClient(app)

    return factory
