"""Runtime configuration — all values come from environment variables."""

from __future__ import annotations

import os

MOCK_SOURCE = "siemulator"


def logscale_token() -> str:
    return os.environ.get("SIEMULATOR_LOGSCALE_TOKEN", "logscale-dev-token")


def qradar_token() -> str:
    return os.environ.get("SIEMULATOR_QRADAR_TOKEN", "qradar-dev-token")


def admin_key() -> str:
    """Admin key for /_debug/* endpoints. Empty string disables them."""
    return os.environ.get("SIEMULATOR_ADMIN_KEY", "")


def logscale_prefix() -> str:
    return os.environ.get("SIEMULATOR_LOGSCALE_PREFIX", "/logscale")


def qradar_prefix() -> str:
    return os.environ.get("SIEMULATOR_QRADAR_PREFIX", "/qradar")


def host() -> str:
    return os.environ.get("SIEMULATOR_HOST", "0.0.0.0")


def port() -> int:
    return int(os.environ.get("SIEMULATOR_PORT", "8080"))
