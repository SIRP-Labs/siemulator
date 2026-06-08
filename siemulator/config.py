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


def _bool_env(name: str, default: str) -> bool:
    val = os.environ.get(name, default).strip().lower()
    return val not in ("false", "0", "no", "off", "")


def ui_enabled() -> bool:
    """Web UI at /. Default on. Set ``SIEMULATOR_UI_ENABLED=false`` (or
    ``0`` / ``no``) for production deployments that want pure-API
    behaviour — root falls back to JSON metadata."""
    return _bool_env("SIEMULATOR_UI_ENABLED", "true")


def access_log_enabled() -> bool:
    """Capture every request to /logscale/* + /qradar/* in an in-memory
    ring + emit a structured JSON line to stdout. Default on. See
    ``siemulator.access_log`` for details."""
    return _bool_env("SIEMULATOR_ACCESS_LOG_ENABLED", "true")


def access_log_size() -> int:
    """In-memory access-log ring size. Default 5000 (~3 days at 60-s polling)."""
    try:
        return max(100, int(os.environ.get("SIEMULATOR_ACCESS_LOG_SIZE", "5000")))
    except ValueError:
        return 5000


def access_log_skip_health() -> bool:
    """When true, health-check paths are NOT recorded in the access log
    (useful when DO Apps' 30-s health probe would otherwise dominate the
    ring). Default off — log everything for full visibility."""
    return _bool_env("SIEMULATOR_ACCESS_LOG_SKIP_HEALTH", "false")
