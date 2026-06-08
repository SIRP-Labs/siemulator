"""Access-log middleware and admin endpoints.

Every request to the LogScale or QRadar surface (or any prefix passed
to :class:`AccessLogMiddleware`) gets captured here:

- Appended to a bounded in-memory deque (configurable cap via
  ``SIEMULATOR_ACCESS_LOG_SIZE``, default 5000).
- Emitted as a single JSON line to the ``siemulator.access`` logger,
  which inherits uvicorn's stdout handler — so DO App Platform,
  Docker logs, k8s, etc. capture it for free.

What we record per request:

- timestamp (ISO 8601 UTC)
- HTTP method + path
- redacted query string (``?token=…`` and friends → ``***``)
- auth channel used (``bearer`` / ``sec`` / ``query`` / ``none``) — the
  *channel name*, never the token value
- client IP (X-Forwarded-For aware, since DO App Platform terminates TLS upstream)
- user-agent (truncated to 200 chars)
- HTTP status code
- response size in bytes (from ``Content-Length`` header)
- duration in milliseconds

What we deliberately DON'T record (so the log is safe to expose):

- Bearer / SEC token values
- ``?token=`` query param value
- ``X-Admin-Key`` header value
- Cookies
- Request body
- Response body

Endpoints (admin-key gated, both at the API root):

- ``GET /api/access-log`` — recent requests with optional filters
  (``?limit=N``, ``?path_prefix=…``, ``?status=NNN``, ``?since=ISO8601``)
- ``GET /api/access-log/stats`` — aggregates: total, by_status, by_auth,
  top_paths, top_clients, top_user_agents, avg + p95 duration

Disable both the middleware + the admin endpoints via
``SIEMULATOR_ACCESS_LOG_ENABLED=false``.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from siemulator.config import (
    access_log_size,
    access_log_skip_health,
    admin_key,
)

logger = logging.getLogger("siemulator.access")

_SENSITIVE_QUERY_KEYS = {"token", "key", "api_key", "apikey", "auth", "secret", "password"}

_HEALTH_PATHS = frozenset({
    "/logscale/api/v1/status",
    "/logscale/api/v1/repositories",
    "/qradar/api/help",
    "/qradar/api/help/capabilities",
    "/",
    "/api/info",
})


@dataclass
class AccessLogEntry:
    """One row in the access log. Serialized 1:1 to JSON."""

    ts: str
    method: str
    path: str
    query: dict[str, str]
    auth: str
    client_ip: str | None
    user_agent: str
    status: int
    duration_ms: int
    response_bytes: int


# In-memory ring buffer. Initialized at import time from env (re-reading
# the cap per-request would slow the hot path).
_entries: deque[AccessLogEntry] = deque(maxlen=access_log_size())


def _redact_query(qp: dict[str, str]) -> dict[str, str]:
    """Replace values of well-known auth-bearing query params with ``***``."""
    return {
        k: ("***" if k.lower() in _SENSITIVE_QUERY_KEYS else v)
        for k, v in qp.items()
    }


def _detect_auth(request: Request) -> str:
    """Return the auth channel the consumer used. Never returns the token value."""
    if request.query_params.get("token"):
        return "query"
    if request.headers.get("SEC") or request.headers.get("sec"):
        return "sec"
    if request.headers.get("Authorization", "").startswith("Bearer "):
        return "bearer"
    return "none"


def _client_ip(request: Request) -> str | None:
    """Honor X-Forwarded-For for deployments behind a reverse proxy.

    DO App Platform sets ``X-Forwarded-For: <real-client>, <do-edge>``; we
    take the leftmost (real client). Falls back to ``request.client.host``
    for direct-connect deployments.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip() or None
    return request.client.host if request.client else None


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _record(entry: AccessLogEntry) -> None:
    """Append to the in-memory ring + emit a structured JSON line."""
    _entries.append(entry)
    try:
        logger.info(json.dumps(asdict(entry), separators=(",", ":")))
    except Exception:
        # Never let logging failures bubble into request handling.
        pass


class AccessLogMiddleware(BaseHTTPMiddleware):
    """Capture every request whose path matches one of ``bound_prefixes``.

    Bind to ``/logscale`` + ``/qradar`` so the access log is surface-
    agnostic and stays out of UI / meta endpoints.
    """

    def __init__(self, app: ASGIApp, bound_prefixes: tuple[str, ...]):
        super().__init__(app)
        self.bound = bound_prefixes
        self.skip_health = access_log_skip_health()

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        path = request.url.path
        if not any(path.startswith(p) for p in self.bound):
            return await call_next(request)
        if self.skip_health and path in _HEALTH_PATHS:
            return await call_next(request)

        t0 = time.perf_counter()
        response = await call_next(request)
        dur_ms = int((time.perf_counter() - t0) * 1000)

        try:
            size = int(response.headers.get("content-length", "0"))
        except (TypeError, ValueError):
            size = 0

        _record(
            AccessLogEntry(
                ts=_utc_iso(),
                method=request.method,
                path=path,
                query=_redact_query(dict(request.query_params)),
                auth=_detect_auth(request),
                client_ip=_client_ip(request),
                user_agent=request.headers.get("user-agent", "")[:200],
                status=response.status_code,
                duration_ms=dur_ms,
                response_bytes=size,
            )
        )
        return response


def _check_admin(request: Request) -> None:
    expected = admin_key()
    if not expected:
        raise HTTPException(status_code=403, detail="admin endpoints disabled")
    key = request.headers.get("x-admin-key", "") or request.headers.get("X-Admin-Key", "")
    if not secrets.compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


def _percentile(sorted_vals: list[int], pct: float) -> int:
    """Nearest-rank percentile on a pre-sorted list."""
    if not sorted_vals:
        return 0
    idx = max(0, min(len(sorted_vals) - 1, int(pct * len(sorted_vals))))
    return sorted_vals[idx]


def get_recent(
    *,
    limit: int = 100,
    since: str | None = None,
    path_prefix: str | None = None,
    status: int | None = None,
    auth: str | None = None,
) -> list[dict]:
    """Return recent entries newest-first, with optional filters."""
    items = list(_entries)
    if since:
        items = [e for e in items if e.ts >= since]
    if path_prefix:
        items = [e for e in items if e.path.startswith(path_prefix)]
    if status is not None:
        items = [e for e in items if e.status == status]
    if auth:
        items = [e for e in items if e.auth == auth]
    items.reverse()  # newest first
    limit = max(1, min(limit, _entries.maxlen or 5000))
    return [asdict(e) for e in items[:limit]]


def get_stats() -> dict[str, Any]:
    """Aggregates over the current in-memory window."""
    if not _entries:
        return {"total": 0, "window_size": _entries.maxlen}
    items = list(_entries)
    by_status = Counter(e.status for e in items)
    by_auth = Counter(e.auth for e in items)
    by_path = Counter(e.path for e in items)
    by_ip = Counter(e.client_ip for e in items if e.client_ip)
    by_ua = Counter(e.user_agent for e in items if e.user_agent)
    by_method = Counter(e.method for e in items)
    sorted_durs = sorted(e.duration_ms for e in items)
    sum_bytes = sum(e.response_bytes for e in items)
    return {
        "total": len(items),
        "window_size": _entries.maxlen,
        "first_seen": items[0].ts,
        "last_seen": items[-1].ts,
        "by_method": dict(by_method),
        "by_status": {str(k): v for k, v in sorted(by_status.items())},
        "by_auth": dict(by_auth),
        "top_paths": dict(by_path.most_common(15)),
        "top_clients": dict(by_ip.most_common(15)),
        "top_user_agents": dict(by_ua.most_common(10)),
        "duration_ms": {
            "avg": sum(sorted_durs) // len(sorted_durs),
            "p50": _percentile(sorted_durs, 0.50),
            "p95": _percentile(sorted_durs, 0.95),
            "p99": _percentile(sorted_durs, 0.99),
            "max": sorted_durs[-1],
        },
        "total_response_bytes": sum_bytes,
    }


def clear() -> int:
    """Drop all entries. Returns the count cleared. Test/admin use only."""
    n = len(_entries)
    _entries.clear()
    return n


def build_router() -> APIRouter:
    """Admin-gated endpoints exposing the access log."""
    router = APIRouter(prefix="/api/access-log", tags=["access-log"])

    @router.get("")
    @router.get("/")
    async def recent(
        request: Request,
        limit: int = 100,
        since: str | None = None,
        path_prefix: str | None = None,
        status: int | None = None,
        auth: str | None = None,
    ):
        """Recent requests, newest first. Filters compose."""
        _check_admin(request)
        return {
            "entries": get_recent(
                limit=limit,
                since=since,
                path_prefix=path_prefix,
                status=status,
                auth=auth,
            ),
            "window_size": _entries.maxlen,
            "current_count": len(_entries),
        }

    @router.get("/stats")
    async def stats(request: Request):
        """Aggregates: by_status, by_auth, top_paths, top_clients,
        top_user_agents, duration percentiles."""
        _check_admin(request)
        return get_stats()

    @router.post("/clear")
    async def clear_endpoint(request: Request):
        """Wipe the in-memory access log. Stdout JSON log untouched."""
        _check_admin(request)
        n = clear()
        return {"cleared": n}

    return router
