"""Configurable failure injection — chaos engineering for SOAR integrations.

Three layers of control, in increasing scope:

1. **Per-request query params** (anyone) — affect only this request.
   Useful for one-off "what does my consumer do on a 500?" probes.
   ``?inject_status=503&inject_latency=2000``

2. **Process-level env vars** (operator, set at deploy time) — probabilistic
   defaults applied to every request.
   ``SIEMULATOR_INJECT_FAULTS=true`` master switch, plus:
   - ``SIEMULATOR_INJECT_5XX_PCT=10``     — 10 %% of requests return 5xx
   - ``SIEMULATOR_INJECT_429_PCT=5``      — 5 %% return rate-limit
   - ``SIEMULATOR_INJECT_LATENCY_MS=500`` — add this much latency every request
   - ``SIEMULATOR_INJECT_MALFORMED_PCT=2`` — 2 %% return truncated JSON

3. **Admin endpoints** (admin-key gated) — dial faults live during a test run
   without redeploying.
   - ``GET  /api/faults``        — current config
   - ``PUT  /api/faults``        — update (JSON body)
   - ``POST /api/faults/reset``  — back to env defaults

Per-request query params override env defaults. Per-request overrides
only affect the calling request, so they're safe to expose publicly
on the live demo — one visitor can't break the experience for everyone.

Fault types implemented:

- **Status codes** — 5xx, 429, 502, 503, 504. Returns the chosen status
  with a synthetic error body. Method-of-injection: dependency raises
  HTTPException before the handler runs.
- **Latency** — added before the handler returns. Method: ``asyncio.sleep``
  in the dependency.
- **Malformed JSON** — response body truncated mid-stream. Method:
  middleware mutates the response body. ~rare; deliberately so.

Not yet implemented (planned): connection drops mid-response, slow-
streaming (byte-by-byte drip), partial JSON arrays.
"""

from __future__ import annotations

import asyncio
import json
import random
import secrets
from dataclasses import asdict, dataclass, field

from fastapi import APIRouter, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp

from siemulator.config import (
    admin_key,
    fault_injection_enabled,
    inject_5xx_pct_default,
    inject_429_pct_default,
    inject_latency_ms_default,
    inject_malformed_pct_default,
)

# Statuses we cycle through when the env-default 5xx injection fires.
# Per-request `?inject_status=NNN` can be any code.
_5XX_CYCLE = (500, 502, 503, 504)


@dataclass
class FaultConfig:
    """Mutable runtime config. Initialised from env, updateable via PUT."""

    enabled: bool = False
    inject_5xx_pct: float = 0.0
    inject_429_pct: float = 0.0
    inject_latency_ms: int = 0
    inject_malformed_pct: float = 0.0
    fault_count: dict[str, int] = field(default_factory=lambda: {
        "5xx": 0, "429": 0, "latency": 0, "malformed": 0,
    })


# Module-level singleton; safe to mutate from admin endpoint.
_config = FaultConfig(
    enabled=fault_injection_enabled(),
    inject_5xx_pct=inject_5xx_pct_default(),
    inject_429_pct=inject_429_pct_default(),
    inject_latency_ms=inject_latency_ms_default(),
    inject_malformed_pct=inject_malformed_pct_default(),
)


def get_config() -> FaultConfig:
    """Current runtime config (read-only view from outside)."""
    return _config


def reset_to_env() -> FaultConfig:
    """Drop live overrides and re-read env vars."""
    _config.enabled = fault_injection_enabled()
    _config.inject_5xx_pct = inject_5xx_pct_default()
    _config.inject_429_pct = inject_429_pct_default()
    _config.inject_latency_ms = inject_latency_ms_default()
    _config.inject_malformed_pct = inject_malformed_pct_default()
    for k in _config.fault_count:
        _config.fault_count[k] = 0
    return _config


def update_config(**kwargs: object) -> FaultConfig:
    """Apply live updates. Unknown keys ignored. Returns new state."""
    for k, v in kwargs.items():
        if hasattr(_config, k) and k != "fault_count":
            setattr(_config, k, v)
    return _config


def _parse_per_request_overrides(request: Request) -> dict[str, int | None]:
    """Pull ``?inject_…`` query params and coerce. Returns ``{}`` if none."""
    qp = request.query_params
    out: dict[str, int | None] = {}
    if "inject_status" in qp:
        try:
            out["status"] = int(qp["inject_status"])
        except (TypeError, ValueError):
            out["status"] = None
    if "inject_latency" in qp:
        try:
            out["latency_ms"] = max(0, int(qp["inject_latency"]))
        except (TypeError, ValueError):
            out["latency_ms"] = None
    if qp.get("inject_malformed", "").lower() in ("1", "true", "yes"):
        out["malformed"] = 1
    return out


def _roll(pct: float) -> bool:
    """True with probability ``pct/100``. Clamped to [0, 100]."""
    if pct <= 0:
        return False
    if pct >= 100:
        return True
    return random.uniform(0, 100) < pct  # nosec: not crypto


async def fault_check(request: Request) -> None:
    """FastAPI dependency. Raises HTTPException to inject status faults;
    sleeps to inject latency. Runs before the route handler."""
    overrides = _parse_per_request_overrides(request)

    # ── Per-request status override (highest priority) ────────────
    if overrides.get("status") is not None:
        code = overrides["status"]
        _config.fault_count["5xx" if code >= 500 else "429" if code == 429 else "5xx"] += 1
        raise HTTPException(
            status_code=code,
            detail={
                "error": "injected fault",
                "x-injected-by": "siemulator-fault-inject",
                "x-injection-source": "per-request",
                "x-injection-status": code,
            },
        )

    # ── Per-request latency override ──────────────────────────────
    per_req_latency = overrides.get("latency_ms")
    if per_req_latency:
        _config.fault_count["latency"] += 1
        await asyncio.sleep(per_req_latency / 1000.0)
    # Env-default latency (additive with per-request — they stack)
    elif _config.enabled and _config.inject_latency_ms > 0:
        await asyncio.sleep(_config.inject_latency_ms / 1000.0)

    # ── Env-default probabilistic faults ──────────────────────────
    if not _config.enabled:
        return

    if _roll(_config.inject_5xx_pct):
        code = random.choice(_5XX_CYCLE)  # nosec
        _config.fault_count["5xx"] += 1
        raise HTTPException(
            status_code=code,
            detail={
                "error": "injected fault",
                "x-injected-by": "siemulator-fault-inject",
                "x-injection-source": "env-default-5xx-pct",
                "x-injection-pct": _config.inject_5xx_pct,
            },
        )

    if _roll(_config.inject_429_pct):
        _config.fault_count["429"] += 1
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate limited (injected)",
                "x-injected-by": "siemulator-fault-inject",
                "x-injection-source": "env-default-429-pct",
            },
            headers={"Retry-After": "5"},
        )


class MalformedResponseMiddleware(BaseHTTPMiddleware):
    """Middleware that occasionally truncates response bodies — simulates a
    flaky upstream returning broken JSON.

    Only fires on bound surfaces (LogScale / QRadar) and only on
    JSON-content-type responses. Per-request ``?inject_malformed=1``
    forces it; env-default ``SIEMULATOR_INJECT_MALFORMED_PCT`` rolls.
    """

    def __init__(self, app: ASGIApp, bound_prefixes: tuple[str, ...]):
        super().__init__(app)
        self.bound = bound_prefixes

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if not any(request.url.path.startswith(p) for p in self.bound):
            return await call_next(request)

        force = request.query_params.get("inject_malformed", "").lower() in (
            "1", "true", "yes",
        )
        fire = force or (
            _config.enabled and _roll(_config.inject_malformed_pct)
        )

        response = await call_next(request)
        if not fire:
            return response
        ctype = response.headers.get("content-type", "")
        if "application/json" not in ctype:
            return response

        # Read the body, truncate at a random midpoint, return.
        chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)
        body = b"".join(chunks)
        if len(body) > 20:
            cut = random.randint(10, max(11, len(body) - 5))  # nosec
            body = body[:cut]  # malformed: truncated mid-token

        _config.fault_count["malformed"] += 1
        new_headers = dict(response.headers)
        new_headers["x-injected-by"] = "siemulator-fault-inject"
        new_headers["x-injection-source"] = (
            "per-request" if force else "env-default-malformed-pct"
        )
        # content-length must reflect the truncated body
        new_headers["content-length"] = str(len(body))
        return Response(
            content=body,
            status_code=response.status_code,
            headers=new_headers,
            media_type=response.media_type,
        )


# ── Admin endpoints ─────────────────────────────────────────────────


def _check_admin(request: Request) -> None:
    expected = admin_key()
    if not expected:
        raise HTTPException(status_code=403, detail="admin endpoints disabled")
    key = request.headers.get("x-admin-key", "") or request.headers.get(
        "X-Admin-Key", ""
    )
    if not secrets.compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api/faults", tags=["faults"])

    @router.get("")
    @router.get("/")
    async def current(request: Request):
        """Current fault-injection config + cumulative fault counts."""
        _check_admin(request)
        return asdict(_config)

    @router.put("")
    @router.put("/")
    async def update(request: Request):
        """Live-update fault config. JSON body with any subset of:
        ``{enabled, inject_5xx_pct, inject_429_pct, inject_latency_ms,
        inject_malformed_pct}``."""
        _check_admin(request)
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(
                status_code=400, detail="invalid JSON body"
            ) from None
        if not isinstance(body, dict):
            raise HTTPException(
                status_code=400, detail="body must be a JSON object"
            )
        update_config(**body)
        return asdict(_config)

    @router.post("/reset")
    async def reset(request: Request):
        """Drop live overrides; re-read env vars; zero the fault counts."""
        _check_admin(request)
        reset_to_env()
        return asdict(_config)

    return router
