"""RSA NetWitness 12.5 mock surface.

Mounted at ``SIEMULATOR_NETWITNESS_PREFIX`` (default ``/nw``).
Mirrors the NetWitness REST API shape so act 1454
(apps/RSA-NetWitness/ingest_alerts_from_incidents.py) can run end-to-end
against siemulator without a real NW appliance.

Endpoints
---------
POST  /rest/api/auth/userpass          — session token (form: username, password)
GET   /rest/api/incidents              — list incidents (Range-paginated)
GET   /rest/api/incidents/{id}         — single incident; 400 on unknown id
GET   /rest/api/alert/fetch            — alerts for an incident (JSON body: meta_value)

Admin (SIEMULATOR_ADMIN_KEY required)
--------------------------------------
POST  /_admin/auth_mode                — toggle auth failure simulation
GET   /_admin/auth_mode                — current mode

Auth modes (toggle via admin endpoint or SIEMULATOR_NETWITNESS_AUTH_MODE env var)
----------------------------------------------------------------------------------
  normal            — 200 {"accessToken": "..."}
  locked            — 500 body containing "User account is locked"
  bad_credentials   — 401 "Bad credentials"
  unavailable       — 503

Auth
----
After /auth/userpass the caller sends ``NetWitness-Token: <token>`` or
``Authorization: Bearer <token>`` on subsequent calls. Cross-token
acceptance with the other surfaces (qradar-dev-token etc.) is also
supported — consistent with the rest of siemulator.
"""

from __future__ import annotations

import os
import random
import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status

from siemulator.config import (
    MOCK_SOURCE,
    admin_key,
    logscale_token,
    netwitness_prefix,
    netwitness_token,
    qradar_token,
)
from siemulator.fault_inject import fault_check
from siemulator.scenarios import all_scenarios_as_qradar
from siemulator.templates import ALERT_TEMPLATES, HOSTNAMES, USERS


def build_router() -> APIRouter:
    return _make_router(netwitness_prefix())


# ── In-memory state ───────────────────────────────────────────────────────────

# Auth mode — mutated by admin endpoint.  One of:
#   "normal" | "locked" | "bad_credentials" | "unavailable"
_AUTH_MODE: list[str] = [os.environ.get("SIEMULATOR_NETWITNESS_AUTH_MODE", "normal")]

# Active session tokens (issued by /auth/userpass). Capped at 256.
_TOKENS: dict[str, str] = {}   # token → username


# ── Incident pool (stable IDs across restarts) ────────────────────────────────

_PRIORITIES = ["Critical", "High", "Medium", "Low"]
_STATUSES   = ["New", "Assigned", "InProgress", "Closed"]

_INCIDENT_BASE = 10_001   # IDs 10001 .. 10038 mirror the 38 scenario pool

def _build_incident(iid: int) -> dict:
    """Build a deterministic incident for a given integer ID."""
    r = random.Random(iid)            # seeded — same ID → same content
    scenarios = all_scenarios_as_qradar()
    scenario = scenarios[(iid - _INCIDENT_BASE) % len(scenarios)]
    now_ms = int(time.time() * 1000)
    created_ms = now_ms - iid * 60_000
    alert_count = r.randint(1, 8)
    return {
        "id": iid,
        "title": scenario.get("description", "")[:120] or f"Incident #{iid}",
        "priority": r.choice(_PRIORITIES),
        "status": r.choice(_STATUSES),
        "alertCount": alert_count,
        "created": created_ms,
        "lastUpdated": created_ms + r.randint(60_000, 3_600_000),
        "x-mock-source": MOCK_SOURCE,
    }


_INCIDENT_IDS: list[int] = list(range(_INCIDENT_BASE, _INCIDENT_BASE + 38))
_INCIDENT_POOL: dict[int, dict] = {iid: _build_incident(iid) for iid in _INCIDENT_IDS}


# ── Alert pool ────────────────────────────────────────────────────────────────

def _build_alert_for_incident(iid: int, seq: int = 0) -> dict:
    r = random.Random(iid * 1000 + seq)
    template = r.choice(ALERT_TEMPLATES)
    host = r.choice(HOSTNAMES)
    user = r.choice(USERS)
    now_ms = int(time.time() * 1000) - seq * 30_000
    iso = (
        datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    return {
        "_id": f"nw-alert-{iid}-{seq:03d}-{secrets.token_hex(4)}",
        "originalAlert": {
            "id": f"{iid}-{seq}",
            "timestamp": iso,
            "severity": template["Severity"],
            "events": [
                {
                    "tenant": "CORPA",
                    "source": host,
                    "destination": f"172.16.{r.randint(1,254)}.{r.randint(1,254)}",
                    "sourceUser": user,
                    "type": template["Tactic"],
                    "technique": template.get("TechniqueId", ""),
                    "commandLine": template["CommandLine"],
                    "fileName": template["FileName"],
                    "sha256": template["SHA256String"],
                    "md5": template["MD5String"],
                }
            ],
        },
        "x-mock-source": MOCK_SOURCE,
    }


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _check_auth(request: Request) -> None:
    """Accept NetWitness-Token, Bearer, or ?token= with any of the surface tokens."""
    valid = (netwitness_token(), qradar_token(), logscale_token())
    # also accept any token we issued this session
    all_valid = set(valid) | set(_TOKENS.keys())

    qp = request.query_params.get("token", "")
    if qp and any(secrets.compare_digest(qp, t) for t in all_valid):
        return
    nw = request.headers.get("NetWitness-Token", "")
    if nw and any(secrets.compare_digest(nw, t) for t in all_valid):
        return
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and any(
        secrets.compare_digest(auth[7:], t) for t in all_valid
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"status": 401, "message": "Bad credentials", "x-mock-source": MOCK_SOURCE},
    )


def _check_admin(request: Request) -> None:
    expected = admin_key()
    if not expected:
        raise HTTPException(status_code=403, detail="admin endpoints disabled")
    key = (
        request.headers.get("X-Admin-Key", "")
        or request.headers.get("x-admin-key", "")
    )
    if not secrets.compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


def _stamp(response: Response) -> None:
    response.headers["X-Mock-Source"] = MOCK_SOURCE


# ── Router ────────────────────────────────────────────────────────────────────

def _make_router(prefix: str) -> APIRouter:
    router = APIRouter(
        prefix=prefix,
        tags=["netwitness-mock"],
        dependencies=[Depends(fault_check)],
    )

    # ── Authentication ────────────────────────────────────────────────────────

    @router.post("/rest/api/auth/userpass")
    async def auth_userpass(
        response: Response,
        username: str | None = Form(default=None),
        password: str | None = Form(default=None),
    ):
        """NetWitness session-token endpoint.

        Supports three fault modes (set via admin or env):
          locked          → 500 "User account is locked"
          bad_credentials → 401 "Bad credentials"
          unavailable     → 503
        """
        _stamp(response)
        mode = _AUTH_MODE[0]

        if mode == "unavailable":
            raise HTTPException(
                status_code=503,
                detail={"status": 503, "message": "Service Unavailable", "x-mock-source": MOCK_SOURCE},
            )
        if mode == "locked":
            raise HTTPException(
                status_code=500,
                detail={"status": 500, "message": "User account is locked", "x-mock-source": MOCK_SOURCE},
            )
        if mode == "bad_credentials":
            raise HTTPException(
                status_code=401,
                detail={"status": 401, "message": "Bad credentials", "x-mock-source": MOCK_SOURCE},
            )

        token = secrets.token_hex(32)
        _TOKENS[token] = username or "mock-user"
        if len(_TOKENS) > 256:
            oldest = next(iter(_TOKENS))
            _TOKENS.pop(oldest, None)

        return {"accessToken": token, "x-mock-source": MOCK_SOURCE}

    # ── Incidents ─────────────────────────────────────────────────────────────

    @router.get("/rest/api/incidents")
    async def list_incidents(
        request: Request,
        response: Response,
        pageNumber: int = 0,
        pageSize: int = 10,
    ):
        """List incidents. Supports ``pageNumber`` / ``pageSize`` pagination."""
        _check_auth(request)
        _stamp(response)
        pageSize = max(1, min(pageSize, 50))
        lo = pageNumber * pageSize
        hi = lo + pageSize
        page = [_INCIDENT_POOL[iid] for iid in _INCIDENT_IDS[lo:hi]]
        return {
            "items": page,
            "pageNumber": pageNumber,
            "pageSize": pageSize,
            "total": len(_INCIDENT_IDS),
            "x-mock-source": MOCK_SOURCE,
        }

    @router.get("/rest/api/incidents/{incident_id}")
    async def get_incident(
        incident_id: str,
        request: Request,
        response: Response,
    ):
        """Single incident by ID.

        Returns the incident object or NetWitness 12.5-shaped 400 for unknown IDs.
        """
        _check_auth(request)
        _stamp(response)
        try:
            iid = int(incident_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"'{incident_id}' is not a valid incident Id",
            ) from None
        incident = _INCIDENT_POOL.get(iid)
        if incident is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"'{incident_id}' is not a valid incident Id",
            )
        return incident

    # ── Alerts ────────────────────────────────────────────────────────────────

    @router.get("/rest/api/alert/fetch")
    async def fetch_alerts(request: Request, response: Response):
        """Fetch alerts for an incident.

        NetWitness sends a JSON body on this GET: ``{"meta_value": "<id>"}``.
        Returns a list of alert objects each with ``_id`` and
        ``originalAlert.events[]`` (containing the ``tenant`` field that
        act 1454 reads).
        """
        _check_auth(request)
        _stamp(response)

        body: dict = {}
        try:
            body = await request.json()
        except Exception:
            body = {}

        meta_value = body.get("meta_value", "") if isinstance(body, dict) else ""
        try:
            iid = int(meta_value)
        except (ValueError, TypeError):
            iid = _INCIDENT_IDS[0]

        incident = _INCIDENT_POOL.get(iid)
        if incident is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"'{meta_value}' is not a valid incident Id",
            )

        alert_count = incident.get("alertCount", 3)
        alerts = [_build_alert_for_incident(iid, i) for i in range(alert_count)]
        return {"items": alerts, "total": len(alerts), "x-mock-source": MOCK_SOURCE}

    # ── Admin — auth-mode toggle ──────────────────────────────────────────────

    _VALID_MODES = {"normal", "locked", "bad_credentials", "unavailable"}

    @router.post("/_admin/auth_mode")
    async def set_auth_mode(request: Request, response: Response):
        """Set the auth failure simulation mode.

        Body: ``{"mode": "normal" | "locked" | "bad_credentials" | "unavailable"}``

        Admin-key gated.
        """
        _check_admin(request)
        _stamp(response)
        body: dict = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        mode = (body.get("mode") or "").strip().lower() if isinstance(body, dict) else ""
        if mode not in _VALID_MODES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "error": f"invalid mode '{mode}'",
                    "valid": sorted(_VALID_MODES),
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        prev = _AUTH_MODE[0]
        _AUTH_MODE[0] = mode
        return {"previous": prev, "current": mode, "x-mock-source": MOCK_SOURCE}

    @router.get("/_admin/auth_mode")
    async def get_auth_mode(request: Request, response: Response):
        """Return the current auth-mode and issued token count. Admin-key gated."""
        _check_admin(request)
        _stamp(response)
        return {
            "mode": _AUTH_MODE[0],
            "issued_tokens": len(_TOKENS),
            "valid_modes": sorted(_VALID_MODES),
            "x-mock-source": MOCK_SOURCE,
        }

    return router
