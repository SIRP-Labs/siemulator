"""Vendor-native endpoints — serve scenarios in each vendor's actual
API response shape rather than wrapped in QRadar offence format.

Purpose: OmniSense (and any SOAR) can point per-vendor ingestion
actions at these endpoints and receive alerts in the exact shape their
vendor parsers expect. No cross-vendor wrapping.

Endpoints:
  GET /crowdstrike/api/v1/detects        — Falcon Streaming API resources[]
  GET /defender/api/security/v1.0/alerts — Graph Security alerts value[]
  GET /netwitness/api/v1/incidents       — NetWitness SA incidents[]

Each endpoint filters the scenario pool by ``_raw_alert.source`` and
returns just those scenarios' raw payloads wrapped in the vendor's
canonical API envelope. Supports ``?scenarios=all|batch|replay``
(same semantics as the QRadar endpoint). Uses token via ``?token=``
matching each vendor's env var.

Note on payload shape: the ``_raw_alert`` bodies are already
vendor-flavoured (Falcon-ish, Defender-ish, etc.) but not always
byte-exact to the real vendor API. Deep-native reformat lives in
follow-up work; this endpoint at least stops mis-wrapping in QRadar
shape, which was the blocker for OmniSense's vendor-native parsers.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from fastapi import APIRouter, HTTPException, Request, Response

from siemulator.config import MOCK_SOURCE
from siemulator.scenarios import SCENARIOS

# Rotation state — one counter per vendor
_VENDOR_ROTATION: dict[str, int] = {}
_VENDOR_SERVED: dict[str, set] = {}


def _vendor_matches(vendor: str, source: str) -> bool:
    """Case-insensitive substring match between vendor label and source."""
    s = source.lower()
    if vendor == "crowdstrike":
        return "crowdstrike" in s or "falcon" in s
    if vendor == "defender":
        return "defender" in s
    if vendor == "netwitness":
        return "netwitness" in s or "rsa sa" in s
    return False


def _scenarios_for_vendor(vendor: str) -> list[dict]:
    """Extract raw_alert dicts for scenarios whose source matches vendor."""
    out = []
    for oid, sid, _label, raw in SCENARIOS:
        src = raw.get("source", "")
        if _vendor_matches(vendor, src):
            copy = dict(raw)
            copy.setdefault("_scenario_id", sid)
            copy.setdefault("_offense_id", oid)
            out.append(copy)
    return out


def _rotate(vendor: str, pool: list[dict]) -> list[dict]:
    """Batch mode — return the next single alert, rotating."""
    if not pool:
        return []
    idx = _VENDOR_ROTATION.get(vendor, 0) % len(pool)
    _VENDOR_ROTATION[vendor] = idx + 1
    return [pool[idx]]


def _dedup_all(vendor: str, pool: list[dict]) -> list[dict]:
    """?scenarios=all — one-shot dedup per vendor."""
    served = _VENDOR_SERVED.setdefault(vendor, set())
    fresh = [s for s in pool if s.get("_offense_id") not in served]
    for s in fresh:
        served.add(s.get("_offense_id"))
    return fresh


def _pick(vendor: str, mode: str | None) -> list[dict]:
    pool = _scenarios_for_vendor(vendor)
    if mode == "all":
        return _dedup_all(vendor, pool)
    if mode == "batch":
        return _rotate(vendor, pool)
    if mode == "replay":
        return pool
    # Default: return everything (replay-like) — vendor endpoints don't
    # generate synthetic templates the way the QRadar endpoint does.
    return pool


def _check_token(request: Request, env_token: str) -> None:
    """Simple token check via ?token=<v> or Authorization header."""
    if not env_token:
        return
    got = request.query_params.get("token") or ""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        got = auth[7:]
    if got != env_token:
        raise HTTPException(status_code=401, detail="invalid_token")


def _stamp(response: Response) -> None:
    response.headers["x-mock-source"] = MOCK_SOURCE


def build_router(*, token_getter: Callable[[str], str]) -> APIRouter:
    """Build the vendor-native router.

    ``token_getter`` returns the expected token for a given vendor
    string (``"crowdstrike"|"defender"|"netwitness"``). Kept as a
    factory so callers control token sourcing.
    """
    router = APIRouter()

    @router.get("/crowdstrike/api/v1/detects")
    async def crowdstrike_detects(
        request: Request,
        response: Response,
        scenarios: str | None = None,
    ):
        """Falcon Streaming API-shape response.

        Envelope: ``{"meta":{"query_time":...}, "resources":[...]}``.
        Each resource is a scenario's ``_raw_alert`` — the raw
        detection body already carries Falcon-style fields
        (device, process, behaviours, iocs, ...).
        """
        _check_token(request, token_getter("crowdstrike"))
        _stamp(response)
        picked = _pick("crowdstrike", scenarios)
        return {
            "meta": {
                "query_time": time.time(),
                "powered_by": "siemulator",
                "trace_id": f"cs-{int(time.time())}",
            },
            "resources": picked,
            "errors": [],
        }

    @router.get("/defender/api/security/v1.0/alerts")
    async def defender_alerts(
        request: Request,
        response: Response,
        scenarios: str | None = None,
    ):
        """Microsoft Graph Security-shape response.

        Envelope: ``{"@odata.context":..., "value":[...]}``.
        """
        _check_token(request, token_getter("defender"))
        _stamp(response)
        picked = _pick("defender", scenarios)
        return {
            "@odata.context": (
                "https://graph.microsoft.com/v1.0/$metadata#Security/alerts"
            ),
            "value": picked,
        }

    @router.get("/netwitness/api/v1/incidents")
    async def netwitness_incidents(
        request: Request,
        response: Response,
        scenarios: str | None = None,
    ):
        """NetWitness SA-shape response.

        Envelope: ``{"incidents":[...]}`` — mirrors the RSA SA REST API.
        """
        _check_token(request, token_getter("netwitness"))
        _stamp(response)
        picked = _pick("netwitness", scenarios)
        return {
            "incidents": picked,
            "totalItems": len(picked),
            "page": 0,
            "size": len(picked),
        }

    @router.post("/_debug/reset_vendor")
    async def reset_vendor(request: Request, response: Response):
        """Clear per-vendor rotation + dedup state. Query: ?vendor=<v>
        or ?vendor=all."""
        _stamp(response)
        v = request.query_params.get("vendor", "all")
        if v == "all":
            _VENDOR_ROTATION.clear()
            _VENDOR_SERVED.clear()
        else:
            _VENDOR_ROTATION.pop(v, None)
            _VENDOR_SERVED.pop(v, None)
        return {"x-mock-source": MOCK_SOURCE, "reset": v}

    return router
