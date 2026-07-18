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


# Per-vendor identity + timestamp field names. Real vendor APIs all
# carry an alert id and a creation timestamp; consumers key off them
# for dedup. Emit each vendor's canonical names so a vendor-specific
# parser finds what it expects.
_VENDOR_ID_FIELDS: dict[str, tuple[str, str]] = {
    # vendor -> (id_field, timestamp_field)
    "crowdstrike": ("detection_id", "created_timestamp"),
    "defender": ("id", "createdDateTime"),
    "netwitness": ("id", "created"),
}


def _iso_to_ms_epoch(ts: str) -> int:
    """ISO-8601 -> int ms epoch. Falls back to a fixed sentinel that is
    still a valid 13-digit ms-epoch so downstream shape checks pass."""
    from datetime import datetime, timezone

    if not ts:
        return 1_780_000_000_000
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return 1_780_000_000_000


# Severity label -> NetWitness riskScore (0-100) + priority band.
# NetWitness Respond scores incidents 0-100 and buckets them into four
# priority bands; consumers filter on both.
_NW_RISK: dict[str, tuple[int, str]] = {
    "critical": (90, "Critical"),
    "high": (75, "High"),
    "medium": (50, "Medium"),
    "low": (25, "Low"),
    "informational": (10, "Low"),
}


def _as_netwitness_incident(oid: int, sid: str, raw: dict) -> dict:
    """Reshape a scenario into a NetWitness Respond incident.

    Field names follow the Respond API's incident object as documented
    at community.netwitness.com — ``id`` is the ``INC-<n>`` string form,
    the human-readable text lives in ``title`` / ``detail``, severity is
    expressed as ``riskScore`` + ``priority``, and the entities involved
    are enumerated under ``events[]`` rather than sitting at top level.

    The full scenario body (``raw_log``, ``parsed``, ``iocs``,
    ``_test_meta``, ``expected_*``) is preserved alongside so the
    fixtures stay useful for grading; a real Respond incident would not
    carry those keys.
    """
    sev = str(raw.get("severity", "medium")).lower()
    risk, priority = _NW_RISK.get(sev, (50, "Medium"))
    parsed = raw.get("parsed", {}) or {}
    alert = raw.get("alert", {}) or {}
    created = raw.get("timestamp", "")

    event = {
        "source": {
            "device": {
                "ipAddress": parsed.get("esrc"),
                "hostname": parsed.get("esrc_hostname"),
                "port": parsed.get("spt"),
            },
            "user": {"username": parsed.get("suser")},
        },
        "destination": {
            "device": {
                "ipAddress": parsed.get("edst"),
                "hostname": parsed.get("edst_hostname"),
                "port": parsed.get("dpt"),
            },
            "user": {"username": parsed.get("duser")},
        },
        "domain": parsed.get("edst_hostname"),
        "eventSource": raw.get("source", "NetWitness"),
        "eventSourceId": parsed.get("sessionid"),
        "type": parsed.get("proto", "Network"),
    }

    out = dict(raw)
    out.update({
        "id": f"INC-{oid}",
        "title": alert.get("name", ""),
        "detail": alert.get("description", ""),
        "riskScore": risk,
        "priority": priority,
        "status": "New",
        "created": created,
        "lastUpdated": created,
        "type": raw.get("category", ""),
        "source": raw.get("source", "NetWitness"),
        "alertCount": 1,
        "eventCount": 1,
        "averageAlertRiskScore": risk,
        "sealed": False,
        "assignee": None,
        "categories": raw.get("qradar_categories", []),
        "events": [event],
        # Portable identity for consumers written against the int-id
        # contract the QRadar surface guarantees. Real Respond incidents
        # have no such field — `id` there is the INC- string above.
        "_offense_id": oid,
        "_scenario_id": sid,
        "start_time": _iso_to_ms_epoch(created),
    })
    return out


def _scenarios_for_vendor(vendor: str) -> list[dict]:
    """Extract raw_alert dicts for scenarios whose source matches vendor.

    NetWitness gets a full reshape into the Respond incident schema (see
    ``_as_netwitness_incident``). The other two vendors keep their
    scenario body at top level, decorated with:

    - the vendor's canonical id + timestamp fields (``detection_id`` /
      ``created_timestamp`` for Falcon, ``id`` / ``createdDateTime`` for
      Graph Security), so a vendor-specific parser finds the identity
      fields it expects;
    - portable ``id`` (int) + ``start_time`` (int ms-epoch) compatibility
      fields, so generic SIEM-shape consumers that were written against
      the QRadar surface keep working without a second code path.

    Both are additive — the vendor-native body fields are untouched.
    """
    id_field, ts_field = _VENDOR_ID_FIELDS.get(vendor, ("id", "created"))
    out = []
    for oid, sid, _label, raw in SCENARIOS:
        src = raw.get("source", "")
        if not _vendor_matches(vendor, src):
            continue
        if vendor == "netwitness":
            out.append(_as_netwitness_incident(oid, sid, raw))
            continue
        copy = dict(raw)
        ms = _iso_to_ms_epoch(copy.get("timestamp", ""))
        # Vendor-canonical timestamp field, plus the vendor's own id
        # field when it is named something other than plain ``id``
        # (Falcon's ``detection_id``). Where the vendor's id field IS
        # ``id`` (Graph Security) the portable int below fills it — one
        # field can't be both a string GUID and an int, and the int form
        # is what every consumer here dedups on.
        copy.setdefault(ts_field, copy.get("timestamp", ""))
        if id_field != "id":
            copy.setdefault(id_field, str(oid))
        # Portable identity — int id + int ms-epoch, matching the
        # contract the QRadar surface guarantees, so consumers written
        # against that surface need no second code path.
        copy.setdefault("id", oid)
        copy.setdefault("start_time", ms)
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

    @router.get("/rest/api/incidents")
    @router.get("/netwitness/api/v1/incidents")
    async def netwitness_incidents(
        request: Request,
        response: Response,
        scenarios: str | None = None,
        pageSize: int | None = None,  # noqa: N803 — vendor's own param name
        pageNumber: int | None = None,  # noqa: N803
    ):
        """NetWitness Respond-shape response.

        ``/rest/api/incidents`` is the real Respond API path;
        ``/netwitness/api/v1/incidents`` is kept as an alias so existing
        configs keep working.

        Envelope matches the documented Respond paging schema::

            {"items": [...], "pageNumber": 0, "pageSize": N,
             "totalPages": 1, "totalItems": N,
             "hasNext": false, "hasPrevious": false}

        ``pageSize`` / ``pageNumber`` are honoured; ``scenarios`` selects
        the pool the same way it does on every other endpoint.
        """
        _check_token(request, token_getter("netwitness"))
        _stamp(response)
        picked = _pick("netwitness", scenarios)

        total = len(picked)
        size = pageSize if pageSize and pageSize > 0 else max(total, 1)
        page = pageNumber if pageNumber and pageNumber > 0 else 0
        start = page * size
        window = picked[start:start + size]
        total_pages = max(1, (total + size - 1) // size)

        return {
            "items": window,
            "pageNumber": page,
            "pageSize": size,
            "totalPages": total_pages,
            "totalItems": total,
            "hasNext": page + 1 < total_pages,
            "hasPrevious": page > 0,
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
