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


# Severity label -> Falcon's numeric severity. CrowdStrike scores
# alerts 0-100 on ``severity`` and mirrors the band in ``severity_name``.
_CS_SEVERITY: dict[str, int] = {
    "critical": 90,
    "high": 70,
    "medium": 50,
    "low": 30,
    "informational": 10,
}

# Stable synthetic tenant + agent ids. Real Falcon uses 32-char hex for
# both; ``composite_id`` is ``<cid>:ind:<agent_id>:<local_id>``.
_CS_CID = "0123456789abcdef0123456789abcdef"


def _cs_agent_id(oid: int) -> str:
    """Deterministic 32-hex agent id derived from the offence id, so the
    same scenario always reports the same sensor."""
    return f"{oid:032x}"


# MITRE tactic name -> id, for the handful the scenario corpus uses.
_MITRE_TACTIC_IDS: dict[str, str] = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}


def _as_crowdstrike_alert(oid: int, sid: str, raw: dict) -> dict:
    """Reshape a scenario into a Falcon Alerts v2 ``DetectsAlert``.

    Field names follow CrowdStrike's own generated model
    (``DetectsAlert`` in CrowdStrike/gofalcon), which is produced from
    their published OpenAPI spec. Identity is the ``composite_id``
    (``<cid>:ind:<agent_id>:<local>``) that the v2 API keys on;
    severity is a 0-100 int with the band mirrored in ``severity_name``;
    ATT&CK data appears both flat (``tactic`` / ``technique`` /
    ``tactic_id`` / ``technique_id``) and under ``mitre_attack[]``.

    Scenario bodies come in two shapes — some carry ``detection`` /
    ``host`` / ``process`` sub-objects, others a flat ``parsed`` dict
    from a raw-log fixture — so both are read.

    The original scenario body is preserved alongside so the fixtures
    stay gradeable; a real Falcon alert would not carry ``raw_log`` /
    ``parsed`` / ``iocs`` / ``_test_meta``.
    """
    parsed = raw.get("parsed", {}) or {}
    detection = raw.get("detection", {}) or {}
    alert = raw.get("alert", {}) or {}
    host = raw.get("host", {}) or {}
    proc = raw.get("process", {}) or {}
    user = raw.get("user", {}) or {}

    sev_name = str(raw.get("severity", "Medium"))
    severity = _CS_SEVERITY.get(sev_name.lower(), 50)
    ts = raw.get("timestamp", "")

    name = (
        detection.get("name")
        or alert.get("name")
        or parsed.get("signature_name")
        or ""
    )
    description = detection.get("description") or alert.get("description") or ""

    technique_id = (
        detection.get("technique")
        or parsed.get("mitre_technique")
        or ""
    )
    tactic = detection.get("tactic") or parsed.get("mitre_tactic") or "Execution"
    tactic_id = _MITRE_TACTIC_IDS.get(tactic, "TA0002")

    filename = (
        proc.get("name")
        or parsed.get("process_name")
        or (parsed.get("process", {}) or {}).get("filename", "")
    )
    filepath = proc.get("path") or parsed.get("loaded_dll_path") or ""
    cmdline = (
        proc.get("command_line")
        or parsed.get("command_line")
        or (parsed.get("process", {}) or {}).get("cmdline", "")
    )
    sha256 = (
        proc.get("sha256")
        or parsed.get("process_sha256")
        or (parsed.get("process", {}) or {}).get("sha256", "")
    )
    md5 = proc.get("md5") or parsed.get("loaded_dll_md5") or ""

    hostname = (
        host.get("hostname")
        or parsed.get("device_hostname")
        or parsed.get("computer")
        or parsed.get("device_host")
        or ""
    )
    local_ip = host.get("ip") or parsed.get("device_ip") or parsed.get("src") or ""
    username = user.get("username") or parsed.get("user") or ""
    logon_domain = ""
    if "\\" in str(username):
        logon_domain, _, username = str(username).partition("\\")

    agent_id = _cs_agent_id(oid)
    composite_id = f"{_CS_CID}:ind:{agent_id}:{oid}"

    mitre = []
    if technique_id:
        mitre.append({
            "pattern_id": oid,
            "tactic": tactic,
            "tactic_id": tactic_id,
            "technique": name,
            "technique_id": technique_id,
        })

    out = dict(raw)
    out.update({
        # Identity — composite_id is what the v2 API's `ids` param takes
        "composite_id": composite_id,
        "id": composite_id,
        "aggregate_id": f"aggind:{agent_id}:{oid}",
        "agent_id": agent_id,
        "cid": _CS_CID,
        "device_id": agent_id,
        # Timestamps
        "created_timestamp": ts,
        "updated_timestamp": ts,
        "timestamp": ts,
        "crawled_timestamp": ts,
        "context_timestamp": ts,
        # Text
        "name": name,
        "display_name": name,
        "description": description,
        # Scoring
        "severity": severity,
        "severity_name": sev_name,
        "confidence": raw.get("confidence", 50),
        # ATT&CK
        "tactic": tactic,
        "tactic_id": tactic_id,
        "technique": name,
        "technique_id": technique_id,
        "objective": "Falcon Detection Method",
        "scenario": sid.lower().replace("-", "_"),
        "mitre_attack": mitre,
        # Classification
        "product": "epp",
        "type": "ldt",
        "pattern_id": oid,
        "pattern_disposition": 0,
        "pattern_disposition_description": "Detection, standard detection.",
        # Triage state
        "status": "new",
        "show_in_ui": True,
        "assigned_to_name": None,
        "assigned_to_uid": None,
        # Process
        "filename": filename,
        "filepath": filepath,
        "cmdline": cmdline,
        "sha256": sha256,
        "md5": md5,
        "parent_process_id": None,
        # Host
        "hostname": hostname,
        "local_ip": local_ip,
        "external_ip": "",
        "platform": "Windows",
        "platform_name": "Windows",
        "machine_domain": logon_domain,
        # User
        "user_name": username,
        "logon_domain": logon_domain,
        # Provenance
        "data_domains": ["Endpoint"],
        "source_products": ["Falcon Insight"],
        "source_vendors": ["CrowdStrike"],
        "falcon_host_link": (
            f"https://falcon.crowdstrike.com/activity-v2/detections/{composite_id}"
        ),
        # Portable identity — Falcon's `id` is the composite string, so
        # the int lives here for consumers written against the QRadar
        # int-id contract.
        "_offense_id": oid,
        "_scenario_id": sid,
        "start_time": _iso_to_ms_epoch(ts),
    })
    return out


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
        if vendor == "crowdstrike":
            out.append(_as_crowdstrike_alert(oid, sid, raw))
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

    @router.get("/alerts/entities/alerts/v2")
    @router.post("/alerts/entities/alerts/v2")
    @router.get("/crowdstrike/api/v1/detects")
    async def crowdstrike_alerts_v2(
        request: Request,
        response: Response,
        scenarios: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ):
        """Falcon Alerts v2-shape response.

        ``/alerts/entities/alerts/v2`` is the real Alerts v2 path (the
        live API takes POST with an ``ids`` body; GET is accepted here
        too since siemulator has no id-query step).
        ``/crowdstrike/api/v1/detects`` is kept as an alias.

        Envelope matches ``DetectsapiPostEntitiesAlertsV2Response``::

            {"meta": {"query_time":…, "powered_by":…, "trace_id":…,
                      "writes": {…},
                      "pagination": {"limit":N, "offset":N, "total":N}},
             "resources": [DetectsAlert, …],
             "errors": []}

        Each resource follows the ``DetectsAlert`` model — ``composite_id``
        identity, 0-100 int ``severity`` with ``severity_name``, flat
        ATT&CK fields plus ``mitre_attack[]``.
        """
        _check_token(request, token_getter("crowdstrike"))
        _stamp(response)
        picked = _pick("crowdstrike", scenarios)

        total = len(picked)
        lim = limit if limit and limit > 0 else max(total, 1)
        off = offset if offset and offset > 0 else 0
        window = picked[off:off + lim]

        return {
            "meta": {
                "query_time": time.time(),
                "powered_by": "siemulator",
                "trace_id": f"cs-{int(time.time())}",
                "writes": {"resources_affected": 0},
                "pagination": {"limit": lim, "offset": off, "total": total},
            },
            "resources": window,
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
