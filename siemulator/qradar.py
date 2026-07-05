"""QRadar mock surface — offences + Ariel-search responses.

Mounted at ``SIEMULATOR_QRADAR_PREFIX`` (default ``/qradar``). Returns
QRadar-shaped offences from the same template pool as the LogScale
surface, plus 22 hand-crafted multi-source attack scenarios from
``siemulator.scenarios``.

Auth: ``SEC: <token>`` header (QRadar canonical), ``Authorization:
Bearer``, or ``?token=`` query param. Either the QRadar or LogScale
token is accepted — both surfaces serve synthetic data only.

Field shape pins:
- ``id`` (int) — many real QRadar consumers do ``a['offense_id'] = a['id']``
- ``start_time`` is INT MILLISECONDS EPOCH — consumers do
  ``datetime.fromtimestamp(a['start_time']/1000)``
Breaking either shape crashes downstream ingestion scripts. Pinned in
``tests/test_qradar.py``.

Scenario modes (``?scenarios=<mode>``):
- ``all`` — return ALL fresh scenarios (one-shot dedup; each offence
  ID is served once per process lifetime). Next call returns ``[]``
  until ``POST /_debug/reset_scenarios`` is called.
- ``batch`` — rotate through scenarios one-at-a-time per call.
- ``replay`` — return all scenarios ignoring the one-shot dedup set.
- ``mix`` — scenarios + synthetic templates in one response.

Debug endpoints (admin-key gated):
- ``GET  /_debug/recent`` — last 100 requests this mock saw.
- ``POST /_debug/reset_scenarios`` — clear served-scenarios set.
- ``GET  /_debug/scenarios_state`` — served vs remaining.
Disabled entirely when ``SIEMULATOR_ADMIN_KEY`` is unset.
"""

from __future__ import annotations

import random
import secrets
import time
import uuid
from collections import deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from siemulator.config import MOCK_SOURCE, admin_key, logscale_token, qradar_prefix, qradar_token
from siemulator.fault_inject import fault_check
from siemulator.scenarios import all_scenarios_as_qradar
from siemulator.templates import ALERT_TEMPLATES, HOSTNAMES, USERS


def build_router() -> APIRouter:
    return _make_router(qradar_prefix())


_RECENT_REQ: deque[dict] = deque(maxlen=100)
_SCENARIO_ROTATION_STATE: dict = {"next": 0}
_SCENARIOS_SERVED: set = set()
_ariel_searches: dict[str, dict] = {}


def _check_auth(request: Request) -> None:
    """Accept query-param, SEC header, or Bearer. Either token works on
    either surface — both serve synthetic data only."""
    valid_tokens = (qradar_token(), logscale_token())
    qp = request.query_params.get("token", "")
    if qp and any(secrets.compare_digest(qp, t) for t in valid_tokens):
        return
    sec = request.headers.get("SEC", "") or request.headers.get("sec", "")
    if sec and any(secrets.compare_digest(sec, t) for t in valid_tokens):
        return
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and any(
        secrets.compare_digest(auth[7:], t) for t in valid_tokens
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "http_response": {"code": 401, "message": "Unauthorized"},
            "code": 1005,
            "description": "missing SEC header or Authorization: Bearer token",
            "x-mock-source": MOCK_SOURCE,
        },
    )


def _check_admin(request: Request) -> None:
    """Gate debug endpoints behind SIEMULATOR_ADMIN_KEY. Empty key
    disables them entirely (returns 403)."""
    expected = admin_key()
    if not expected:
        raise HTTPException(status_code=403, detail="admin endpoints disabled")
    key = request.headers.get("x-admin-key", "") or request.headers.get("X-Admin-Key", "")
    if not secrets.compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


def severity_to_qradar(name: str) -> int:
    """LogScale SeverityName → QRadar 1-10 numeric scale."""
    return {
        "Critical": 9,
        "High": 7,
        "Medium": 5,
        "Low": 3,
        "Informational": 1,
    }.get(name, 5)


def _stamp(response: Response) -> None:
    response.headers["X-Mock-Source"] = MOCK_SOURCE


def _build_offense(seq: int = 0) -> dict:
    """Convert a template detection into a QRadar offence."""
    template = random.choice(ALERT_TEMPLATES)
    host = random.choice(HOSTNAMES)
    user = random.choice(USERS)
    now_s = int(time.time()) - seq * random.randint(30, 300)
    sev_num = severity_to_qradar(template["SeverityName"])
    offense_id = random.randint(30_000, 99_999)
    source_ip = template.get("RemoteAddress") or (
        f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    )
    dest_ip = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return {
        "id": offense_id,
        "offense_id": offense_id,
        "description": (
            f"{template['DetectName']} — {template['DetectDescription'][:150]}"
        ),
        "offense_source": source_ip,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "severity": sev_num,
        "magnitude": min(10, sev_num + 1),
        "credibility": random.randint(5, 9),
        "relevance": random.randint(5, 9),
        "status": "OPEN",
        "categories": [template["Tactic"], "Custom Rule Engine"],
        "category_count": 2,
        "security_category_count": 2,
        "policy_category_count": 0,
        "rules": [{"type": "CRE_RULE", "id": random.randint(100_000, 200_000)}],
        "start_time": now_s * 1000,
        "start_epochtime": now_s * 1000,
        "first_persisted_time": now_s * 1000,
        "last_persisted_time": (now_s + 60) * 1000,
        "last_updated_time": (now_s + 30) * 1000,
        "event_count": random.randint(50, 500),
        "flow_count": 0,
        "source_count": 1,
        "username_count": 1,
        "device_count": 2,
        "destination_port": str(template.get("RemotePort", 443)),
        "source_port": str(random.randint(40_000, 60_000)),
        "log_sources": [
            {
                "type_name": "EventCRE",
                "id": 63,
                "name": "Custom Rule Engine-8 :: cre-primary",
                "type_id": 18,
            },
            {
                "type_name": "MicrosoftWindows",
                "id": 168,
                "name": f"WinEventLog @ {host}",
                "type_id": 12,
            },
        ],
        "remote_destination_count": 0,
        "local_destination_count": 1,
        "destination_networks": ["other"],
        "source_network": "Net-10-172-192.Net_10_0_0_0",
        "domain_id": 1,
        "domain_name": "EXAMPLE",
        "assigned_to": None,
        "closing_user": None,
        "closing_reason_id": None,
        "close_time": None,
        "inactive": False,
        "protected": False,
        "follow_up": False,
        "offense_type": 0,
        "source_address_ids": [random.randint(15_000, 20_000)],
        "local_destination_address_ids": [],
        "_detection": {
            "DetectName": template["DetectName"],
            "Tactic": template["Tactic"],
            "TacticId": template["TacticId"],
            "Technique": template["Technique"],
            "TechniqueId": template["TechniqueId"],
            "Severity": template["Severity"],
            "SeverityName": template["SeverityName"],
            "ComputerName": host,
            "UserName": user,
            "CommandLine": template["CommandLine"],
            "FileName": template["FileName"],
            "MD5String": template["MD5String"],
            "SHA256String": template["SHA256String"],
            "ParentImageFileName": template.get("ParentImageFileName", ""),
        },
        "org_id": "1",
        "x-mock-source": MOCK_SOURCE,
    }


def build_offenses(n: int) -> list[dict]:
    n = max(1, min(n, 1000))
    return [_build_offense(i) for i in range(n)]


def _record_request(
    request: Request, mode: str, response_payload, status_code: int = 200
) -> None:
    try:
        body_size = (
            len(response_payload)
            if isinstance(response_payload, (list, dict, str, bytes))
            else 0
        )
        first_row = None
        if isinstance(response_payload, list) and response_payload:
            row = response_payload[0]
            if isinstance(row, dict):
                first_row = {k: row[k] for k in list(row.keys())[:8]}
        auth_seen = []
        if request.query_params.get("token"):
            auth_seen.append("query-token")
        if request.headers.get("SEC") or request.headers.get("sec"):
            auth_seen.append("SEC-header")
        if request.headers.get("Authorization", "").startswith("Bearer "):
            auth_seen.append("Bearer")
        _RECENT_REQ.append(
            {
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "path": str(request.url.path),
                "query": dict(request.query_params),
                "client": (request.client.host if request.client else None),
                "user_agent": request.headers.get("user-agent", "")[:120],
                "auth": auth_seen,
                "range_header": request.headers.get("Range") or request.headers.get("range"),
                "mode": mode,
                "status": status_code,
                "response_count": body_size if isinstance(response_payload, list) else None,
                "response_first_row_preview": first_row,
            }
        )
    except Exception:
        pass


def _make_router(prefix: str) -> APIRouter:
    router = APIRouter(
        prefix=prefix,
        tags=["qradar-mock"],
        dependencies=[Depends(fault_check)],
    )

    @router.get("/")
    @router.get("/api/help")
    @router.get("/api/help/capabilities")
    async def health(response: Response):
        """QRadar help / capabilities. No auth required."""
        _stamp(response)
        return {
            "endpoint_categories": ["siem", "ariel", "reference_data"],
            "deprecated": False,
            "min_version": "12.0",
            "version": "20.0",
            "x-mock-source": MOCK_SOURCE,
            "mock": True,
        }

    @router.get("/api/siem/offenses")
    async def list_offenses(
        request: Request,
        response: Response,
        filter: str | None = None,
        fields: str | None = None,
        sort: str | None = None,
        scenarios: str | None = None,
        extras: int | None = None,
    ):
        """List active offences.

        Modes:
          - default: synthetic offences (Range header honoured: ``items=0-N``).
          - ``?scenarios=all``: one-shot mode — each scenario offence served
            once per process lifetime.
          - ``?scenarios=batch``: rotate one scenario per call.
          - ``?scenarios=replay``: all scenarios ignoring dedup.
          - ``?scenarios=mix``: scenarios + synthetic templates.

        Extras:
          - ``?extras=<N>``: append N randomised synthetic offences to the
            response (capped at 50). Works with ``scenarios=all|batch|replay``.
            Randomised offences are drawn from ``ALERT_TEMPLATES`` with
            per-call randomised host / user / IP / offence_id.
        """
        _check_auth(request)
        _stamp(response)

        # ``?scenarios=all`` bakes in 500 random-shape extras by default
        # so a single poll yields 52 curated + 500 noise = 552 alerts.
        # Callers wanting a bare scenario batch pass ``extras=0`` explicitly.
        _DEFAULT_EXTRAS_FOR_ALL = 500

        def _extras_tail() -> list[dict]:
            if extras is None:
                n = _DEFAULT_EXTRAS_FOR_ALL if scenarios == "all" else 0
            else:
                n = int(extras)
            if n <= 0:
                return []
            return build_offenses(min(n, 1000))

        if scenarios == "all":
            full = all_scenarios_as_qradar()
            fresh = [s for s in full if s.get("offense_id") not in _SCENARIOS_SERVED]
            for s in fresh:
                _SCENARIOS_SERVED.add(s.get("offense_id"))
            tail = _extras_tail()
            out = fresh + tail
            response.headers["X-Mock-Scenarios-Served-Total"] = str(len(_SCENARIOS_SERVED))
            response.headers["X-Mock-Scenarios-Returned"] = str(len(fresh))
            response.headers["X-Mock-Scenarios-Pool-Size"] = str(len(full))
            response.headers["X-Mock-Extras-Appended"] = str(len(tail))
            _record_request(
                request,
                f"scenarios=all(returned={len(fresh)},served={len(_SCENARIOS_SERVED)}/{len(full)},extras={len(tail)})",
                out,
            )
            return out

        if scenarios == "batch":
            full = all_scenarios_as_qradar()
            idx = _SCENARIO_ROTATION_STATE["next"] % len(full)
            _SCENARIO_ROTATION_STATE["next"] = idx + 1
            tail = _extras_tail()
            out = [full[idx]] + tail
            response.headers["X-Mock-Scenario-Index"] = f"{idx + 1}/{len(full)}"
            response.headers["X-Mock-Scenario-Id"] = str(full[idx].get("offense_id"))
            response.headers["X-Mock-Extras-Appended"] = str(len(tail))
            _record_request(request, f"scenarios=batch({idx + 1}/{len(full)},extras={len(tail)})", out)
            return out

        if scenarios == "replay":
            tail = _extras_tail()
            out = all_scenarios_as_qradar() + tail
            response.headers["X-Mock-Extras-Appended"] = str(len(tail))
            _record_request(request, f"scenarios=replay(extras={len(tail)})", out)
            return out

        rng = request.headers.get("Range", "")
        n = 5
        if rng.startswith("items="):
            try:
                lo, hi = rng[6:].split("-", 1)
                n = max(1, min(int(hi) - int(lo) + 1, 50))
            except (ValueError, IndexError):
                pass
        out = build_offenses(n)
        if scenarios == "mix":
            out = all_scenarios_as_qradar() + out
        _record_request(request, f"default(n={len(out)})", out)
        return out

    @router.get("/api/siem/scenarios")
    async def list_scenarios(request: Request, response: Response):
        """Return all sophisticated multi-source attack-narrative offences.
        Same content as ``/api/siem/offenses?scenarios=all`` but without the
        one-shot dedup. Convenient for ad-hoc inspection."""
        _check_auth(request)
        _stamp(response)
        return all_scenarios_as_qradar()

    @router.get("/api/siem/offenses/{offense_id}")
    async def get_offense(offense_id: int, request: Request, response: Response):
        """Single offence by ID. Returns a fresh synthetic offence whose
        ``offense_id`` matches the requested value."""
        _check_auth(request)
        _stamp(response)
        offense = _build_offense(0)
        offense["offense_id"] = offense_id
        return offense

    @router.get("/api/siem/source_addresses")
    async def list_source_addresses(request: Request, response: Response):
        """Optional QRadar endpoint that some integrations poll for IP context."""
        _check_auth(request)
        _stamp(response)
        return [
            {
                "id": random.randint(15_000, 20_000),
                "source_ip": (
                    f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                ),
                "magnitude": random.randint(4, 9),
                "domain_id": 1,
                "x-mock-source": MOCK_SOURCE,
            }
            for _ in range(3)
        ]

    @router.post("/api/ariel/searches")
    async def create_ariel_search(request: Request, response: Response):
        """Create an Ariel search. The mock returns COMPLETED immediately."""
        _check_auth(request)
        _stamp(response)
        body: dict = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        try:
            n = int((body.get("limit") if isinstance(body, dict) else None) or 5)
        except (TypeError, ValueError):
            n = 5
        search_id = str(uuid.uuid4())
        _ariel_searches[search_id] = {
            "events": build_offenses(n),
            "created_at": int(time.time() * 1000),
            "query_expression": (
                body.get("query_expression") if isinstance(body, dict) else ""
            ),
        }
        if len(_ariel_searches) > 256:
            oldest = sorted(
                _ariel_searches.items(), key=lambda kv: kv[1]["created_at"]
            )[0][0]
            _ariel_searches.pop(oldest, None)
        return {
            "search_id": search_id,
            "status": "COMPLETED",
            "progress": 100,
            "record_count": n,
            "x-mock-source": MOCK_SOURCE,
        }

    @router.get("/api/ariel/searches/{search_id}")
    async def get_ariel_search(search_id: str, request: Request, response: Response):
        """Status of an Ariel search. Always COMPLETED."""
        _check_auth(request)
        _stamp(response)
        job = _ariel_searches.get(search_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "http_response": {"code": 404, "message": "Not Found"},
                    "code": 1002,
                    "description": "Ariel search not found",
                    "search_id": search_id,
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        return {
            "search_id": search_id,
            "status": "COMPLETED",
            "progress": 100,
            "record_count": len(job["events"]),
            "x-mock-source": MOCK_SOURCE,
        }

    @router.get("/api/ariel/searches/{search_id}/results")
    async def get_ariel_results(search_id: str, request: Request, response: Response):
        """Results of an Ariel search."""
        _check_auth(request)
        _stamp(response)
        job = _ariel_searches.get(search_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "http_response": {"code": 404, "message": "Not Found"},
                    "code": 1002,
                    "description": "Ariel search not found",
                    "search_id": search_id,
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        return {"events": job["events"], "x-mock-source": MOCK_SOURCE}

    @router.get("/_debug/recent")
    async def debug_recent(request: Request):
        """Last 100 requests this mock saw. Admin-key gated."""
        _check_admin(request)
        return {
            "x-mock-source": MOCK_SOURCE,
            "count": len(_RECENT_REQ),
            "requests": list(_RECENT_REQ),
        }

    @router.post("/_debug/reset_scenarios")
    async def debug_reset_scenarios(request: Request):
        """Clear the served-scenarios set so ``?scenarios=all`` replays the pool."""
        _check_admin(request)
        prev = len(_SCENARIOS_SERVED)
        _SCENARIOS_SERVED.clear()
        return {"x-mock-source": MOCK_SOURCE, "cleared_count": prev, "served_now": 0}

    @router.get("/_debug/scenarios_state")
    async def debug_scenarios_state(request: Request):
        """Served vs remaining scenario IDs."""
        _check_admin(request)
        pool = all_scenarios_as_qradar()
        pool_ids = {s.get("offense_id") for s in pool}
        return {
            "x-mock-source": MOCK_SOURCE,
            "pool_size": len(pool),
            "served_count": len(_SCENARIOS_SERVED),
            "remaining_count": len(pool_ids - _SCENARIOS_SERVED),
            "served_ids": sorted(_SCENARIOS_SERVED),
            "remaining_ids": sorted(pool_ids - _SCENARIOS_SERVED),
        }

    return router
