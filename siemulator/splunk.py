"""Splunk Enterprise REST mock surface.

Mounted at ``SIEMULATOR_SPLUNK_PREFIX`` (default ``/splunk``). Mirrors
Splunk Enterprise's REST search API so any Splunk-compatible consumer
(REST Modular Input, Splunk SOAR REST asset, Splunk Add-on, custom
HEC-like pulling integration) can point at it with just URL + token.

Shape choice — JSON, not XML
----------------------------
Splunk's native default is Atom/XML. Modern clients almost universally
pass ``?output_mode=json`` to flip to JSON. We always return JSON
regardless of ``output_mode`` because (a) it's what every consumer
written this decade expects, and (b) XML mocking is needless complexity
for a synthetic-data fixture. Consumers passing ``output_mode=xml``
get a documented 406 (rather than a silent shape mismatch) — the JSON
contract is the supported one.

Auth
----
Splunk REST canonically uses ``Authorization: Splunk <session-key>``
for session-based auth and ``Authorization: Bearer <token>`` for the
newer token-based auth. We accept both. The ``?token=`` query-param
channel works too for proxy-stripped environments.

Cross-token acceptance: LogScale + QRadar tokens also work, same as
the other surfaces — all three serve synthetic data, so config-paste
mistakes are forgiven by default.

Async search lifecycle
----------------------
Real Splunk searches are async:

  POST /services/search/jobs          → returns {sid: "..."}
  GET  /services/search/jobs/{sid}    → status (state: DONE, dispatchState, etc.)
  GET  /services/search/jobs/{sid}/results → results

The mock returns DONE immediately and the results come from the same
synthetic template + scenario pool used by the LogScale/QRadar surfaces.
``search`` SPL string is recorded but ignored (no execution engine).

Field shape pins
----------------
Consumers reading from Splunk events look for:
- ``_time``: float seconds-since-epoch (NOT ms, NOT ISO 8601)
- ``host``, ``source``, ``sourcetype``, ``index``
- ``_raw``: the original event text
- ``_indextime``: when the event was indexed

We populate all of these so consumers don't have to special-case the
mock.
"""

from __future__ import annotations

import random
import secrets
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from siemulator.config import (
    MOCK_SOURCE,
    logscale_token,
    qradar_token,
    splunk_prefix,
    splunk_token,
)
from siemulator.fault_inject import fault_check
from siemulator.templates import ALERT_TEMPLATES, HOSTNAMES, USERS


def build_router() -> APIRouter:
    return _make_router(splunk_prefix())


# In-memory search jobs. Same FIFO cap as the other surfaces.
_search_jobs: dict[str, dict] = {}


def _check_auth(request: Request) -> None:
    """Accept Splunk session, Bearer, or ?token=. Cross-token w/ LogScale+QRadar."""
    valid_tokens = (splunk_token(), logscale_token(), qradar_token())
    qp = request.query_params.get("token", "")
    if qp and any(secrets.compare_digest(qp, t) for t in valid_tokens):
        return
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Splunk ") and any(
        secrets.compare_digest(auth[7:], t) for t in valid_tokens
    ):
        return
    if auth.startswith("Bearer ") and any(
        secrets.compare_digest(auth[7:], t) for t in valid_tokens
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "messages": [
                {
                    "type": "WARN",
                    "code": "Unauthorized",
                    "text": "missing or invalid token",
                }
            ],
            "expected": (
                "Authorization: Splunk <session>  OR  "
                "Authorization: Bearer <token>  OR  ?token=<token>"
            ),
            "x-mock-source": MOCK_SOURCE,
        },
    )


def _build_event(seq: int = 0) -> dict:
    """Build one Splunk-shape event from a random template."""
    template = random.choice(ALERT_TEMPLATES)
    host = random.choice(HOSTNAMES)
    user = random.choice(USERS)
    # Splunk _time is float seconds-since-epoch, NOT ms.
    now_s = time.time() - seq * random.randint(30, 300)
    sid = secrets.token_hex(8)
    raw = (
        f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now_s))} "
        f"CrowdStrike Falcon: DetectName=\"{template['DetectName']}\" "
        f"Severity={template['Severity']} ComputerName={host} "
        f"UserName={user} TechniqueId={template['TechniqueId']} "
        f"FileName={template['FileName']} MD5={template['MD5String']}"
    )
    return {
        "_time": now_s,
        "_indextime": str(int(now_s)),
        "_raw": raw,
        "_serial": str(seq),
        "_sourcetype": "crowdstrike:falcon:detection",
        "host": host,
        "source": "siemulator:logscale-mirror",
        "sourcetype": "crowdstrike:falcon:detection",
        "index": "main",
        "splunk_server": "siemulator-mock",
        "DetectName": template["DetectName"],
        "DetectDescription": template["DetectDescription"],
        "Severity": template["Severity"],
        "SeverityName": template["SeverityName"],
        "Tactic": template["Tactic"],
        "TacticId": template["TacticId"],
        "Technique": template["Technique"],
        "TechniqueId": template["TechniqueId"],
        "ComputerName": host,
        "UserName": user,
        "CommandLine": template["CommandLine"],
        "FileName": template["FileName"],
        "FilePath": template["FilePath"],
        "MD5String": template["MD5String"],
        "SHA256String": template["SHA256String"],
        "ParentImageFileName": template.get("ParentImageFileName", ""),
        "FalconHostLink": (
            f"https://falcon.crowdstrike.com/activity/detections/detail/"
            f"ldt:{sid}:{seq}"
        ),
        "x-mock-source": MOCK_SOURCE,
    }


def _build_events(n: int) -> list[dict]:
    n = max(1, min(n, 50))
    return [_build_event(i) for i in range(n)]


def _stamp(response: Response) -> None:
    response.headers["X-Mock-Source"] = MOCK_SOURCE


def _make_router(prefix: str) -> APIRouter:
    router = APIRouter(
        prefix=prefix,
        tags=["splunk-mock"],
        dependencies=[Depends(fault_check)],
    )

    @router.get("/services/server/info")
    async def server_info(response: Response):
        """Health — no auth. Real Splunk returns Atom XML; we return
        Splunk-shaped JSON (the modern default for ``?output_mode=json``)."""
        _stamp(response)
        return {
            "entry": [
                {
                    "name": "server-info",
                    "content": {
                        "build": "siemulator-mock",
                        "version": "9.2.0",
                        "serverName": "siemulator-mock",
                        "isFree": "0",
                        "licenseState": "OK",
                        "x-mock-source": MOCK_SOURCE,
                    },
                }
            ],
            "mock": True,
            "x-mock-source": MOCK_SOURCE,
        }

    @router.post("/services/search/jobs")
    async def create_search_job(request: Request, response: Response):
        """Submit a search. Returns ``{sid: ...}`` like real Splunk.
        The ``search`` form field is recorded but not executed — the
        synthetic event pool is what fills the results."""
        _check_auth(request)
        _stamp(response)

        # Splunk accepts form-encoded body. Pull `search` + `count` if present.
        form = {}
        try:
            form = dict(await request.form())
        except Exception:
            form = {}
        # Also accept JSON body for modern clients.
        if not form:
            try:
                form = await request.json()
            except Exception:
                form = {}

        count = 10
        try:
            if "count" in form:
                count = max(1, min(50, int(form["count"])))
        except (TypeError, ValueError):
            pass

        sid = str(uuid.uuid4())
        _search_jobs[sid] = {
            "events": _build_events(count),
            "created_at": int(time.time() * 1000),
            "search": str(form.get("search", ""))[:500],
        }
        if len(_search_jobs) > 256:
            oldest = sorted(
                _search_jobs.items(), key=lambda kv: kv[1]["created_at"]
            )[0][0]
            _search_jobs.pop(oldest, None)
        return {"sid": sid, "x-mock-source": MOCK_SOURCE}

    @router.get("/services/search/jobs/export")
    async def export_search(
        request: Request,
        response: Response,
        search: str = "",
        count: int = 10,
    ):
        """One-shot synchronous search — Splunk's ``oneshot`` mode.

        Submits, executes, and returns results in one call. Most
        modern ingestion paths prefer this over the async POST→GET
        flow.

        IMPORTANT: registered BEFORE ``/services/search/jobs/{sid}`` so
        FastAPI doesn't match ``export`` as a sid parameter.
        """
        _check_auth(request)
        _stamp(response)
        n = max(1, min(50, count))
        events = _build_events(n)
        return {
            "preview": False,
            "init_offset": 0,
            "messages": [],
            "fields": [
                {"name": "_time"},
                {"name": "_raw"},
                {"name": "host"},
                {"name": "source"},
                {"name": "sourcetype"},
                {"name": "DetectName"},
                {"name": "Severity"},
                {"name": "TechniqueId"},
            ],
            "results": events,
            "x-mock-source": MOCK_SOURCE,
        }

    @router.get("/services/search/jobs/{sid}")
    async def get_search_job(sid: str, request: Request, response: Response):
        """Search status. Mock returns DONE immediately."""
        _check_auth(request)
        _stamp(response)
        job = _search_jobs.get(sid)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "messages": [
                        {
                            "type": "WARN",
                            "code": "NotFound",
                            "text": f"search job {sid} not found",
                        }
                    ],
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        return {
            "entry": [
                {
                    "name": sid,
                    "content": {
                        "sid": sid,
                        "dispatchState": "DONE",
                        "isDone": True,
                        "isFailed": False,
                        "doneProgress": 1.0,
                        "eventCount": len(job["events"]),
                        "resultCount": len(job["events"]),
                        "scanCount": len(job["events"]),
                        "label": job.get("search", "")[:80],
                    },
                }
            ],
            "x-mock-source": MOCK_SOURCE,
        }

    @router.get("/services/search/jobs/{sid}/results")
    async def get_search_results(sid: str, request: Request, response: Response):
        """Search results in Splunk's JSON shape: ``{results: [...]}``."""
        _check_auth(request)
        _stamp(response)
        job = _search_jobs.get(sid)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "messages": [
                        {
                            "type": "WARN",
                            "code": "NotFound",
                            "text": f"search job {sid} not found",
                        }
                    ],
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        return {
            "preview": False,
            "init_offset": 0,
            "messages": [],
            "fields": [
                {"name": "_time"},
                {"name": "_raw"},
                {"name": "host"},
                {"name": "source"},
                {"name": "sourcetype"},
                {"name": "DetectName"},
                {"name": "Severity"},
                {"name": "TechniqueId"},
            ],
            "results": job["events"],
            "x-mock-source": MOCK_SOURCE,
        }

    return router
