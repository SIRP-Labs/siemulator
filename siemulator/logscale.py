"""Falcon LogScale (Humio REST) mock surface.

Mounted at ``SIEMULATOR_LOGSCALE_PREFIX`` (default ``/logscale``).
Mirrors Humio's REST shape so any LogScale-compatible integration
can point at it with just URL + token config.

Auth: ``Authorization: Bearer <token>`` OR ``?token=<token>`` query
param (the query-param channel exists because some forward proxies
strip Authorization headers in outbound flows). Either the LogScale
or QRadar token is accepted on both surfaces — both serve synthetic
data only, so cross-acceptance has zero security impact and removes
a class of config-paste friction during integration setup.

Health endpoints (``/status``, ``/repositories``) require no auth so
integration UIs can probe before credentials are configured.

Every response carries ``X-Mock-Source`` header + ``x-mock-source``
field in JSON. No write side — POST/queryjobs stores only an int
(limit) into per-job state.
"""

from __future__ import annotations

import asyncio
import json
import random
import secrets
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse

from siemulator.config import MOCK_SOURCE, logscale_prefix, logscale_token, qradar_token
from siemulator.fault_inject import fault_check
from siemulator.templates import ALERT_TEMPLATES, HOSTNAMES, REPO_NAME, USERS


def build_router() -> APIRouter:
    """Build the LogScale router at the configured prefix."""
    return _make_router(logscale_prefix())


# Active query jobs (poll-style API). In-memory only.
_query_jobs: dict[str, dict] = {}


def _check_auth(request: Request) -> None:
    valid_tokens = (logscale_token(), qradar_token())
    qp = request.query_params.get("token", "")
    if qp and any(secrets.compare_digest(qp, t) for t in valid_tokens):
        return
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and any(
        secrets.compare_digest(auth[7:], t) for t in valid_tokens
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "missing or invalid token",
            "expected": "Authorization: Bearer <token>  OR  ?token=<token> query param",
            "x-mock-source": MOCK_SOURCE,
        },
    )


def _build_event(seq: int = 0) -> dict:
    template = random.choice(ALERT_TEMPLATES)
    host = random.choice(HOSTNAMES)
    user = random.choice(USERS)
    now_ms = int(time.time() * 1000) - seq * random.randint(30_000, 300_000)
    iso = (
        datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    detection_id = (
        "ldt:" + secrets.token_hex(16) + ":" + str(random.randint(10_000, 99_999))
    )
    event = {
        "@timestamp": iso,
        "@id": secrets.token_hex(12),
        "@rawstring": (
            f"{iso} CrowdStrike Falcon Sensor — Detection: "
            f"{template['DetectName']} on {host} by {user}"
        ),
        "#repo": REPO_NAME,
        "#type": "kv",
        "metadata.customerIDString": "0123456789abcdef0123456789abcdef",
        "metadata.eventType": "DetectionSummaryEvent",
        "metadata.eventCreationTime": now_ms,
        "metadata.offset": random.randint(10_000_000, 99_999_999),
        "metadata.version": "1.0",
        "event.SensorId": secrets.token_hex(16),
        "event.DetectId": detection_id,
        "event.DetectName": template["DetectName"],
        "event.DetectDescription": template["DetectDescription"],
        "event.Severity": template["Severity"],
        "event.SeverityName": template["SeverityName"],
        "event.Tactic": template["Tactic"],
        "event.TacticId": template["TacticId"],
        "event.Technique": template["Technique"],
        "event.TechniqueId": template["TechniqueId"],
        "event.ComputerName": host,
        "event.UserName": user,
        "event.MachineDomain": "EXAMPLE",
        "event.ProcessId": random.randint(2_000, 60_000),
        "event.ParentProcessId": random.randint(2_000, 60_000),
        "event.ProcessStartTime": now_ms // 1000,
        "event.FileName": template["FileName"],
        "event.FilePath": template["FilePath"],
        "event.CommandLine": template["CommandLine"],
        "event.MD5String": template["MD5String"],
        "event.SHA256String": template["SHA256String"],
        "event.ParentImageFileName": template.get("ParentImageFileName", ""),
        "event.ParentCommandLine": template.get("ParentCommandLine", ""),
        "event.FalconHostLink": (
            f"https://falcon.crowdstrike.com/activity/detections/detail/{detection_id}"
        ),
        "x-mock-source": MOCK_SOURCE,
    }
    for k in ("RemoteAddress", "RemotePort", "Domain", "ConnectionFrequencyMinutes"):
        if k in template:
            event[f"event.{k}"] = template[k]
    return event


def build_events(n: int) -> list[dict]:
    n = max(1, min(n, 50))
    return [_build_event(i) for i in range(n)]


def _envelope(events: list[dict]) -> dict:
    return {
        "events": events,
        "metadata": {
            "totalWork": len(events),
            "doneWork": len(events),
            "workInProgress": 0,
            "extraData": {
                "x-mock-source": MOCK_SOURCE,
                "x-mock-version": "1.0",
                "x-server-timestamp": int(time.time() * 1000),
            },
        },
    }


def _stamp(response: Response) -> None:
    response.headers["X-Mock-Source"] = MOCK_SOURCE


def _make_router(prefix: str) -> APIRouter:
    router = APIRouter(
        prefix=prefix,
        tags=["logscale-mock"],
        dependencies=[Depends(fault_check)],
    )

    @router.get("/")
    @router.get("/api/v1/status")
    async def status_endpoint(response: Response):
        """Health/info — no auth required."""
        _stamp(response)
        return {
            "name": "Falcon LogScale (siemulator mock)",
            "version": "1.139.0",
            "humio-version": "1.139.0",
            "mock": True,
            "x-mock-source": MOCK_SOURCE,
        }

    @router.get("/api/v1/repositories")
    async def list_repositories(response: Response):
        """Lists the single mock repo. No auth required."""
        _stamp(response)
        return [
            {
                "name": REPO_NAME,
                "description": "synthetic CrowdStrike detections",
                "id": "rep_mock_detections",
                "x-mock-source": MOCK_SOURCE,
            }
        ]

    @router.get("/api/v1/repositories/{repo}/alerts")
    async def list_alerts(
        repo: str,
        request: Request,
        response: Response,
        limit: int = 3,
    ):
        """List active alerts. Mirrors Humio's REST alert-listing shape."""
        _check_auth(request)
        _stamp(response)
        return _envelope(build_events(limit))

    @router.get("/api/v1/repositories/{repo}/query")
    async def rest_query(
        repo: str,
        request: Request,
        response: Response,
        q: str | None = None,
        limit: int = 3,
    ):
        """REST search endpoint. ``q`` is accepted but ignored — the mock
        returns from the template pool regardless of query expression."""
        _check_auth(request)
        _stamp(response)
        return _envelope(build_events(limit))

    @router.post("/api/v1/repositories/{repo}/queryjobs")
    async def submit_queryjob(
        repo: str,
        request: Request,
        response: Response,
    ):
        """Async query submission. Returns ``{id: <uuid>}`` — poll the GET
        sibling endpoint to retrieve results."""
        _check_auth(request)
        _stamp(response)
        body: dict = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        try:
            n = int(body.get("limit", 3))
        except (TypeError, ValueError):
            n = 3
        job_id = str(uuid.uuid4())
        _query_jobs[job_id] = {
            "events": build_events(n),
            "created_at": int(time.time() * 1000),
        }
        if len(_query_jobs) > 256:
            oldest = sorted(_query_jobs.items(), key=lambda kv: kv[1]["created_at"])[0][0]
            _query_jobs.pop(oldest, None)
        return {"id": job_id, "x-mock-source": MOCK_SOURCE}

    @router.get("/api/v1/repositories/{repo}/queryjobs/{job_id}")
    async def poll_queryjob(
        repo: str,
        job_id: str,
        request: Request,
        response: Response,
    ):
        """Poll an async query job. Repeated polls return identical events."""
        _check_auth(request)
        _stamp(response)
        job = _query_jobs.get(job_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "queryjob not found",
                    "job_id": job_id,
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        return _envelope(job["events"])

    @router.get("/api/v1/repositories/{repo}/stream")
    async def stream_alerts(
        repo: str,
        request: Request,
        rate: float = 1.0,
        max_count: int = 0,
    ):
        """Push-style alert feed via Server-Sent Events.

        Pushes one fresh synthetic alert every ``1/rate`` seconds. Default
        1 alert/sec; ``?rate=5`` for five per second; ``?rate=0.1`` for one
        every 10 seconds. Clamped to [0.05, 20.0] req/s.

        ``?max_count=N`` ends the stream after N events (useful for
        bounded tests). ``max_count=0`` (default) is unbounded.

        Auth: same three channels as the pull endpoints. The client's
        connection close ends the stream — siemulator detects it via
        the request disconnect signal and stops generating.

        Each event is emitted as one SSE record:

            id: <integer monotonic counter>
            event: alert
            data: <single-line JSON of the alert>

        Consumers using EventSource (browser) or sseclient (Python) get
        first-class push semantics; consumers preferring raw NDJSON can
        use the same endpoint and parse the lines.
        """
        _check_auth(request)
        # Clamp rate to sane bounds (5 ms minimum interval; 20 Hz ceiling).
        rate = max(0.05, min(20.0, float(rate)))
        interval = 1.0 / rate

        async def event_generator():
            counter = 0
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    event = _build_event(0)
                    payload = json.dumps(event, separators=(",", ":"))
                    yield (
                        f"id: {counter}\n"
                        f"event: alert\n"
                        f"data: {payload}\n\n"
                    )
                    counter += 1
                    if 0 < max_count <= counter:
                        # Emit a final "end" event for clean client shutdown.
                        yield (
                            f"id: {counter}\n"
                            "event: end\n"
                            f"data: {{\"reason\":\"max_count_reached\","
                            f"\"emitted\":{counter},"
                            f"\"x-mock-source\":\"{MOCK_SOURCE}\"}}\n\n"
                        )
                        break
                    await asyncio.sleep(interval)
            except asyncio.CancelledError:
                # Client disconnected mid-sleep — clean shutdown.
                raise

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",  # disable nginx/CF buffering
                "X-Mock-Source": MOCK_SOURCE,
            },
        )

    return router
