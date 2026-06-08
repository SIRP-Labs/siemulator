"""Record / replay / diff — turn siemulator into a regression-testing
tool for SOC tooling teams.

**The core use case.** You run XSOAR v1 against siemulator, capturing
every (request, response) pair into a named session. Later you run
XSOAR v2 the same way. Diff the two sessions — "did the consumer's
request stream change?" is your regression signal. If v2 made an
extra request, sent different headers, or expected a different
response, the diff surfaces it.

**Three primitives:**

1. **Record** — operator names an active session; every request to the
   bound surfaces (logscale / qradar / splunk) is captured with full
   request + response into the session's append-only JSONL log.

2. **Diff** — given two sessions, walk them in order and report
   per-entry differences: method/path mismatch, status code change,
   body delta, missing/extra entries.

3. **Replay** — when a request arrives with ``?replay_from=<session>``,
   look up the first matching captured entry by ``(method, path,
   sorted query without inject/replay/token keys)`` and serve the
   captured response verbatim — preserved bytes, original status, full
   headers (with the mock-source marker added on top). Bonus for
   snapshot-pinning siemulator's own output so future code changes
   here don't break your consumer's test suite.

**Storage:**
- In-memory append while a session is active (fast).
- Persisted to ``SIEMULATOR_SESSIONS_DIR/<name>.jsonl`` on stop (or
  every K entries during long runs).
- Re-loadable on process restart (sessions survive container redeploy
  as long as the dir is on a persistent volume).

**Token redaction** matches the access log: query-param ``?token=`` and
the ``Authorization`` / ``SEC`` / ``X-Admin-Key`` headers are recorded
as channel names only, never as values.

**Endpoints** (admin-key gated):

- ``POST   /api/sessions/{name}/start``   begin recording
- ``POST   /api/sessions/{name}/stop``    flush + finalize
- ``GET    /api/sessions``                list all sessions (metadata)
- ``GET    /api/sessions/{name}``         session metadata + summary
- ``GET    /api/sessions/{name}/entries`` full req+resp pairs (paginated)
- ``DELETE /api/sessions/{name}``         remove from memory + disk
- ``GET    /api/sessions/diff?a=X&b=Y``   structured diff of two sessions

Replay is opt-in per request via ``?replay_from=<session>`` on any
bound endpoint — works without any admin auth (it's just an alternative
response source the requester chooses).
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp

from siemulator.config import admin_key, sessions_dir

# Query-param keys we strip from the match fingerprint so a request
# carrying ``?replay_from=X&inject_status=500`` matches a recorded
# request that didn't have those (they're meta-params, not API params).
_FINGERPRINT_DROP_KEYS = frozenset({
    "replay_from",
    "inject_status",
    "inject_latency",
    "inject_malformed",
    "token",  # sensitive — already redacted
})

# Sensitive header names — captured as "<present>" channel marker, not value.
_SENSITIVE_HEADERS = frozenset({
    "authorization",
    "sec",
    "x-admin-key",
    "cookie",
    "set-cookie",
})


@dataclass
class CapturedRequest:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]  # sensitive values masked
    body_b64: str  # base64-encoded bytes (or "" if no body)
    body_text: str  # utf-8 decoded if possible, else ""


@dataclass
class CapturedResponse:
    status: int
    headers: dict[str, str]  # sensitive values masked
    body_b64: str
    body_text: str


@dataclass
class SessionEntry:
    idx: int
    ts: str
    duration_ms: int
    request: CapturedRequest
    response: CapturedResponse


@dataclass
class SessionMeta:
    name: str
    started_at: str
    stopped_at: str | None = None
    entry_count: int = 0
    bound_prefixes: list[str] = field(default_factory=list)


class SessionState:
    """In-memory state for a single session — both active recordings
    and finalized loaded-from-disk ones live here."""

    def __init__(self, meta: SessionMeta, entries: list[SessionEntry] | None = None):
        self.meta = meta
        self.entries: list[SessionEntry] = entries or []
        self.recording = meta.stopped_at is None

    def append(self, entry: SessionEntry) -> None:
        self.entries.append(entry)
        self.meta.entry_count = len(self.entries)


# Module-level registry. ``_sessions`` keeps all known sessions in
# memory; ``_active_recording`` points to the most recently started
# session (only one records at a time in v1).
_sessions: dict[str, SessionState] = {}
_active_recording: SessionState | None = None


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _redact_query(qp: dict[str, str]) -> dict[str, str]:
    return {
        k: ("***" if k.lower() in ("token", "key", "api_key", "apikey", "secret", "password") else v)
        for k, v in qp.items()
    }


def _redact_headers(hdrs: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in hdrs.items():
        if k.lower() in _SENSITIVE_HEADERS:
            out[k] = "***"
        else:
            out[k] = v
    return out


def _encode_body(body: bytes) -> tuple[str, str]:
    """Return ``(base64, text-or-empty)``."""
    if not body:
        return "", ""
    b64 = base64.b64encode(body).decode("ascii")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    return b64, text


def _fingerprint(method: str, path: str, query: dict[str, str]) -> str:
    """Match key for replay lookups. Method + path + sorted non-meta query."""
    filtered = {k: v for k, v in query.items() if k not in _FINGERPRINT_DROP_KEYS}
    items = sorted(filtered.items())
    qstr = "&".join(f"{k}={v}" for k, v in items)
    return f"{method.upper()} {path}?{qstr}"


# ── Public API: session lifecycle ───────────────────────────────────


_NAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")


def _validate_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail=f"invalid session name {name!r}; allowed: [A-Za-z0-9._-], 1-64 chars",
        )


def start_session(name: str, bound_prefixes: list[str]) -> SessionState:
    global _active_recording
    _validate_name(name)
    if name in _sessions and _sessions[name].recording:
        raise HTTPException(status_code=409, detail=f"session {name!r} already recording")
    # Starting overwrites a previous (stopped) session with the same name.
    meta = SessionMeta(
        name=name,
        started_at=_utc_iso(),
        bound_prefixes=list(bound_prefixes),
    )
    state = SessionState(meta)
    _sessions[name] = state
    _active_recording = state
    return state


def stop_session(name: str) -> SessionState:
    global _active_recording
    if name not in _sessions:
        raise HTTPException(status_code=404, detail=f"session {name!r} not found")
    state = _sessions[name]
    if not state.recording:
        return state  # idempotent
    state.recording = False
    state.meta.stopped_at = _utc_iso()
    if _active_recording is state:
        _active_recording = None
    _persist(state)
    return state


def delete_session(name: str) -> None:
    global _active_recording
    if name not in _sessions:
        raise HTTPException(status_code=404, detail=f"session {name!r} not found")
    if _active_recording is _sessions[name]:
        _active_recording = None
    del _sessions[name]
    path = _disk_path(name)
    if path.exists():
        path.unlink()


def list_sessions() -> list[dict]:
    return [asdict(s.meta) for s in _sessions.values()]


def get_session(name: str) -> SessionState:
    if name not in _sessions:
        # Try loading from disk
        loaded = _try_load(name)
        if loaded is None:
            raise HTTPException(status_code=404, detail=f"session {name!r} not found")
        _sessions[name] = loaded
    return _sessions[name]


def active_recording() -> SessionState | None:
    return _active_recording


# ── Persistence (JSONL on disk) ────────────────────────────────────


def _disk_path(name: str) -> Path:
    return Path(sessions_dir()) / f"{name}.jsonl"


def _persist(state: SessionState) -> None:
    path = _disk_path(state.meta.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        meta_line = {"_meta": asdict(state.meta)}
        fp.write(json.dumps(meta_line) + "\n")
        for entry in state.entries:
            fp.write(json.dumps(asdict(entry)) + "\n")


def _try_load(name: str) -> SessionState | None:
    path = _disk_path(name)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fp:
            lines = fp.readlines()
        if not lines:
            return None
        meta_obj = json.loads(lines[0])["_meta"]
        meta = SessionMeta(**meta_obj)
        entries = []
        for line in lines[1:]:
            d = json.loads(line)
            entries.append(
                SessionEntry(
                    idx=d["idx"],
                    ts=d["ts"],
                    duration_ms=d["duration_ms"],
                    request=CapturedRequest(**d["request"]),
                    response=CapturedResponse(**d["response"]),
                )
            )
        state = SessionState(meta, entries=entries)
        state.recording = False
        return state
    except (OSError, json.JSONDecodeError, KeyError):
        return None


# ── Diff ───────────────────────────────────────────────────────────


def diff_sessions(a_name: str, b_name: str) -> dict[str, Any]:
    """Walk two sessions in order; report per-entry differences."""
    a = get_session(a_name)
    b = get_session(b_name)
    diffs: list[dict[str, Any]] = []
    max_len = max(len(a.entries), len(b.entries))
    for i in range(max_len):
        ae = a.entries[i] if i < len(a.entries) else None
        be = b.entries[i] if i < len(b.entries) else None
        if ae is None:
            diffs.append({
                "idx": i, "kind": "extra_in_b",
                "b": {"path": be.request.path, "method": be.request.method, "status": be.response.status},
            })
            continue
        if be is None:
            diffs.append({
                "idx": i, "kind": "missing_in_b",
                "a": {"path": ae.request.path, "method": ae.request.method, "status": ae.response.status},
            })
            continue
        entry_diff = _diff_entry(ae, be)
        if entry_diff:
            diffs.append({"idx": i, "kind": "changed", **entry_diff})
    return {
        "a": a_name,
        "b": b_name,
        "a_entry_count": len(a.entries),
        "b_entry_count": len(b.entries),
        "diff_count": len(diffs),
        "identical": len(diffs) == 0,
        "diffs": diffs,
    }


def _diff_entry(a: SessionEntry, b: SessionEntry) -> dict[str, Any] | None:
    """Return diff dict if entries differ at the request-shape or status
    level. Body deltas reported as line counts; full diff is on you."""
    out: dict[str, Any] = {}
    if a.request.method != b.request.method:
        out["method"] = {"a": a.request.method, "b": b.request.method}
    if a.request.path != b.request.path:
        out["path"] = {"a": a.request.path, "b": b.request.path}
    if a.request.query != b.request.query:
        # Show keys added/removed/changed
        a_keys = set(a.request.query.keys())
        b_keys = set(b.request.query.keys())
        q: dict[str, Any] = {}
        if a_keys - b_keys:
            q["removed"] = sorted(a_keys - b_keys)
        if b_keys - a_keys:
            q["added"] = sorted(b_keys - a_keys)
        changed = {k for k in a_keys & b_keys if a.request.query[k] != b.request.query[k]}
        if changed:
            q["changed"] = {k: {"a": a.request.query[k], "b": b.request.query[k]} for k in sorted(changed)}
        if q:
            out["query"] = q
    if a.response.status != b.response.status:
        out["status"] = {"a": a.response.status, "b": b.response.status}
    # Body delta — line count only (full diff is large; consumer can pull
    # the raw entries and diff itself).
    if a.response.body_text != b.response.body_text:
        a_lines = a.response.body_text.splitlines()
        b_lines = b.response.body_text.splitlines()
        out["body_lines_delta"] = len(b_lines) - len(a_lines)
        out["body_bytes_delta"] = len(b.response.body_b64) - len(a.response.body_b64)
    return out or None


# ── Replay lookup ──────────────────────────────────────────────────


def lookup_replay(
    session_name: str, method: str, path: str, query: dict[str, str]
) -> SessionEntry | None:
    """Find the first captured entry matching the request fingerprint."""
    try:
        state = get_session(session_name)
    except HTTPException:
        return None
    target = _fingerprint(method, path, query)
    for entry in state.entries:
        recorded = _fingerprint(
            entry.request.method, entry.request.path, entry.request.query
        )
        if recorded == target:
            return entry
    return None


# ── Middleware ─────────────────────────────────────────────────────


class SessionMiddleware(BaseHTTPMiddleware):
    """Captures req+resp pairs when an active recording is in progress;
    serves replay responses when ``?replay_from=<session>`` is set.

    Bound to the same prefixes as access_log (the API surfaces) — UI / docs
    / meta endpoints aren't recorded or replayable.
    """

    def __init__(self, app: ASGIApp, bound_prefixes: tuple[str, ...]):
        super().__init__(app)
        self.bound = bound_prefixes

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path
        if not any(path.startswith(p) for p in self.bound):
            return await call_next(request)

        # ── Replay short-circuit ──
        replay_from = request.query_params.get("replay_from", "")
        if replay_from:
            qp = dict(request.query_params)
            qp.pop("replay_from", None)
            entry = lookup_replay(replay_from, request.method, path, qp)
            if entry is None:
                return Response(
                    content=json.dumps({
                        "error": "no matching entry in session",
                        "session": replay_from,
                        "fingerprint": _fingerprint(request.method, path, qp),
                        "x-mock-source": "siemulator",
                    }),
                    status_code=404,
                    media_type="application/json",
                    headers={
                        "X-Replay-From": replay_from,
                        "X-Replay-Match": "miss",
                        "X-Mock-Source": "siemulator",
                    },
                )
            body = base64.b64decode(entry.response.body_b64) if entry.response.body_b64 else b""
            return Response(
                content=body,
                status_code=entry.response.status,
                media_type=entry.response.headers.get("content-type"),
                headers={
                    "X-Replay-From": replay_from,
                    "X-Replay-Idx": str(entry.idx),
                    "X-Replay-Match": "hit",
                    "X-Mock-Source": "siemulator",
                },
            )

        # ── Recording pass-through ──
        rec = active_recording()
        if rec is None:
            return await call_next(request)

        # Read the request body (so we can both capture it AND pass it
        # along to the handler). Starlette lets us re-inject via _receive.
        body_bytes = await request.body()

        async def receive():  # re-injection of the buffered body
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        request._receive = receive  # type: ignore[attr-defined]

        t0 = time.perf_counter()
        response = await call_next(request)
        dur_ms = int((time.perf_counter() - t0) * 1000)

        # Capture response body.
        resp_chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            resp_chunks.append(chunk)
        resp_body = b"".join(resp_chunks)

        # Re-emit the response with the captured body.
        new_headers = dict(response.headers)
        new_headers["content-length"] = str(len(resp_body))
        out_response = Response(
            content=resp_body,
            status_code=response.status_code,
            headers=new_headers,
            media_type=response.media_type,
        )

        req_b64, req_text = _encode_body(body_bytes)
        resp_b64, resp_text = _encode_body(resp_body)

        entry = SessionEntry(
            idx=len(rec.entries),
            ts=_utc_iso(),
            duration_ms=dur_ms,
            request=CapturedRequest(
                method=request.method,
                path=path,
                query=_redact_query(dict(request.query_params)),
                headers=_redact_headers(dict(request.headers)),
                body_b64=req_b64,
                body_text=req_text[:8000],  # truncation only on text-view
            ),
            response=CapturedResponse(
                status=response.status_code,
                headers=dict(response.headers),
                body_b64=resp_b64,
                body_text=resp_text[:64000],
            ),
        )
        rec.append(entry)
        return out_response


# ── Admin endpoints ────────────────────────────────────────────────


def _check_admin(request: Request) -> None:
    expected = admin_key()
    if not expected:
        raise HTTPException(status_code=403, detail="admin endpoints disabled")
    key = request.headers.get("x-admin-key", "") or request.headers.get("X-Admin-Key", "")
    if not secrets.compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


def build_router(bound_prefixes: list[str]) -> APIRouter:
    router = APIRouter(prefix="/api/sessions", tags=["sessions"])

    @router.get("/diff")
    async def diff(request: Request, a: str, b: str):
        """Structured diff of two sessions."""
        _check_admin(request)
        return diff_sessions(a, b)

    @router.get("")
    @router.get("/")
    async def list_(request: Request):
        """List all known sessions (in-memory + on-disk)."""
        _check_admin(request)
        # Surface any on-disk sessions we haven't loaded yet
        try:
            d = Path(sessions_dir())
            if d.is_dir():
                for f in d.glob("*.jsonl"):
                    name = f.stem
                    if name not in _sessions:
                        loaded = _try_load(name)
                        if loaded:
                            _sessions[name] = loaded
        except OSError:
            pass
        return {"sessions": list_sessions()}

    @router.post("/{name}/start")
    async def start(name: str, request: Request):
        """Begin recording into session ``name``. Overwrites any prior
        session with the same name (after stop). Only one session records
        at a time — starting a new one auto-stops any prior active."""
        _check_admin(request)
        # Auto-stop any prior active recording.
        prior = active_recording()
        if prior is not None and prior.meta.name != name:
            stop_session(prior.meta.name)
        # Wipe any prior session-of-the-same-name first.
        if name in _sessions:
            delete_session(name)
        state = start_session(name, list(bound_prefixes))
        return asdict(state.meta)

    @router.post("/{name}/stop")
    async def stop(name: str, request: Request):
        """Finalize the session — flush to disk, mark stopped."""
        _check_admin(request)
        state = stop_session(name)
        return asdict(state.meta)

    @router.get("/{name}")
    async def info(name: str, request: Request):
        """Session metadata + per-path summary."""
        _check_admin(request)
        state = get_session(name)
        path_counts: dict[str, int] = {}
        status_counts: dict[int, int] = {}
        for e in state.entries:
            path_counts[e.request.path] = path_counts.get(e.request.path, 0) + 1
            status_counts[e.response.status] = (
                status_counts.get(e.response.status, 0) + 1
            )
        return {
            **asdict(state.meta),
            "recording": state.recording,
            "by_path": dict(sorted(path_counts.items(), key=lambda kv: -kv[1])),
            "by_status": {str(k): v for k, v in sorted(status_counts.items())},
        }

    @router.get("/{name}/entries")
    async def entries(name: str, request: Request, limit: int = 100, offset: int = 0):
        """Full request+response entries, paginated."""
        _check_admin(request)
        state = get_session(name)
        start_i = max(0, offset)
        end_i = min(len(state.entries), start_i + max(1, min(limit, 500)))
        return {
            "session": name,
            "total": len(state.entries),
            "offset": start_i,
            "count": end_i - start_i,
            "entries": [asdict(e) for e in state.entries[start_i:end_i]],
        }

    @router.delete("/{name}")
    async def delete_(name: str, request: Request):
        _check_admin(request)
        delete_session(name)
        return {"deleted": name}

    return router


def _all_sessions() -> Iterator[SessionState]:
    """Test helper — yields all currently-tracked sessions."""
    return iter(_sessions.values())


def _wipe_all() -> None:
    """Test helper — clears in-memory state. Doesn't touch disk."""
    global _active_recording
    _sessions.clear()
    _active_recording = None
