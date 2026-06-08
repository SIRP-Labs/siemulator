"""Pinned regressions for the SSE push surface."""

from __future__ import annotations

import json
import os
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate_env():
    keys = ("SIEMULATOR_LOGSCALE_TOKEN",)
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _client(token: str = "ls-tok") -> TestClient:
    os.environ["SIEMULATOR_LOGSCALE_TOKEN"] = token
    from siemulator.app import create_app

    return TestClient(create_app())


def _parse_sse(text: str) -> list[dict]:
    """Parse SSE text into a list of (event, data) records."""
    records = []
    current = {}
    for line in text.split("\n"):
        if not line.strip():
            if current:
                records.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        value = value.lstrip(" ")
        current[field] = value
    if current:
        records.append(current)
    return records


# ── Basic streaming ──────────────────────────────────────────────


def test_sse_requires_auth():
    c = _client()
    # No Bearer header
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=10&max_count=1"
    )
    assert r.status_code == 401


def test_sse_streams_bounded():
    """With max_count=3, the stream emits exactly 3 alert events + 1 end event."""
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=20&max_count=3",
        headers={"Authorization": "Bearer ls-tok"},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    records = _parse_sse(r.text)
    alert_records = [r for r in records if r.get("event") == "alert"]
    end_records = [r for r in records if r.get("event") == "end"]
    assert len(alert_records) == 3, f"expected 3 alerts; got {len(alert_records)}"
    assert len(end_records) == 1, "expected one terminal 'end' event"


def test_sse_alert_payload_is_valid_logscale_event():
    """Each `data:` line is a single-line JSON of one LogScale-shape alert."""
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=20&max_count=1",
        headers={"Authorization": "Bearer ls-tok"},
    )
    records = _parse_sse(r.text)
    alert = next(r for r in records if r.get("event") == "alert")
    payload = json.loads(alert["data"])
    # Same shape as the pull endpoint's events
    for k in (
        "@timestamp",
        "@id",
        "@rawstring",
        "#repo",
        "event.DetectName",
        "event.Severity",
        "event.TechniqueId",
        "x-mock-source",
    ):
        assert k in payload, f"missing field {k}"
    assert payload["x-mock-source"] == "siemulator"


def test_sse_events_have_monotonic_ids():
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=20&max_count=5",
        headers={"Authorization": "Bearer ls-tok"},
    )
    records = _parse_sse(r.text)
    ids = [int(r["id"]) for r in records if "id" in r]
    assert ids == list(range(len(ids))), "expected monotonic 0..N"


def test_sse_end_event_signals_completion():
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=20&max_count=2",
        headers={"Authorization": "Bearer ls-tok"},
    )
    records = _parse_sse(r.text)
    end = next(r for r in records if r.get("event") == "end")
    payload = json.loads(end["data"])
    assert payload["reason"] == "max_count_reached"
    assert payload["emitted"] == 2
    assert payload["x-mock-source"] == "siemulator"


# ── Rate clamping ────────────────────────────────────────────────


def test_sse_rate_clamps_too_high():
    """Rate above 20 Hz clamps to 20."""
    c = _client()
    t0 = time.perf_counter()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=1000&max_count=5",
        headers={"Authorization": "Bearer ls-tok"},
    )
    dur = time.perf_counter() - t0
    assert r.status_code == 200
    # 5 events at clamped 20Hz = ~250ms minimum (actually <250ms because the
    # first event fires immediately; the 4 subsequent gaps are 50ms each = 200ms).
    # Just check it doesn't fire all 5 in <10ms (which would mean rate didn't clamp).
    assert dur > 0.15, f"rate clamp not effective; duration {dur:.3f}s for 5 events"


def test_sse_rate_clamps_too_low():
    """Rate below 0.05 Hz clamps to 0.05. We use max_count=1 to avoid waiting."""
    c = _client()
    # rate=0.001 would mean 1 event every 1000s if not clamped; max_count=1
    # forces immediate exit after the first event anyway.
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=0.001&max_count=1",
        headers={"Authorization": "Bearer ls-tok"},
    )
    assert r.status_code == 200
    records = _parse_sse(r.text)
    alerts = [r for r in records if r.get("event") == "alert"]
    assert len(alerts) == 1


# ── Headers ──────────────────────────────────────────────────────


def test_sse_response_headers():
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=20&max_count=1",
        headers={"Authorization": "Bearer ls-tok"},
    )
    assert r.headers.get("content-type", "").startswith("text/event-stream")
    assert r.headers.get("cache-control") == "no-cache"
    assert r.headers.get("x-accel-buffering") == "no"  # nginx/CF buffering off
    assert r.headers.get("x-mock-source") == "siemulator"


# ── Auth channels ────────────────────────────────────────────────


def test_sse_accepts_query_param_token():
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?token=ls-tok&rate=20&max_count=1",
    )
    assert r.status_code == 200
    records = _parse_sse(r.text)
    assert any(r.get("event") == "alert" for r in records)


# ── Fault injection works on SSE ─────────────────────────────────


def test_sse_injection_status_blocks_stream():
    """?inject_status=503 → 503 with body, never opens the stream."""
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/stream?rate=20&max_count=1&inject_status=503",
        headers={"Authorization": "Bearer ls-tok"},
    )
    assert r.status_code == 503
    assert "event-stream" not in r.headers.get("content-type", "")
