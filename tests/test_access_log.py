"""Pinned regressions for the access log middleware + admin endpoints."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate_env():
    """Stop access-log env from leaking between tests."""
    keys = (
        "SIEMULATOR_ACCESS_LOG_ENABLED",
        "SIEMULATOR_ACCESS_LOG_SIZE",
        "SIEMULATOR_ACCESS_LOG_SKIP_HEALTH",
        "SIEMULATOR_ADMIN_KEY",
    )
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    # Clear the in-memory ring between tests so counts are deterministic.
    try:
        from siemulator.access_log import clear

        clear()
    except Exception:
        pass


def _client(admin: str = "admin-tok"):
    os.environ["SIEMULATOR_ADMIN_KEY"] = admin
    os.environ.setdefault("SIEMULATOR_LOGSCALE_TOKEN", "ls-tok")
    os.environ.setdefault("SIEMULATOR_QRADAR_TOKEN", "qr-tok")
    from siemulator.app import create_app

    return TestClient(create_app())


# ── Recording behaviour ───────────────────────────────────────────


def test_logscale_request_recorded():
    c = _client()
    c.get("/logscale/api/v1/status")
    # Force an extra hit so we have something even if status is excluded
    r = c.get(
        "/logscale/api/v1/repositories/detections/alerts?limit=1",
        headers={"Authorization": "Bearer ls-tok"},
    )
    assert r.status_code == 200
    log = c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"})
    assert log.status_code == 200
    entries = log.json()["entries"]
    paths = [e["path"] for e in entries]
    assert "/logscale/api/v1/repositories/detections/alerts" in paths


def test_qradar_request_recorded():
    c = _client()
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    entries = (
        c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"})
        .json()["entries"]
    )
    assert any(e["path"] == "/qradar/api/siem/offenses" for e in entries)


def test_ui_root_not_recorded():
    """The UI / and meta endpoints aren't bound surfaces — keep them out
    of the access log so /api/access-log stays focused on real API traffic."""
    c = _client()
    c.get("/")
    c.get("/api/info")
    c.get("/docs")
    entries = (
        c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"})
        .json()["entries"]
    )
    paths = [e["path"] for e in entries]
    assert "/" not in paths
    assert "/api/info" not in paths
    assert "/docs" not in paths


# ── Token redaction (security pin) ────────────────────────────────


def test_token_query_param_redacted():
    """?token=… must appear as *** in the recorded query — never the value."""
    c = _client()
    c.get("/qradar/api/siem/offenses?token=qr-tok&scenarios=replay")
    entries = (
        c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"})
        .json()["entries"]
    )
    qr_entry = next(e for e in entries if e["path"] == "/qradar/api/siem/offenses")
    assert qr_entry["query"]["token"] == "***"
    assert qr_entry["query"]["scenarios"] == "replay"  # non-sensitive kept
    assert qr_entry["auth"] == "query"


def test_bearer_token_value_not_logged_anywhere():
    """The literal token value must NEVER appear in the access log payload."""
    c = _client()
    c.get(
        "/logscale/api/v1/repositories/detections/alerts?limit=1",
        headers={"Authorization": "Bearer ls-tok-SUPERSECRET"},
    )
    payload = c.get(
        "/api/access-log", headers={"X-Admin-Key": "admin-tok"}
    ).text
    assert "ls-tok-SUPERSECRET" not in payload
    entries = (
        c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"})
        .json()["entries"]
    )
    ls_entry = next(
        e for e in entries
        if e["path"] == "/logscale/api/v1/repositories/detections/alerts"
    )
    assert ls_entry["auth"] == "bearer"


def test_sec_header_value_not_logged():
    c = _client()
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok-SECRET2"})
    payload = c.get(
        "/api/access-log", headers={"X-Admin-Key": "admin-tok"}
    ).text
    assert "qr-tok-SECRET2" not in payload


def test_admin_key_header_value_not_logged():
    """Even the admin key itself must not echo through the log."""
    c = _client()
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    # /api/access-log itself isn't a bound surface — admin key never lands
    # in any access-log ENTRY because the middleware doesn't record meta.
    entries = (
        c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"})
        .json()["entries"]
    )
    for e in entries:
        assert not e["path"].startswith("/api/access-log")


# ── Auth channel detection ────────────────────────────────────────


def test_auth_channel_bearer_detected():
    c = _client()
    c.get(
        "/logscale/api/v1/repositories/detections/alerts?limit=1",
        headers={"Authorization": "Bearer ls-tok"},
    )
    e = c.get(
        "/api/access-log", headers={"X-Admin-Key": "admin-tok"}
    ).json()["entries"][0]
    assert e["auth"] == "bearer"


def test_auth_channel_sec_detected():
    c = _client()
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    e = c.get(
        "/api/access-log", headers={"X-Admin-Key": "admin-tok"}
    ).json()["entries"][0]
    assert e["auth"] == "sec"


def test_auth_channel_query_detected():
    c = _client()
    c.get("/qradar/api/siem/offenses?token=qr-tok")
    e = c.get(
        "/api/access-log", headers={"X-Admin-Key": "admin-tok"}
    ).json()["entries"][0]
    assert e["auth"] == "query"


def test_auth_channel_none_for_unauth_request():
    c = _client()
    # 401 — no auth at all
    c.get("/logscale/api/v1/repositories/detections/alerts")
    e = c.get(
        "/api/access-log", headers={"X-Admin-Key": "admin-tok"}
    ).json()["entries"][0]
    assert e["auth"] == "none"
    assert e["status"] == 401


# ── Admin gating ──────────────────────────────────────────────────


def test_admin_endpoint_403_without_key(monkeypatch):
    """No SIEMULATOR_ADMIN_KEY set → endpoints return 403 universally."""
    monkeypatch.delenv("SIEMULATOR_ADMIN_KEY", raising=False)
    from siemulator.app import create_app

    c = TestClient(create_app())
    assert c.get("/api/access-log").status_code == 403
    assert c.get("/api/access-log/stats").status_code == 403


def test_admin_endpoint_403_with_wrong_key():
    c = _client(admin="right-key")
    r = c.get("/api/access-log", headers={"X-Admin-Key": "wrong"})
    assert r.status_code == 403


# ── Stats aggregation ─────────────────────────────────────────────


def test_stats_aggregations():
    c = _client()
    c.get("/qradar/api/help")
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    c.get("/qradar/api/siem/offenses?token=qr-tok&scenarios=replay")
    c.get("/logscale/api/v1/status")
    stats = c.get(
        "/api/access-log/stats", headers={"X-Admin-Key": "admin-tok"}
    ).json()
    assert stats["total"] >= 4
    assert "by_status" in stats
    assert "by_auth" in stats
    assert "top_paths" in stats
    assert "duration_ms" in stats
    # Auth distribution shows both sec + query for the QRadar pings
    assert stats["by_auth"].get("sec", 0) >= 1
    assert stats["by_auth"].get("query", 0) >= 1
    assert stats["by_auth"].get("none", 0) >= 2


# ── Filters ───────────────────────────────────────────────────────


def test_filter_by_path_prefix():
    c = _client()
    c.get("/qradar/api/help")
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    c.get("/logscale/api/v1/status")
    r = c.get(
        "/api/access-log?path_prefix=/qradar",
        headers={"X-Admin-Key": "admin-tok"},
    )
    paths = [e["path"] for e in r.json()["entries"]]
    assert all(p.startswith("/qradar") for p in paths)
    assert paths  # not empty


def test_filter_by_status():
    c = _client()
    c.get("/qradar/api/siem/offenses")  # 401
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})  # 200
    r = c.get(
        "/api/access-log?status=401",
        headers={"X-Admin-Key": "admin-tok"},
    )
    statuses = [e["status"] for e in r.json()["entries"]]
    assert statuses
    assert all(s == 401 for s in statuses)


def test_filter_by_auth():
    c = _client()
    c.get("/qradar/api/siem/offenses?token=qr-tok")
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    r = c.get(
        "/api/access-log?auth=query",
        headers={"X-Admin-Key": "admin-tok"},
    )
    auths = [e["auth"] for e in r.json()["entries"]]
    assert auths and all(a == "query" for a in auths)


def test_limit_param_clamps():
    c = _client()
    for _ in range(10):
        c.get("/qradar/api/help")
    r = c.get(
        "/api/access-log?limit=3", headers={"X-Admin-Key": "admin-tok"}
    )
    assert len(r.json()["entries"]) == 3


# ── Disable / health-skip switches ────────────────────────────────


def test_disabled_completely(monkeypatch):
    """SIEMULATOR_ACCESS_LOG_ENABLED=false → no middleware AND no admin endpoints."""
    monkeypatch.setenv("SIEMULATOR_ACCESS_LOG_ENABLED", "false")
    monkeypatch.setenv("SIEMULATOR_ADMIN_KEY", "ak")
    from siemulator.app import create_app

    c = TestClient(create_app())
    # The API itself still works
    assert c.get("/qradar/api/help").status_code == 200
    # But the access-log endpoints don't exist (404)
    r = c.get("/api/access-log", headers={"X-Admin-Key": "ak"})
    assert r.status_code == 404


def test_skip_health_excludes_status_endpoints(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_ACCESS_LOG_SKIP_HEALTH", "true")
    monkeypatch.setenv("SIEMULATOR_ADMIN_KEY", "ak")
    monkeypatch.setenv("SIEMULATOR_LOGSCALE_TOKEN", "ls-tok")
    monkeypatch.setenv("SIEMULATOR_QRADAR_TOKEN", "qr-tok")
    from siemulator.access_log import clear
    from siemulator.app import create_app

    clear()
    c = TestClient(create_app())
    c.get("/logscale/api/v1/status")
    c.get("/qradar/api/help")
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})  # non-health
    entries = c.get("/api/access-log", headers={"X-Admin-Key": "ak"}).json()["entries"]
    paths = [e["path"] for e in entries]
    # Health paths skipped
    assert "/logscale/api/v1/status" not in paths
    assert "/qradar/api/help" not in paths
    # Real-API call still recorded
    assert "/qradar/api/siem/offenses" in paths


# ── Stdout JSON emission ──────────────────────────────────────────


def test_stdout_emits_structured_json(caplog):
    """siemulator.access logger emits one JSON line per request — drives
    platform-level log aggregation (DO Apps, Docker logs, etc.)."""
    import logging

    caplog.set_level(logging.INFO, logger="siemulator.access")
    c = _client()
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    records = [r for r in caplog.records if r.name == "siemulator.access"]
    assert records, "expected siemulator.access logger to emit at least one record"
    import json as _json

    # Each record is a JSON line we can round-trip
    parsed = _json.loads(records[-1].message)
    assert parsed["path"] == "/qradar/api/siem/offenses"
    assert parsed["auth"] == "sec"
    assert "qr-tok" not in records[-1].message  # token never in the log line


# ── X-Forwarded-For handling ──────────────────────────────────────


def test_x_forwarded_for_takes_leftmost():
    """Behind DO Apps, X-Forwarded-For: <real-client>, <do-edge> — we
    record the real client, not the edge."""
    c = _client()
    c.get(
        "/qradar/api/siem/offenses",
        headers={"SEC": "qr-tok", "X-Forwarded-For": "203.0.113.45, 10.0.0.1"},
    )
    e = c.get(
        "/api/access-log", headers={"X-Admin-Key": "admin-tok"}
    ).json()["entries"][0]
    assert e["client_ip"] == "203.0.113.45"


# ── Clear endpoint ────────────────────────────────────────────────


def test_clear_endpoint_wipes_ring():
    c = _client()
    c.get("/qradar/api/help")
    c.get("/qradar/api/help")
    before = c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"}).json()
    assert before["current_count"] >= 2
    r = c.post("/api/access-log/clear", headers={"X-Admin-Key": "admin-tok"})
    assert r.status_code == 200
    assert r.json()["cleared"] >= 2
    after = c.get("/api/access-log", headers={"X-Admin-Key": "admin-tok"}).json()
    # The clear() itself doesn't get logged (admin endpoints aren't bound).
    # Only the new GET that follows lands. So count should be 0 or 1 max.
    assert after["current_count"] <= 1
