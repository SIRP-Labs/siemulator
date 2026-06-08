"""Pinned regressions for record / replay / diff sessions."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path):
    """Wipe sessions state between tests; use tmp dir for disk persistence."""
    keys = (
        "SIEMULATOR_ADMIN_KEY",
        "SIEMULATOR_SESSIONS_ENABLED",
        "SIEMULATOR_SESSIONS_DIR",
        "SIEMULATOR_LOGSCALE_TOKEN",
        "SIEMULATOR_QRADAR_TOKEN",
        "SIEMULATOR_SPLUNK_TOKEN",
    )
    saved = {k: os.environ.get(k) for k in keys}
    os.environ["SIEMULATOR_SESSIONS_DIR"] = str(tmp_path)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    from siemulator.sessions import _wipe_all

    _wipe_all()


def _client(admin: str = "admin-tok"):
    os.environ["SIEMULATOR_ADMIN_KEY"] = admin
    os.environ["SIEMULATOR_LOGSCALE_TOKEN"] = "ls-tok"
    os.environ["SIEMULATOR_QRADAR_TOKEN"] = "qr-tok"
    os.environ["SIEMULATOR_SPLUNK_TOKEN"] = "sp-tok"
    from siemulator.app import create_app
    from siemulator.sessions import _wipe_all

    _wipe_all()
    return TestClient(create_app())


# ── Recording lifecycle ──────────────────────────────────────────


def test_start_creates_session():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    r = c.post("/api/sessions/sess-1/start", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "sess-1"
    assert body["started_at"]
    assert body["stopped_at"] is None


def test_recording_captures_requests():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/cap-test/start", headers=h)
    # Make some API calls
    c.get("/qradar/api/help")
    c.get("/qradar/api/siem/offenses", headers={"SEC": "qr-tok"})
    c.get(
        "/logscale/api/v1/repositories/detections/alerts",
        headers={"Authorization": "Bearer ls-tok"},
    )
    c.post("/api/sessions/cap-test/stop", headers=h)
    info = c.get("/api/sessions/cap-test", headers=h).json()
    assert info["entry_count"] == 3
    assert info["by_path"]["/qradar/api/help"] == 1
    assert info["by_status"]["200"] == 3


def test_meta_endpoints_not_recorded():
    """Recording only captures bound surfaces — UI/docs/api/* skip it."""
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/meta-test/start", headers=h)
    c.get("/")  # UI
    c.get("/api/info")
    c.get("/docs")
    c.get("/api/sessions", headers=h)
    # One bound call
    c.get("/qradar/api/help")
    c.post("/api/sessions/meta-test/stop", headers=h)
    info = c.get("/api/sessions/meta-test", headers=h).json()
    assert info["entry_count"] == 1
    assert "/qradar/api/help" in info["by_path"]


def test_starting_new_session_auto_stops_prior():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/first/start", headers=h)
    c.get("/qradar/api/help")
    c.post("/api/sessions/second/start", headers=h)
    c.get("/qradar/api/help")
    # `first` should be stopped; `second` recording
    first = c.get("/api/sessions/first", headers=h).json()
    second = c.get("/api/sessions/second", headers=h).json()
    assert first["recording"] is False
    assert second["recording"] is True
    assert first["entry_count"] == 1
    assert second["entry_count"] == 1


def test_token_redacted_in_captured_headers():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/redact-test/start", headers=h)
    c.get(
        "/logscale/api/v1/repositories/detections/alerts",
        headers={"Authorization": "Bearer ls-tok-SECRET"},
    )
    c.post("/api/sessions/redact-test/stop", headers=h)
    entries = c.get(
        "/api/sessions/redact-test/entries", headers=h
    ).json()["entries"]
    assert len(entries) == 1
    captured_auth = entries[0]["request"]["headers"].get(
        "authorization"
    ) or entries[0]["request"]["headers"].get("Authorization")
    assert captured_auth == "***", "auth header value must be redacted"
    # And the literal secret never appears anywhere in the entry payload
    payload = json.dumps(entries[0])
    assert "ls-tok-SECRET" not in payload


def test_stop_persists_to_disk(tmp_path):
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/disk-test/start", headers=h)
    c.get("/qradar/api/help")
    c.post("/api/sessions/disk-test/stop", headers=h)
    expected_file = tmp_path / "disk-test.jsonl"
    assert expected_file.exists(), "session should be persisted as JSONL"
    lines = expected_file.read_text().strip().split("\n")
    assert len(lines) == 2  # 1 meta + 1 entry
    meta = json.loads(lines[0])
    assert meta["_meta"]["name"] == "disk-test"
    entry = json.loads(lines[1])
    assert entry["request"]["path"] == "/qradar/api/help"


def test_load_from_disk_when_not_in_memory(tmp_path):
    """After process restart, get_session falls back to disk."""
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/persist-test/start", headers=h)
    c.get("/qradar/api/help")
    c.post("/api/sessions/persist-test/stop", headers=h)
    # Wipe in-memory state, simulating restart
    from siemulator.sessions import _wipe_all

    _wipe_all()
    # GET should re-load from disk
    info = c.get("/api/sessions/persist-test", headers=h)
    assert info.status_code == 200
    assert info.json()["entry_count"] == 1


def test_delete_removes_memory_and_disk(tmp_path):
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/del-test/start", headers=h)
    c.get("/qradar/api/help")
    c.post("/api/sessions/del-test/stop", headers=h)
    assert (tmp_path / "del-test.jsonl").exists()
    r = c.delete("/api/sessions/del-test", headers=h)
    assert r.status_code == 200
    assert not (tmp_path / "del-test.jsonl").exists()
    miss = c.get("/api/sessions/del-test", headers=h)
    assert miss.status_code == 404


# ── Validation ───────────────────────────────────────────────────


def test_invalid_session_name_400():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    r = c.post("/api/sessions/bad name with spaces/start", headers=h)
    # 404 because the route matches `{name}` with the literal "bad name..."
    # — fastapi treats slash-free fragments as the name. Spaces fail validation.
    # Either 400 (validation) or 404 (route miss) is acceptable rejection.
    assert r.status_code in (400, 404, 422)


def test_admin_endpoints_require_key():
    c = _client()
    assert c.get("/api/sessions").status_code == 403
    assert c.post("/api/sessions/x/start").status_code == 403


# ── Diff ─────────────────────────────────────────────────────────


def test_diff_identical_sessions():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    for name in ("dif-a", "dif-b"):
        c.post(f"/api/sessions/{name}/start", headers=h)
        c.get("/qradar/api/help")
        c.get("/qradar/api/help")
        c.post(f"/api/sessions/{name}/stop", headers=h)
    diff = c.get(
        "/api/sessions/diff?a=dif-a&b=dif-b", headers=h
    ).json()
    # Identical request shapes; bodies differ (timestamps) but the diff
    # surfaces that as body_lines_delta / body_bytes_delta entries, not
    # as request-stream changes. We assert no method/path/status changes:
    for d in diff["diffs"]:
        assert "method" not in d
        assert "path" not in d
        assert "status" not in d


def test_diff_extra_request_in_b():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/short/start", headers=h)
    c.get("/qradar/api/help")
    c.post("/api/sessions/short/stop", headers=h)

    c.post("/api/sessions/long/start", headers=h)
    c.get("/qradar/api/help")
    c.get(
        "/qradar/api/siem/offenses", headers={"SEC": "qr-tok"}
    )  # extra request
    c.post("/api/sessions/long/stop", headers=h)

    diff = c.get(
        "/api/sessions/diff?a=short&b=long", headers=h
    ).json()
    assert diff["a_entry_count"] == 1
    assert diff["b_entry_count"] == 2
    assert not diff["identical"]
    extra = [d for d in diff["diffs"] if d["kind"] == "extra_in_b"]
    assert len(extra) == 1
    assert extra[0]["b"]["path"] == "/qradar/api/siem/offenses"


def test_diff_path_change_detected():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/v1/start", headers=h)
    c.get("/qradar/api/help")
    c.post("/api/sessions/v1/stop", headers=h)

    c.post("/api/sessions/v2/start", headers=h)
    c.get(
        "/qradar/api/siem/offenses", headers={"SEC": "qr-tok"}
    )  # different path
    c.post("/api/sessions/v2/stop", headers=h)

    diff = c.get("/api/sessions/diff?a=v1&b=v2", headers=h).json()
    assert not diff["identical"]
    changed = [d for d in diff["diffs"] if d.get("kind") == "changed"]
    assert len(changed) == 1
    assert changed[0]["path"]["a"] == "/qradar/api/help"
    assert changed[0]["path"]["b"] == "/qradar/api/siem/offenses"


def test_diff_status_change_detected():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/ok-run/start", headers=h)
    c.get(
        "/qradar/api/siem/offenses", headers={"SEC": "qr-tok"}
    )  # 200
    c.post("/api/sessions/ok-run/stop", headers=h)

    c.post("/api/sessions/fail-run/start", headers=h)
    c.get("/qradar/api/siem/offenses")  # 401 — no auth
    c.post("/api/sessions/fail-run/stop", headers=h)

    diff = c.get(
        "/api/sessions/diff?a=ok-run&b=fail-run", headers=h
    ).json()
    changed = [d for d in diff["diffs"] if d.get("kind") == "changed"]
    assert len(changed) == 1
    assert changed[0]["status"]["a"] == 200
    assert changed[0]["status"]["b"] == 401


# ── Replay ───────────────────────────────────────────────────────


def test_replay_returns_captured_response():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/replay-test/start", headers=h)
    # Capture a known response
    original = c.get(
        "/qradar/api/siem/offenses?scenarios=replay&token=qr-tok",
    )
    original_body = original.json()
    c.post("/api/sessions/replay-test/stop", headers=h)

    # Now ask siemulator to replay it — should return THE SAME bytes
    # even though the live endpoint would generate fresh data.
    replayed = c.get(
        "/qradar/api/siem/offenses?scenarios=replay&token=qr-tok&replay_from=replay-test",
    )
    assert replayed.status_code == 200
    assert replayed.headers.get("X-Replay-Match") == "hit"
    assert replayed.headers.get("X-Replay-From") == "replay-test"
    # Same body, byte-for-byte (would otherwise differ due to fresh
    # random IDs on every generated response)
    assert replayed.json() == original_body


def test_replay_miss_returns_404_with_diagnostic():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/empty-rep/start", headers=h)
    c.post("/api/sessions/empty-rep/stop", headers=h)
    r = c.get(
        "/qradar/api/help?replay_from=empty-rep",
    )
    assert r.status_code == 404
    assert r.headers.get("X-Replay-Match") == "miss"
    body = r.json()
    assert body["session"] == "empty-rep"
    assert body["fingerprint"].startswith("GET /qradar/api/help")


def test_replay_strips_meta_params_from_match():
    """?replay_from / ?inject_status / ?token are stripped from the
    fingerprint so a request adding them still matches a recorded
    request that didn't have them."""
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/meta-strip/start", headers=h)
    c.get("/qradar/api/help")  # recorded without any meta params
    c.post("/api/sessions/meta-strip/stop", headers=h)

    # Replay request adds replay_from + token — both should be stripped
    # before the fingerprint match
    r = c.get(
        "/qradar/api/help?replay_from=meta-strip&token=anything",
    )
    assert r.status_code == 200
    assert r.headers.get("X-Replay-Match") == "hit"


# ── Token redaction in replayed responses ─────────────────────────


def test_replay_response_preserves_x_mock_source():
    c = _client()
    h = {"X-Admin-Key": "admin-tok"}
    c.post("/api/sessions/header-test/start", headers=h)
    c.get("/qradar/api/help")
    c.post("/api/sessions/header-test/stop", headers=h)
    r = c.get("/qradar/api/help?replay_from=header-test")
    assert r.headers.get("X-Mock-Source") == "siemulator"
