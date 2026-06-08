"""Pinned regressions for failure injection."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_env_and_state():
    """Wipe inject env between tests + reset the runtime config singleton."""
    keys = (
        "SIEMULATOR_INJECT_FAULTS",
        "SIEMULATOR_INJECT_5XX_PCT",
        "SIEMULATOR_INJECT_429_PCT",
        "SIEMULATOR_INJECT_LATENCY_MS",
        "SIEMULATOR_INJECT_MALFORMED_PCT",
        "SIEMULATOR_ADMIN_KEY",
        "SIEMULATOR_LOGSCALE_TOKEN",
        "SIEMULATOR_QRADAR_TOKEN",
    )
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    from siemulator.fault_inject import reset_to_env

    reset_to_env()


def _client(admin: str = "admin-tok"):
    os.environ["SIEMULATOR_ADMIN_KEY"] = admin
    os.environ.setdefault("SIEMULATOR_LOGSCALE_TOKEN", "ls-tok")
    os.environ.setdefault("SIEMULATOR_QRADAR_TOKEN", "qr-tok")
    from siemulator.app import create_app
    from siemulator.fault_inject import reset_to_env

    reset_to_env()
    return TestClient(create_app())


# ── Per-request status injection (anyone-can-use) ────────────────


def test_per_request_status_500():
    c = _client()
    r = c.get(
        "/qradar/api/siem/offenses?inject_status=500",
        headers={"SEC": "qr-tok"},
    )
    assert r.status_code == 500
    detail = r.json()["detail"]
    assert detail["error"] == "injected fault"
    assert detail["x-injection-source"] == "per-request"


def test_per_request_status_503():
    c = _client()
    r = c.get(
        "/logscale/api/v1/repositories/detections/alerts?inject_status=503",
        headers={"Authorization": "Bearer ls-tok"},
    )
    assert r.status_code == 503


def test_per_request_status_429_includes_retry_marker():
    """Per-request 429 still works (just no auto Retry-After header)."""
    c = _client()
    r = c.get(
        "/qradar/api/siem/offenses?inject_status=429",
        headers={"SEC": "qr-tok"},
    )
    assert r.status_code == 429


def test_per_request_status_overrides_normal_response():
    """Even successful auth + valid endpoint → injection fires before handler."""
    c = _client()
    r = c.get(
        "/qradar/api/siem/offenses?inject_status=418",
        headers={"SEC": "qr-tok"},
    )
    assert r.status_code == 418


# ── Per-request latency injection ────────────────────────────────


def test_per_request_latency_adds_delay():
    import time

    c = _client()
    t0 = time.perf_counter()
    c.get(
        "/qradar/api/help?inject_latency=200",
    )
    dur_ms = (time.perf_counter() - t0) * 1000
    assert dur_ms >= 180, f"expected >=180ms, got {dur_ms:.0f}ms"


def test_per_request_latency_zero_does_nothing():
    c = _client()
    r = c.get("/qradar/api/help?inject_latency=0")
    assert r.status_code == 200


# ── Per-request malformed JSON ───────────────────────────────────


def test_per_request_malformed_truncates_body():
    c = _client()
    r = c.get(
        "/qradar/api/siem/offenses?inject_malformed=1",
        headers={"SEC": "qr-tok"},
    )
    # Status still 200, but JSON should fail to parse
    assert r.status_code == 200
    assert r.headers.get("x-injected-by") == "siemulator-fault-inject"
    with pytest.raises(json.JSONDecodeError):
        json.loads(r.text)


# ── Env-default probabilistic injection ──────────────────────────


def test_env_default_5xx_pct_100_always_fires(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_INJECT_FAULTS", "true")
    monkeypatch.setenv("SIEMULATOR_INJECT_5XX_PCT", "100")
    c = _client()
    r = c.get("/qradar/api/help")
    assert r.status_code in (500, 502, 503, 504)
    assert r.json()["detail"]["x-injection-source"] == "env-default-5xx-pct"


def test_env_default_429_pct_100_always_fires(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_INJECT_FAULTS", "true")
    monkeypatch.setenv("SIEMULATOR_INJECT_429_PCT", "100")
    c = _client()
    r = c.get("/qradar/api/help")
    assert r.status_code == 429
    assert r.headers.get("retry-after") == "5"


def test_env_default_disabled_blocks_probabilistic_faults(monkeypatch):
    """SIEMULATOR_INJECT_FAULTS=false → no probabilistic faults even at 100%."""
    monkeypatch.setenv("SIEMULATOR_INJECT_FAULTS", "false")
    monkeypatch.setenv("SIEMULATOR_INJECT_5XX_PCT", "100")
    monkeypatch.setenv("SIEMULATOR_INJECT_429_PCT", "100")
    c = _client()
    r = c.get("/qradar/api/help")
    assert r.status_code == 200, "master-switch off should block env-default faults"


def test_env_default_off_still_honors_per_request_overrides(monkeypatch):
    """Per-request overrides bypass the master switch — anyone can probe
    fault behavior on their own request."""
    monkeypatch.setenv("SIEMULATOR_INJECT_FAULTS", "false")
    c = _client()
    r = c.get("/qradar/api/help?inject_status=500")
    assert r.status_code == 500


# ── Bounds — not bound to UI / meta ──────────────────────────────


def test_per_request_inject_doesnt_affect_ui_root():
    """Fault dependency is only on /logscale/* and /qradar/* — UI never injected."""
    c = _client()
    r = c.get("/?inject_status=500")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")


def test_per_request_inject_doesnt_affect_api_info():
    c = _client()
    r = c.get("/api/info?inject_status=500")
    assert r.status_code == 200
    assert r.json()["name"] == "siemulator"


# ── Admin endpoints ──────────────────────────────────────────────


def test_admin_get_returns_config():
    c = _client()
    r = c.get("/api/faults", headers={"X-Admin-Key": "admin-tok"})
    assert r.status_code == 200
    body = r.json()
    for k in (
        "enabled",
        "inject_5xx_pct",
        "inject_429_pct",
        "inject_latency_ms",
        "inject_malformed_pct",
        "fault_count",
    ):
        assert k in body


def test_admin_get_403_without_key():
    c = _client()
    r = c.get("/api/faults")
    assert r.status_code == 403


def test_admin_get_403_with_no_admin_key_configured(monkeypatch):
    monkeypatch.delenv("SIEMULATOR_ADMIN_KEY", raising=False)
    from siemulator.app import create_app

    c = TestClient(create_app())
    r = c.get("/api/faults", headers={"X-Admin-Key": "anything"})
    assert r.status_code == 403


def test_admin_put_updates_config():
    c = _client()
    r = c.put(
        "/api/faults",
        json={"enabled": True, "inject_5xx_pct": 50, "inject_latency_ms": 100},
        headers={"X-Admin-Key": "admin-tok"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["inject_5xx_pct"] == 50
    assert body["inject_latency_ms"] == 100


def test_admin_put_applies_immediately():
    c = _client()
    c.put(
        "/api/faults",
        json={"enabled": True, "inject_5xx_pct": 100},
        headers={"X-Admin-Key": "admin-tok"},
    )
    r = c.get("/qradar/api/help")
    assert r.status_code in (500, 502, 503, 504)


def test_admin_put_ignores_unknown_keys():
    c = _client()
    r = c.put(
        "/api/faults",
        json={"enabled": True, "nuke_everything": True},
        headers={"X-Admin-Key": "admin-tok"},
    )
    assert r.status_code == 200
    assert "nuke_everything" not in r.json()


def test_admin_put_invalid_json_400():
    c = _client()
    r = c.put(
        "/api/faults",
        content="not json at all",
        headers={"X-Admin-Key": "admin-tok", "content-type": "application/json"},
    )
    assert r.status_code == 400


def test_admin_reset_drops_overrides(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_INJECT_FAULTS", "true")
    monkeypatch.setenv("SIEMULATOR_INJECT_5XX_PCT", "10")
    c = _client()
    # Live-update to 90%
    c.put(
        "/api/faults",
        json={"inject_5xx_pct": 90},
        headers={"X-Admin-Key": "admin-tok"},
    )
    assert c.get("/api/faults", headers={"X-Admin-Key": "admin-tok"}).json()[
        "inject_5xx_pct"
    ] == 90
    # Reset → back to env (10%)
    c.post("/api/faults/reset", headers={"X-Admin-Key": "admin-tok"})
    assert c.get("/api/faults", headers={"X-Admin-Key": "admin-tok"}).json()[
        "inject_5xx_pct"
    ] == 10


# ── Fault counter ────────────────────────────────────────────────


def test_fault_counter_increments():
    c = _client()
    c.get("/qradar/api/help?inject_status=500")
    c.get("/qradar/api/help?inject_status=500")
    c.get("/qradar/api/help?inject_status=429")
    cfg = c.get("/api/faults", headers={"X-Admin-Key": "admin-tok"}).json()
    assert cfg["fault_count"]["5xx"] >= 2
    assert cfg["fault_count"]["429"] >= 1


# ── Tokens still never leak ──────────────────────────────────────


def test_injection_response_doesnt_leak_token():
    c = _client()
    r = c.get(
        "/qradar/api/siem/offenses?inject_status=500&token=qr-tok",
        headers={"SEC": "qr-tok"},
    )
    assert "qr-tok" not in r.text
