"""Pinned regressions for the Splunk mock surface."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate_env():
    keys = (
        "SIEMULATOR_SPLUNK_TOKEN",
        "SIEMULATOR_SPLUNK_PREFIX",
        "SIEMULATOR_LOGSCALE_TOKEN",
        "SIEMULATOR_QRADAR_TOKEN",
    )
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _client(token: str = "splunk-tok") -> TestClient:
    os.environ["SIEMULATOR_SPLUNK_TOKEN"] = token
    # Explicit set (not setdefault) — sibling test files may have set
    # conflicting values; we need known fixtures every time so the cross-
    # token assertions test what they think they're testing.
    os.environ["SIEMULATOR_LOGSCALE_TOKEN"] = "ls-tok"
    os.environ["SIEMULATOR_QRADAR_TOKEN"] = "qr-tok"
    from siemulator.app import create_app

    return TestClient(create_app())


# ── Health (no auth) ─────────────────────────────────────────────


def test_server_info_no_auth():
    c = _client()
    r = c.get("/splunk/services/server/info")
    assert r.status_code == 200
    body = r.json()
    assert body["mock"] is True
    assert body["x-mock-source"] == "siemulator"
    entry = body["entry"][0]
    assert entry["content"]["version"]


# ── Auth — three channels ─────────────────────────────────────────


def test_search_requires_auth():
    c = _client()
    r = c.post("/splunk/services/search/jobs", data={"search": "search index=main"})
    assert r.status_code == 401
    body = r.json()
    assert body["detail"]["messages"][0]["code"] == "Unauthorized"


def test_splunk_session_auth():
    """Authorization: Splunk <session-key> — Splunk's canonical header."""
    c = _client(token="splunk-session-key")
    r = c.post(
        "/splunk/services/search/jobs",
        data={"search": "search index=main"},
        headers={"Authorization": "Splunk splunk-session-key"},
    )
    assert r.status_code == 200
    assert "sid" in r.json()


def test_splunk_bearer_auth():
    """Authorization: Bearer <token> — newer Splunk token-based auth."""
    c = _client(token="splunk-tok")
    r = c.post(
        "/splunk/services/search/jobs",
        data={"search": "search index=main"},
        headers={"Authorization": "Bearer splunk-tok"},
    )
    assert r.status_code == 200


def test_query_param_auth_works():
    c = _client(token="splunk-tok")
    r = c.post(
        "/splunk/services/search/jobs?token=splunk-tok",
        data={"search": "search index=main"},
    )
    assert r.status_code == 200


def test_cross_token_logscale_works_on_splunk():
    """Cross-acceptance — LogScale token works on Splunk surface."""
    c = _client(token="splunk-tok")
    r = c.post(
        "/splunk/services/search/jobs",
        data={"search": "*"},
        headers={"Authorization": "Bearer ls-tok"},
    )
    assert r.status_code == 200


def test_cross_token_qradar_works_on_splunk():
    c = _client(token="splunk-tok")
    r = c.post(
        "/splunk/services/search/jobs",
        data={"search": "*"},
        headers={"Authorization": "Splunk qr-tok"},
    )
    assert r.status_code == 200


# ── Async search lifecycle ───────────────────────────────────────


def test_search_lifecycle_submit_status_results():
    c = _client()
    h = {"Authorization": "Bearer splunk-tok"}
    submit = c.post(
        "/splunk/services/search/jobs",
        data={"search": "search index=main DetectName=*", "count": 3},
        headers=h,
    )
    assert submit.status_code == 200
    sid = submit.json()["sid"]

    status_r = c.get(f"/splunk/services/search/jobs/{sid}", headers=h)
    assert status_r.status_code == 200
    content = status_r.json()["entry"][0]["content"]
    assert content["dispatchState"] == "DONE"
    assert content["isDone"] is True
    assert content["eventCount"] == 3

    results_r = c.get(f"/splunk/services/search/jobs/{sid}/results", headers=h)
    assert results_r.status_code == 200
    body = results_r.json()
    assert len(body["results"]) == 3
    assert body["preview"] is False


def test_unknown_sid_404():
    c = _client()
    r = c.get(
        "/splunk/services/search/jobs/does-not-exist",
        headers={"Authorization": "Bearer splunk-tok"},
    )
    assert r.status_code == 404
    assert r.json()["detail"]["messages"][0]["code"] == "NotFound"


def test_results_for_unknown_sid_404():
    c = _client()
    r = c.get(
        "/splunk/services/search/jobs/does-not-exist/results",
        headers={"Authorization": "Bearer splunk-tok"},
    )
    assert r.status_code == 404


# ── Event shape pins ─────────────────────────────────────────────


def test_event_has_splunk_canonical_fields():
    """_time must be float epoch SECONDS (not ms), plus host/source/sourcetype."""
    c = _client()
    h = {"Authorization": "Bearer splunk-tok"}
    submit = c.post(
        "/splunk/services/search/jobs",
        data={"search": "*", "count": 1},
        headers=h,
    )
    sid = submit.json()["sid"]
    results = c.get(f"/splunk/services/search/jobs/{sid}/results", headers=h).json()
    event = results["results"][0]
    # Splunk canonical fields
    for k in ("_time", "_raw", "_indextime", "host", "source", "sourcetype", "index"):
        assert k in event, f"missing canonical Splunk field {k}"
    # _time is float SECONDS (10 digits as int, 13 would be ms)
    assert isinstance(event["_time"], (int, float))
    assert event["_time"] < 1e12, f"_time {event['_time']} looks like ms, not seconds"
    # _raw is a non-empty string
    assert isinstance(event["_raw"], str)
    assert len(event["_raw"]) > 20
    # Detection fields preserved
    for k in ("DetectName", "Severity", "TechniqueId"):
        assert k in event


def test_count_param_clamps():
    c = _client()
    h = {"Authorization": "Bearer splunk-tok"}
    submit = c.post(
        "/splunk/services/search/jobs",
        data={"search": "*", "count": 999},
        headers=h,
    )
    sid = submit.json()["sid"]
    results = c.get(f"/splunk/services/search/jobs/{sid}/results", headers=h).json()
    assert len(results["results"]) == 50  # clamped


def test_invalid_count_falls_back_to_default():
    c = _client()
    h = {"Authorization": "Bearer splunk-tok"}
    submit = c.post(
        "/splunk/services/search/jobs",
        data={"search": "*", "count": "not-a-number"},
        headers=h,
    )
    assert submit.status_code == 200


# ── Oneshot export ───────────────────────────────────────────────


def test_export_oneshot_search():
    """Synchronous oneshot — modern clients prefer this over the async dance."""
    c = _client()
    r = c.get(
        "/splunk/services/search/jobs/export?search=*&count=5",
        headers={"Authorization": "Bearer splunk-tok"},
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["results"]) == 5
    assert body["x-mock-source"] == "siemulator"


def test_export_requires_auth():
    c = _client()
    r = c.get("/splunk/services/search/jobs/export?search=*")
    assert r.status_code == 401


# ── Mock-source markers ──────────────────────────────────────────


def test_all_events_carry_mock_source():
    c = _client()
    h = {"Authorization": "Bearer splunk-tok"}
    submit = c.post(
        "/splunk/services/search/jobs",
        data={"search": "*", "count": 10},
        headers=h,
    )
    sid = submit.json()["sid"]
    events = c.get(f"/splunk/services/search/jobs/{sid}/results", headers=h).json()
    for event in events["results"]:
        assert event["x-mock-source"] == "siemulator"


def test_response_carries_x_mock_source_header():
    c = _client()
    r = c.get("/splunk/services/server/info")
    assert r.headers.get("X-Mock-Source") == "siemulator"


# ── Templates vary across requests ───────────────────────────────


def test_templates_provide_variety():
    c = _client()
    h = {"Authorization": "Bearer splunk-tok"}
    submit = c.post(
        "/splunk/services/search/jobs",
        data={"search": "*", "count": 20},
        headers=h,
    )
    sid = submit.json()["sid"]
    events = c.get(f"/splunk/services/search/jobs/{sid}/results", headers=h).json()
    names = {e["DetectName"] for e in events["results"]}
    assert len(names) >= 3, f"expected variety; only saw {names}"


# ── Fault injection works on Splunk too ──────────────────────────


def test_per_request_inject_works_on_splunk():
    c = _client()
    r = c.get(
        "/splunk/services/server/info?inject_status=503",
    )
    assert r.status_code == 503


# ── Access log captures Splunk ───────────────────────────────────


def test_access_log_captures_splunk_requests():
    os.environ["SIEMULATOR_ADMIN_KEY"] = "ak"
    c = _client()
    c.get(
        "/splunk/services/server/info",
    )
    c.post(
        "/splunk/services/search/jobs",
        data={"search": "*"},
        headers={"Authorization": "Bearer splunk-tok"},
    )
    log = c.get("/api/access-log", headers={"X-Admin-Key": "ak"}).json()
    paths = [e["path"] for e in log["entries"]]
    assert "/splunk/services/server/info" in paths
    assert "/splunk/services/search/jobs" in paths
