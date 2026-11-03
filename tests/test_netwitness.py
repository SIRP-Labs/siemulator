"""Pinned regression tests for the NetWitness mock surface.

Shape contracts mirror what act 1454
(apps/RSA-NetWitness/ingest_alerts_from_incidents.py) and
tests/test_netwitness_ingest_alerts_from_incidents.py (FakeNetWitness)
expect from NetWitness 12.5.
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import siemulator.netwitness as nw_mod

TOKEN = "nw-test-tok"
ADMIN_KEY = "nw-admin-key"
NW_HDR = {"NetWitness-Token": TOKEN}
BEARER = {"Authorization": f"Bearer {TOKEN}"}
SEC = {"SEC": TOKEN}


@pytest.fixture(autouse=True)
def reset_state():
    """Reset auth mode and token store between tests."""
    nw_mod._AUTH_MODE[0] = "normal"
    nw_mod._TOKENS.clear()
    yield
    nw_mod._AUTH_MODE[0] = "normal"
    nw_mod._TOKENS.clear()


@pytest.fixture
def client():
    os.environ["SIEMULATOR_NETWITNESS_TOKEN"] = TOKEN
    os.environ["SIEMULATOR_NETWITNESS_PREFIX"] = "/nw"
    os.environ["SIEMULATOR_ADMIN_KEY"] = ADMIN_KEY
    app = FastAPI()
    app.include_router(nw_mod.build_router())
    return TestClient(app)


# ── Auth — normal flow ────────────────────────────────────────────────────────

def test_auth_returns_access_token(client):
    r = client.post("/nw/rest/api/auth/userpass", data={"username": "admin", "password": "pass"})
    assert r.status_code == 200
    body = r.json()
    assert "accessToken" in body
    assert len(body["accessToken"]) == 64   # secrets.token_hex(32)
    assert body["x-mock-source"] == "siemulator"


def test_issued_token_accepted_on_incidents(client):
    auth = client.post("/nw/rest/api/auth/userpass", data={"username": "u", "password": "p"})
    token = auth.json()["accessToken"]
    r = client.get("/nw/rest/api/incidents", headers={"NetWitness-Token": token})
    assert r.status_code == 200


def test_auth_no_body_still_returns_token(client):
    """Form fields optional — some callers POST with empty body."""
    r = client.post("/nw/rest/api/auth/userpass")
    assert r.status_code == 200
    assert "accessToken" in r.json()


# ── Auth — fault modes ────────────────────────────────────────────────────────

def test_auth_mode_locked_returns_500(client):
    nw_mod._AUTH_MODE[0] = "locked"
    r = client.post("/nw/rest/api/auth/userpass", data={"username": "u", "password": "p"})
    assert r.status_code == 500
    assert "User account is locked" in r.json()["detail"]["message"]


def test_auth_mode_bad_credentials_returns_401(client):
    nw_mod._AUTH_MODE[0] = "bad_credentials"
    r = client.post("/nw/rest/api/auth/userpass", data={"username": "u", "password": "p"})
    assert r.status_code == 401
    assert "Bad credentials" in r.json()["detail"]["message"]


def test_auth_mode_unavailable_returns_503(client):
    nw_mod._AUTH_MODE[0] = "unavailable"
    r = client.post("/nw/rest/api/auth/userpass", data={"username": "u", "password": "p"})
    assert r.status_code == 503


# ── Admin — toggle auth mode ──────────────────────────────────────────────────

def test_admin_set_auth_mode(client):
    r = client.post(
        "/nw/_admin/auth_mode",
        json={"mode": "locked"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["current"] == "locked"
    assert body["previous"] == "normal"
    assert nw_mod._AUTH_MODE[0] == "locked"


def test_admin_get_auth_mode(client):
    r = client.get("/nw/_admin/auth_mode", headers={"X-Admin-Key": ADMIN_KEY})
    assert r.status_code == 200
    assert r.json()["mode"] == "normal"


def test_admin_invalid_mode_422(client):
    r = client.post(
        "/nw/_admin/auth_mode",
        json={"mode": "broken"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert r.status_code == 422


def test_admin_no_key_403(client):
    r = client.post("/nw/_admin/auth_mode", json={"mode": "locked"})
    assert r.status_code == 403


def test_toggle_cycle(client):
    """Toggle through all modes and confirm auth endpoint behaviour."""
    for mode, expected_status in [
        ("locked", 500),
        ("bad_credentials", 401),
        ("unavailable", 503),
        ("normal", 200),
    ]:
        client.post(
            "/nw/_admin/auth_mode",
            json={"mode": mode},
            headers={"X-Admin-Key": ADMIN_KEY},
        )
        r = client.post("/nw/rest/api/auth/userpass", data={"username": "u", "password": "p"})
        assert r.status_code == expected_status, f"mode={mode}"


# ── Auth on SIEM endpoints ────────────────────────────────────────────────────

def test_incidents_no_auth_401(client):
    r = client.get("/nw/rest/api/incidents")
    assert r.status_code == 401


def test_incidents_bearer_auth(client):
    r = client.get("/nw/rest/api/incidents", headers=BEARER)
    assert r.status_code == 200


def test_incidents_netwitness_token_header(client):
    r = client.get("/nw/rest/api/incidents", headers=NW_HDR)
    assert r.status_code == 200


def test_cross_token_acceptance(client):
    """QRadar token works on the NetWitness surface (cross-acceptance)."""
    os.environ["SIEMULATOR_QRADAR_TOKEN"] = "qr-cross-tok"
    r = client.get("/nw/rest/api/incidents", headers={"NetWitness-Token": "qr-cross-tok"})
    assert r.status_code == 200


# ── Incident list ─────────────────────────────────────────────────────────────

def test_list_incidents_shape(client):
    r = client.get("/nw/rest/api/incidents", headers=NW_HDR)
    assert r.status_code == 200
    body = r.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert body["total"] == 38
    assert body["x-mock-source"] == "siemulator"


def test_list_incidents_pagination(client):
    r = client.get("/nw/rest/api/incidents?pageNumber=0&pageSize=5", headers=NW_HDR)
    assert r.status_code == 200
    assert len(r.json()["items"]) == 5

    r2 = client.get("/nw/rest/api/incidents?pageNumber=1&pageSize=5", headers=NW_HDR)
    ids_page0 = {i["id"] for i in r.json()["items"]}
    ids_page1 = {i["id"] for i in r2.json()["items"]}
    assert ids_page0.isdisjoint(ids_page1)


def test_incident_item_fields(client):
    r = client.get("/nw/rest/api/incidents?pageSize=1", headers=NW_HDR)
    inc = r.json()["items"][0]
    for field in ("id", "title", "priority", "status", "alertCount", "created", "lastUpdated"):
        assert field in inc, f"missing field: {field}"
    assert isinstance(inc["id"], int)
    assert isinstance(inc["alertCount"], int)
    # created / lastUpdated must be ms epoch (> 1 trillion)
    assert inc["created"] > 1_000_000_000_000
    assert inc["lastUpdated"] > 1_000_000_000_000


# ── Single incident ───────────────────────────────────────────────────────────

def test_get_incident_by_id(client):
    r = client.get("/nw/rest/api/incidents/10001", headers=NW_HDR)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 10001
    assert "title" in body


def test_get_incident_unknown_id_400(client):
    """NetWitness 12.5 returns 400 with the exact message shape for unknown IDs."""
    r = client.get("/nw/rest/api/incidents/99999", headers=NW_HDR)
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "'99999' is not a valid incident Id" in detail


def test_get_incident_non_integer_id_400(client):
    r = client.get("/nw/rest/api/incidents/abc", headers=NW_HDR)
    assert r.status_code == 400
    assert "'abc' is not a valid incident Id" in r.json()["detail"]


def test_incident_id_stable(client):
    """Same ID returns the same title on repeated calls (deterministic)."""
    r1 = client.get("/nw/rest/api/incidents/10005", headers=NW_HDR)
    r2 = client.get("/nw/rest/api/incidents/10005", headers=NW_HDR)
    assert r1.json()["title"] == r2.json()["title"]


# ── Alert fetch ───────────────────────────────────────────────────────────────

_FETCH_HDR = {**NW_HDR, "Content-Type": "application/json"}


def _alert_fetch(client, meta_value: str):
    return client.request(
        "GET",
        "/nw/rest/api/alert/fetch",
        headers=_FETCH_HDR,
        data=json.dumps({"meta_value": meta_value}),
    )


def test_fetch_alerts_shape(client):
    r = _alert_fetch(client, "10001")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert len(body["items"]) > 0
    assert body["x-mock-source"] == "siemulator"


def test_fetch_alerts_item_fields(client):
    r = _alert_fetch(client, "10001")
    alert = r.json()["items"][0]
    # Fields act 1454 reads
    assert "_id" in alert
    assert "originalAlert" in alert
    orig = alert["originalAlert"]
    assert "events" in orig
    assert len(orig["events"]) > 0
    event = orig["events"][0]
    assert "tenant" in event, "act 1454 reads the tenant field from events"


def test_fetch_alerts_count_matches_incident(client):
    inc = client.get("/nw/rest/api/incidents/10001", headers=NW_HDR).json()
    alerts = _alert_fetch(client, "10001").json()
    assert alerts["total"] == inc["alertCount"]


def test_fetch_alerts_unknown_incident_400(client):
    r = _alert_fetch(client, "99999")
    assert r.status_code == 400
    assert "'99999' is not a valid incident Id" in r.json()["detail"]
