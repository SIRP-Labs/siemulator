"""SIEMULATOR_MODE=pinned — the private deployment that serves only hand-written
showcase scenarios (one predictable incident, no real infrastructure, no people).

The app factory, the mode switch, auth and the routes run for real.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from siemulator import pinned

TOKEN = "private-qradar-token"
SID = "SHOWCASE-PHISH-1"
OID = pinned.PINNABLE[SID][0]

TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
HOSTISH = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*[a-z]\b", re.I)
EMAIL = re.compile(r"\b([a-z0-9._-]+)@([a-z0-9.-]+)\b", re.I)
# Not hostnames: file names and the decoded PowerShell's .NET-ish tokens.
NOT_HOSTS = re.compile(r"\.(zip|js|dll|bin|exe|ps1)$|^(env:temp|stage2)\b", re.I)
# Mailbox / account local parts must be roles or services, not people.
ROLE_LOCAL_PARTS = {"billing", "ar-desk", "ap-invoices"}


@pytest.fixture(autouse=True)
def _clean_served():
    pinned.reset_served()
    yield
    pinned.reset_served()


@pytest.fixture
def pinned_env(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_MODE", "pinned")
    monkeypatch.setenv("SIEMULATOR_PINNED_SCENARIOS", SID)
    monkeypatch.setenv("SIEMULATOR_QRADAR_TOKEN", TOKEN)
    monkeypatch.setenv("SIEMULATOR_LOGSCALE_TOKEN", "logscale-token")
    monkeypatch.setenv("SIEMULATOR_QRADAR_PREFIX", "/qradar")
    monkeypatch.setenv("SIEMULATOR_ACCESS_LOG_ENABLED", "false")
    return monkeypatch


def _client() -> TestClient:
    from siemulator.app import create_app
    return TestClient(create_app())


def _get(client, path="/qradar/api/siem/offenses", **params):
    return client.get(path, params=params, headers={"SEC": TOKEN})


# ── content rules: no real infrastructure, no people ────────────────


@pytest.mark.parametrize("sid", sorted(pinned.PINNABLE))
def test_every_ipv4_is_in_an_rfc5737_documentation_range(sid):
    text = json.dumps(pinned.PINNABLE[sid][3])
    ips = IPV4.findall(text)
    assert ips, "control: the scenario must carry IPs for this test to mean anything"
    for ip in ips:
        assert any(ipaddress.ip_address(ip) in n for n in TEST_NETS), ip


@pytest.mark.parametrize("sid", sorted(pinned.PINNABLE))
def test_every_hostname_is_under_example_test(sid):
    text = json.dumps(pinned.PINNABLE[sid][3])
    hosts = {h for h in HOSTISH.findall(text) if not NOT_HOSTS.search(h)}
    assert hosts, "control: the scenario must name hosts for this test to mean anything"
    for h in hosts:
        assert h.lower().endswith(".example.test"), h


@pytest.mark.parametrize("sid", sorted(pinned.PINNABLE))
def test_no_mailbox_or_account_names_a_person(sid):
    raw = pinned.PINNABLE[sid][3]
    text = json.dumps(raw)
    # Message-IDs (<timestamp.hex@domain>) look like addresses but name nobody.
    locals_ = {m[0].lower() for m in EMAIL.findall(text) if not m[0][:1].isdigit()}
    assert locals_, "control: the scenario must carry mailboxes"
    assert locals_ <= ROLE_LOCAL_PARTS, locals_ - ROLE_LOCAL_PARTS
    assert raw["device"]["account_type"] == "shared role account"


@pytest.mark.parametrize("sid", sorted(pinned.PINNABLE))
def test_no_answer_key_or_test_metadata_reaches_the_offence(sid):
    text = json.dumps(pinned.as_qradar_offence(sid))
    for leak in ("_test_meta", "expected_", "SARA_SCENARIO_TEST", "Sophisticated-Test"):
        assert leak not in text


def test_pinned_ids_never_collide_with_the_public_library():
    from siemulator.scenarios import SCENARIOS
    public = {oid for oid, *_ in SCENARIOS}
    assert not public & {v[0] for v in pinned.PINNABLE.values()}


# ── serving rules ────────────────────────────────────────────────────


@pytest.mark.parametrize("query", [{}, {"scenarios": "all"}, {"scenarios": "replay"},
                                   {"scenarios": "mix"}, {"extras": "50"}, {"labels": "blind"}])
def test_every_query_gets_only_the_pinned_offence(pinned_env, query):
    r = _get(_client(), **query)
    assert r.status_code == 200
    assert [o["offense_id"] for o in r.json()] == [OID]
    assert r.headers["X-Mock-Mode"] == "pinned"


def test_each_offence_is_served_once_per_process(pinned_env):
    c = _client()
    assert len(_get(c).json()) == 1
    assert _get(c).json() == []
    assert _get(c).json() == []


def test_repeat_switch_serves_on_every_poll(pinned_env):
    pinned_env.setenv("SIEMULATOR_PINNED_REPEAT", "true")
    c = _client()
    assert len(_get(c).json()) == 1
    assert len(_get(c).json()) == 1


def test_detail_answers_for_a_pinned_id_even_after_serving(pinned_env):
    c = _client()
    _get(c)
    r = _get(c, f"/qradar/api/siem/offenses/{OID}")
    assert r.status_code == 200 and r.json()["offense_id"] == OID
    assert _get(c, "/qradar/api/siem/offenses/90011").status_code == 404


@pytest.mark.parametrize("value,header", [("", "none-configured"), ("NOPE-1", "unknown:NOPE-1"),
                                          (f"{SID},NOPE-1", "unknown:NOPE-1")])
def test_unknown_or_missing_selection_serves_nothing(pinned_env, value, header):
    pinned_env.setenv("SIEMULATOR_PINNED_SCENARIOS", value)
    r = _get(_client())
    assert r.json() == [] and r.headers["X-Mock-Pinned"] == header


@pytest.mark.parametrize("headers", [{}, {"SEC": "logscale-token"}, {"SEC": "wrong"},
                                     {"Authorization": "Bearer logscale-token"}])
def test_only_the_qradar_token_opens_it(pinned_env, headers):
    r = _client().get("/qradar/api/siem/offenses", headers=headers)
    assert r.status_code == 401


@pytest.mark.parametrize("token", ["", "qradar-dev-token"])
def test_an_unset_or_default_token_refuses_everyone(pinned_env, token):
    pinned_env.setenv("SIEMULATOR_QRADAR_TOKEN", token)
    r = _client().get("/qradar/api/siem/offenses", headers={"SEC": token or "x"})
    assert r.status_code == 503


@pytest.mark.parametrize("path", ["/logscale/api/v1/status", "/qradar/api/siem/scenarios",
                                  "/alerts/entities/alerts/v2", "/v1.0/security/alerts",
                                  "/rest/api/incidents", "/splunk/services/server/info", "/guide"])
def test_no_other_surface_is_mounted(pinned_env, path):
    assert _client().get(path, headers={"SEC": TOKEN}).status_code == 404


def test_info_reports_the_selection(pinned_env):
    body = _client().get("/api/info").json()
    assert body["mode"] == "pinned" and body["pinned"] == [SID] and body["unknown"] == []


def test_without_the_mode_the_public_app_is_unchanged(monkeypatch):
    monkeypatch.delenv("SIEMULATOR_MODE", raising=False)
    monkeypatch.setenv("SIEMULATOR_QRADAR_TOKEN", "qradar-dev-token")
    r = _client().get("/qradar/api/siem/scenarios", headers={"SEC": "qradar-dev-token"})
    assert r.status_code == 200
    assert OID not in {o["offense_id"] for o in r.json()}


# ── retiming ─────────────────────────────────────────────────────────


def test_retime_makes_the_newest_event_minutes_old_and_keeps_spacing():
    now = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
    raw = pinned.PINNABLE[SID][3]
    shifted = pinned.retime(raw, now)
    assert shifted["timestamp"] == "2026-10-09T11:57:00Z"
    # 08:54:12 → 09:00:00 in the authored scenario: spacing preserved.
    assert shifted["email"]["received"] == "2026-10-09T11:51:12Z"
    assert raw["timestamp"] == "2026-01-01T09:00:00Z", "the authored scenario is not mutated"


def test_retime_off_keeps_authored_times(pinned_env):
    pinned_env.setenv("SIEMULATOR_PINNED_RETIME", "false")
    o = pinned.as_qradar_offence(SID)
    assert o["_raw_alert"]["timestamp"] == "2026-01-01T09:00:00Z"
    assert o["start_time"] < o["last_updated_time"]


def test_served_offence_starts_recently(pinned_env):
    o = _get(_client()).json()[0]
    start = datetime.fromtimestamp(o["start_time"] / 1000, tz=timezone.utc)
    assert timedelta(0) < datetime.now(timezone.utc) - start < timedelta(minutes=30)


# ── SIRP's QRadar app scripts, as they actually call ────────────────
# automation-engine apps/Qradar/qradar.py (ingestion) and refset_ip_dynamic.py
# (containment) call https://<server>/api/... with no /qradar prefix, a
# lower-case `sec` header, and a start_time filter of "now - 30 min" or the
# last saved start_time.


@pytest.fixture
def root_env(pinned_env):
    pinned_env.setenv("SIEMULATOR_QRADAR_PREFIX", "/")
    return pinned_env


def test_the_sirp_ingestion_script_poll_gets_the_offence_once(root_env):
    c = _client()
    t30 = int((datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp() * 1000)
    url = f"/api/siem/offenses?filter=status%3D%22Open%22%20and%20start_time%20%3E%3D%20{t30}"
    first = c.get(url, headers={"Accept": "application/json", "sec": TOKEN})
    assert first.status_code == 200
    offences = first.json()
    assert [o["id"] for o in offences] == [OID]
    o = offences[0]
    # The script keeps only start_time > curr_time, maps magnitude 8 -> "High",
    # and needs id / start_time / magnitude.
    assert o["start_time"] > t30 and int(o["magnitude"]) > 6
    assert c.get(url, headers={"sec": TOKEN}).json() == []


def test_the_sirp_block_ip_action_is_recorded_not_executed(root_env):
    c = _client()
    hdrs = {"SEC": TOKEN, "Version": "7.1", "content-type": "application/json", "accept": "application/json"}
    r = c.post("/api/reference_data/sets/SOAR_Blocked_IPs?value=203.0.113.88", headers=hdrs)
    assert r.status_code == 200 and r.json()["simulated"] is True
    assert r.headers["X-Mock-Simulated-Action"] == "reference_set_add"
    c.post("/api/reference_data/sets/SOAR_Blocked_IPs?value=203.0.113.88", headers=hdrs)  # idempotent
    got = c.get("/api/reference_data/sets/SOAR_Blocked_IPs", headers=hdrs).json()
    assert [e["value"] for e in got["data"]] == ["203.0.113.88"]
    assert c.get("/api/reference_data/sets/other", headers=hdrs).json()["number_of_elements"] == 0


def test_offence_notes_are_recorded_for_pinned_offences_only(root_env):
    c = _client()
    h = {"SEC": TOKEN}
    r = c.post(f"/api/siem/offenses/{OID}/notes?note_text=Contained%20by%20SOAR", headers=h)
    assert r.status_code == 200 and r.json()["id"] == 1
    assert [n["note_text"] for n in c.get(f"/api/siem/offenses/{OID}/notes", headers=h).json()] == ["Contained by SOAR"]
    assert c.post("/api/siem/offenses/90011/notes?note_text=x", headers=h).status_code == 404


@pytest.mark.parametrize("method,path", [
    ("post", "/api/reference_data/sets/S?value=203.0.113.88"),
    ("get", "/api/reference_data/sets/S"),
    ("post", f"/api/siem/offenses/{OID}/notes?note_text=x"),
    ("get", f"/api/siem/offenses/{OID}/notes"),
])
def test_simulated_actions_need_the_token(root_env, method, path):
    assert getattr(_client(), method)(path, headers={"SEC": "wrong"}).status_code == 401


def test_a_block_without_a_value_is_refused(root_env):
    assert _client().post("/api/reference_data/sets/S", headers={"SEC": TOKEN}).status_code == 422
