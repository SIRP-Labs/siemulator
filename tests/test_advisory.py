"""Regression tests for the advisory ingestion feature.

All URL fetches are mocked — no real network calls are made.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import siemulator.advisory as adv_mod

# ── Fixtures ──────────────────────────────────────────────────────────────────

TOKEN = "test-advisory-tok"
BEARER = {"Authorization": f"Bearer {TOKEN}"}

SAMPLE_HTML = b"""
<html>
<head><title>CISA Advisory AA24-001A: Example Malware</title></head>
<body>
<h1>Advisory AA24-001A</h1>
<p>CVE-2024-12345 exploited via T1059.001 and T1027.001.</p>
<p>Malware SHA256: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899</p>
<p>C2 server at 185.220.101.34 and 192.0.2.55</p>
<p>MD5: aabbccddeeff00112233445566778899</p>
</body>
</html>
""".strip()

SAMPLE_TEXT = b"""
Threat advisory: CVE-2023-99999 and CVE-2023-99998.
Techniques: T1190, T1133.
C2 IPs: 203.0.113.10 203.0.113.20
Hash: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
""".strip()


def _mock_urlopen(content: bytes, content_type: str = "text/html; charset=utf-8"):
    """Build a mock for urllib.request.urlopen context manager."""
    msg = MagicMock()
    msg.get_content_type.return_value = content_type.split(";")[0].strip()
    msg.get_content_charset.return_value = "utf-8"

    resp = MagicMock()
    resp.headers = msg
    resp.read.return_value = content
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


@pytest.fixture(autouse=True)
def clear_store():
    """Reset advisory store and counter between tests."""
    adv_mod._ADVISORY_STORE.clear()
    adv_mod._ADV_COUNTER[0] = 0
    yield
    adv_mod._ADVISORY_STORE.clear()
    adv_mod._ADV_COUNTER[0] = 0


@pytest.fixture
def client():
    os.environ["SIEMULATOR_LOGSCALE_TOKEN"] = TOKEN
    os.environ["SIEMULATOR_QRADAR_TOKEN"] = TOKEN
    app = FastAPI()
    app.include_router(adv_mod.build_router())
    return TestClient(app)


# ── Auth ──────────────────────────────────────────────────────────────────────

def test_ingest_no_auth(client):
    r = client.post("/api/advisory", json={"url": "https://example.com/"})
    assert r.status_code == 401


def test_list_no_auth(client):
    r = client.get("/api/advisories")
    assert r.status_code == 401


def test_delete_no_auth(client):
    r = client.delete("/api/advisories/adv-0001-abcd1234")
    assert r.status_code == 401


# ── Validation ────────────────────────────────────────────────────────────────

def test_missing_url_field(client):
    r = client.post("/api/advisory", json={}, headers=BEARER)
    assert r.status_code == 422
    assert "url" in r.json()["detail"]["error"]


def test_bad_scheme_file(client):
    r = client.post("/api/advisory", json={"url": "file:///etc/passwd"}, headers=BEARER)
    assert r.status_code == 422
    assert "http" in r.json()["detail"]["error"]


def test_bad_scheme_ftp(client):
    r = client.post("/api/advisory", json={"url": "ftp://files.example.com/advisory.txt"}, headers=BEARER)
    assert r.status_code == 422


def test_network_error_returns_502(client):
    import urllib.error

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        r = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    assert r.status_code == 502
    assert "failed to fetch" in r.json()["detail"]["error"]


def test_http_error_returns_502(client):
    import urllib.error

    with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
        "https://example.com/", 403, "Forbidden", {}, None
    )):
        r = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    assert r.status_code == 502
    assert "403" in r.json()["detail"]["error"]


# ── IOC extraction unit tests ─────────────────────────────────────────────────

def test_extract_iocs_sha256():
    text = "SHA256: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    iocs = adv_mod._extract_iocs(text)
    assert "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" in iocs["sha256"]


def test_extract_iocs_cve():
    text = "CVE-2024-12345 and cve-2023-99999 are affected."
    iocs = adv_mod._extract_iocs(text)
    assert "CVE-2024-12345" in iocs["cves"]
    assert "CVE-2023-99999" in iocs["cves"]


def test_extract_iocs_mitre():
    text = "Techniques include T1059.001 and T1027 and T1190."
    iocs = adv_mod._extract_iocs(text)
    assert "T1059.001" in iocs["mitre_techniques"]
    assert "T1027" in iocs["mitre_techniques"]
    assert "T1190" in iocs["mitre_techniques"]


def test_extract_iocs_ips_prefers_routable():
    text = "Internal: 192.168.1.1, External: 185.220.101.34"
    iocs = adv_mod._extract_iocs(text)
    assert "185.220.101.34" in iocs["ips"]
    # RFC-1918 included only as fallback when no routable IPs exist
    assert "192.168.1.1" not in iocs["ips"]


def test_extract_iocs_rfc1918_fallback():
    text = "Pivot host 10.0.0.5 was observed."
    iocs = adv_mod._extract_iocs(text)
    assert "10.0.0.5" in iocs["ips"]


def test_extract_iocs_sha1_not_confused_with_sha256():
    sha256 = "a" * 64
    sha1 = "b" * 40
    text = f"{sha256} {sha1}"
    iocs = adv_mod._extract_iocs(text)
    assert sha256 in iocs["sha256"]
    # sha1 (40 chars) is a substring of sha256 (64 chars)? No — they're different chars.
    # The filter excludes sha1 values that are substrings of any sha256.
    # "b" * 40 is NOT a substring of "a" * 64, so it should appear in sha1.
    assert sha1 in iocs["sha1"]


def test_extract_iocs_dedup():
    text = "T1059.001 T1059.001 CVE-2024-12345 CVE-2024-12345"
    iocs = adv_mod._extract_iocs(text)
    assert iocs["mitre_techniques"].count("T1059.001") == 1
    assert iocs["cves"].count("CVE-2024-12345") == 1


# ── Ingest + shape contract ───────────────────────────────────────────────────

def test_ingest_html_advisory(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        r = client.post(
            "/api/advisory",
            json={"url": "https://cisa.gov/advisory/aa24-001a", "label": "CISA AA24-001A"},
            headers=BEARER,
        )
    assert r.status_code == 201
    body = r.json()
    assert body["x-mock-source"] == "siemulator"
    assert body["advisory_id"].startswith("adv-")
    assert body["url"] == "https://cisa.gov/advisory/aa24-001a"
    assert body["label"] == "CISA AA24-001A"
    assert "title" in body
    assert "extracted" in body
    assert "offense" in body
    assert "event" in body


def test_ingest_extracts_iocs_from_html(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        r = client.post(
            "/api/advisory",
            json={"url": "https://example.com/"},
            headers=BEARER,
        )
    iocs = r.json()["extracted"]
    assert "CVE-2024-12345" in iocs["cves"]
    assert "T1059.001" in iocs["mitre_techniques"]
    assert "185.220.101.34" in iocs["ips"]
    assert "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" in iocs["sha256"]


def test_ingest_title_from_html(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        r = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    assert "CISA Advisory AA24-001A" in r.json()["title"]


# ── Offense shape pins (breaking these fails downstream ingestion) ─────────────

def test_offense_shape_contract(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_TEXT, "text/plain")):
        r = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    offense = r.json()["offense"]
    # Fields that downstream QRadar scripts depend on
    assert isinstance(offense["id"], int)
    assert isinstance(offense["offense_id"], int)
    assert offense["id"] == offense["offense_id"]
    assert isinstance(offense["start_time"], int)
    assert offense["start_time"] > 1_000_000_000_000, "start_time must be ms epoch"
    assert isinstance(offense["magnitude"], int)
    assert isinstance(offense["severity"], int)
    assert "description" in offense
    assert offense["status"] == "OPEN"
    assert offense["x-mock-source"] == "siemulator"
    assert "_advisory" in offense


def test_event_shape_contract(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        r = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    event = r.json()["event"]
    assert "@timestamp" in event
    assert "@id" in event
    assert "event.DetectName" in event
    assert "event.SeverityName" in event
    assert "event.AdvisoryURL" in event
    assert "event.IOCs" in event
    assert event["x-mock-source"] == "siemulator"


def test_offense_ids_are_unique(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        r1 = client.post("/api/advisory", json={"url": "https://a.example.com/"}, headers=BEARER)
        r2 = client.post("/api/advisory", json={"url": "https://b.example.com/"}, headers=BEARER)
    id1 = r1.json()["offense"]["offense_id"]
    id2 = r2.json()["offense"]["offense_id"]
    assert id1 != id2


def test_offense_id_in_advisory_range(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        r = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    oid = r.json()["offense"]["offense_id"]
    assert oid >= adv_mod._ADV_OFFENSE_BASE, "advisory offense IDs must be in advisory range"


# ── CRUD ──────────────────────────────────────────────────────────────────────

def test_list_empty(client):
    r = client.get("/api/advisories", headers=BEARER)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 0
    assert body["advisories"] == []


def test_list_after_ingest(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        client.post("/api/advisory", json={"url": "https://example.com/", "label": "Test"}, headers=BEARER)
    r = client.get("/api/advisories", headers=BEARER)
    body = r.json()
    assert body["count"] == 1
    entry = body["advisories"][0]
    assert "advisory_id" in entry
    assert "offense_id" in entry
    assert "ioc_counts" in entry
    assert entry["label"] == "Test"


def test_get_advisory_by_id(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        ingest = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    adv_id = ingest.json()["advisory_id"]
    r = client.get(f"/api/advisories/{adv_id}", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["advisory_id"] == adv_id


def test_get_advisory_not_found(client):
    r = client.get("/api/advisories/adv-9999-doesnotexist", headers=BEARER)
    assert r.status_code == 404


def test_delete_advisory(client):
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(SAMPLE_HTML)):
        ingest = client.post("/api/advisory", json={"url": "https://example.com/"}, headers=BEARER)
    adv_id = ingest.json()["advisory_id"]
    r = client.delete(f"/api/advisories/{adv_id}", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["deleted"] == adv_id
    # Confirm it's gone
    assert client.get(f"/api/advisories/{adv_id}", headers=BEARER).status_code == 404


def test_delete_advisory_not_found(client):
    r = client.delete("/api/advisories/adv-9999-doesnotexist", headers=BEARER)
    assert r.status_code == 404


# ── QRadar surface integration ────────────────────────────────────────────────

def test_qradar_advisory_mode_empty():
    os.environ["SIEMULATOR_LOGSCALE_TOKEN"] = TOKEN
    os.environ["SIEMULATOR_QRADAR_TOKEN"] = TOKEN
    os.environ["SIEMULATOR_QRADAR_PREFIX"] = "/qradar"

    from siemulator.qradar import build_router

    app = FastAPI()
    app.include_router(build_router())
    c = TestClient(app)

    r = c.get(f"/qradar/api/siem/offenses?scenarios=advisory&token={TOKEN}")
    assert r.status_code == 200
    assert r.json() == []
    assert "X-Mock-Advisory-Count" in r.headers
    assert r.headers["X-Mock-Advisory-Count"] == "0"


def test_qradar_advisory_mode_returns_ingested():
    os.environ["SIEMULATOR_LOGSCALE_TOKEN"] = TOKEN
    os.environ["SIEMULATOR_QRADAR_TOKEN"] = TOKEN
    os.environ["SIEMULATOR_QRADAR_PREFIX"] = "/qradar"

    from siemulator.qradar import build_router

    # Inject directly into the store
    adv_mod._ADV_COUNTER[0] = 99
    fake_offense = {
        "id": 700099, "offense_id": 700099, "start_time": 1_700_000_000_000,
        "magnitude": 7, "description": "Test advisory offense",
        "status": "OPEN", "x-mock-source": "siemulator",
    }
    adv_mod._ADVISORY_STORE["adv-0099-test"] = {
        "advisory_id": "adv-0099-test",
        "url": "https://example.com/",
        "label": "Test",
        "title": "Test Advisory",
        "fetched_at": "2026-01-01T00:00:00Z",
        "extracted": {},
        "offense": fake_offense,
        "event": {},
    }

    app = FastAPI()
    app.include_router(build_router())
    c = TestClient(app)

    r = c.get(f"/qradar/api/siem/offenses?scenarios=advisory&token={TOKEN}")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["offense_id"] == 700099
