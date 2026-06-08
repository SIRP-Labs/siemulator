"""Pinned regressions for the QRadar mock surface.

Shape pins (``id`` field, ``start_time`` ms-epoch) are CRITICAL —
breaking them crashes real QRadar ingestion scripts.
"""

from __future__ import annotations

import siemulator.qradar as qradar_mod


def test_health_no_auth(qradar_client):
    r = qradar_client().get("/qradar/api/help")
    assert r.status_code == 200
    body = r.json()
    assert body["mock"] is True
    assert "siem" in body["endpoint_categories"]


def test_offenses_requires_auth(qradar_client):
    r = qradar_client().get("/qradar/api/siem/offenses")
    assert r.status_code == 401
    detail = r.json()["detail"]
    assert detail["http_response"]["code"] == 401
    assert detail["x-mock-source"] == "siemulator"


def test_offenses_accepts_sec_header(qradar_client):
    """QRadar canonical auth is the SEC header, not Bearer."""
    r = qradar_client(token="t1").get(
        "/qradar/api/siem/offenses",
        headers={"SEC": "t1"},
    )
    assert r.status_code == 200


def test_offenses_accepts_bearer(qradar_client):
    """Also accept Bearer — some integrations send that shape."""
    r = qradar_client(token="t1").get(
        "/qradar/api/siem/offenses",
        headers={"Authorization": "Bearer t1"},
    )
    assert r.status_code == 200


def test_offense_shape(qradar_client):
    """Every field a typical QRadar ingest path reads must be present."""
    r = qradar_client(token="t1").get(
        "/qradar/api/siem/offenses",
        headers={"SEC": "t1"},
    )
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list)
    assert len(items) >= 1
    o = items[0]
    for k in (
        "offense_id",
        "description",
        "offense_source",
        "source_ip",
        "destination_ip",
        "severity",
        "magnitude",
        "credibility",
        "relevance",
        "status",
        "categories",
        "rules",
        "start_time",
        "event_count",
        "log_sources",
        "_detection",
        "x-mock-source",
    ):
        assert k in o, f"missing QRadar offence field: {k}"
    assert isinstance(o["severity"], int)
    assert 1 <= o["severity"] <= 10
    det = o["_detection"]
    assert "DetectName" in det
    assert "MD5String" in det
    assert "TechniqueId" in det


def test_offense_matches_real_script_shape(qradar_client):
    """Pinned: ``id`` exists as int; ``start_time`` is INT MS EPOCH.

    Real QRadar consumers do ``a['offense_id']=a['id']`` and
    ``datetime.fromtimestamp(a['start_time']/1000)``. If this shape
    regresses, downstream ingest crashes.
    """
    r = qradar_client(token="t1").get(
        "/qradar/api/siem/offenses",
        headers={"SEC": "t1"},
    )
    o = r.json()[0]
    assert "id" in o, "consumers read a['id']; missing field breaks polling"
    assert isinstance(o["id"], int)
    assert isinstance(o["start_time"], int), (
        f"start_time must be int ms epoch; got {type(o['start_time']).__name__}"
    )
    assert o["start_time"] > 1_000_000_000_000, (
        f"start_time {o['start_time']} looks like seconds, not ms epoch"
    )


def test_range_header_clamping(qradar_client):
    """QRadar uses Range: items=0-N for pagination."""
    c = qradar_client(token="t1")
    h = {"SEC": "t1", "Range": "items=0-9"}
    r = c.get("/qradar/api/siem/offenses", headers=h)
    items = r.json()
    assert len(items) == 10
    h["Range"] = "items=0-999"
    items = c.get("/qradar/api/siem/offenses", headers=h).json()
    assert len(items) == 50


def test_get_offense_by_id_preserves_id(qradar_client):
    r = qradar_client(token="t1").get(
        "/qradar/api/siem/offenses/42",
        headers={"SEC": "t1"},
    )
    assert r.status_code == 200
    assert r.json()["offense_id"] == 42


def test_ariel_search_post_then_results(qradar_client):
    c = qradar_client(token="t1")
    h = {"SEC": "t1"}
    submit = c.post(
        "/qradar/api/ariel/searches",
        json={"query_expression": "SELECT * FROM events", "limit": 3},
        headers=h,
    )
    assert submit.status_code == 200
    body = submit.json()
    assert body["status"] == "COMPLETED"
    assert body["record_count"] == 3
    sid = body["search_id"]
    status_r = c.get(f"/qradar/api/ariel/searches/{sid}", headers=h)
    assert status_r.status_code == 200
    assert status_r.json()["status"] == "COMPLETED"
    results_r = c.get(f"/qradar/api/ariel/searches/{sid}/results", headers=h)
    assert results_r.status_code == 200
    assert len(results_r.json()["events"]) == 3


def test_ariel_unknown_search_404(qradar_client):
    r = qradar_client(token="t1").get(
        "/qradar/api/ariel/searches/does-not-exist/results",
        headers={"SEC": "t1"},
    )
    assert r.status_code == 404
    assert r.json()["detail"]["http_response"]["code"] == 404


def test_mock_source_on_every_offense(qradar_client):
    items = qradar_client(token="t1").get(
        "/qradar/api/siem/offenses",
        headers={"SEC": "t1", "Range": "items=0-9"},
    ).json()
    assert len(items) == 10
    for o in items:
        assert o["x-mock-source"] == "siemulator"


def test_severity_mapping():
    assert qradar_mod.severity_to_qradar("Critical") == 9
    assert qradar_mod.severity_to_qradar("High") == 7
    assert qradar_mod.severity_to_qradar("Medium") == 5
    assert qradar_mod.severity_to_qradar("Low") == 3
    assert qradar_mod.severity_to_qradar("Informational") == 1
    assert qradar_mod.severity_to_qradar("anything-else") == 5


def test_accepts_logscale_token(both_clients):
    """Cross-token acceptance: either LogScale or QRadar token works on the
    QRadar surface. Both serve synthetic data, so zero security impact."""
    c = both_clients(logscale="logscale-tok", qradar="qradar-tok")
    assert (
        c.get("/qradar/api/siem/offenses", headers={"SEC": "logscale-tok"}).status_code
        == 200
    )
    assert (
        c.get(
            "/qradar/api/siem/offenses",
            headers={"Authorization": "Bearer logscale-tok"},
        ).status_code
        == 200
    )
    assert (
        c.get("/qradar/api/siem/offenses", headers={"SEC": "qradar-tok"}).status_code
        == 200
    )
    assert (
        c.get("/qradar/api/siem/offenses", headers={"SEC": "neither-token"}).status_code
        == 401
    )


def test_accepts_token_query_param(qradar_client):
    c = qradar_client(token="qradar-qp")
    r = c.get("/qradar/api/siem/offenses?token=qradar-qp")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_rejects_wrong_query_param_token(qradar_client):
    c = qradar_client(token="qradar-qp")
    r = c.get("/qradar/api/siem/offenses?token=neither-tok")
    assert r.status_code == 401


def test_debug_endpoints_disabled_without_admin_key(qradar_client, monkeypatch):
    """SIEMULATOR_ADMIN_KEY unset → /_debug/* returns 403, never the data."""
    monkeypatch.delenv("SIEMULATOR_ADMIN_KEY", raising=False)
    c = qradar_client(token="t1")
    r = c.get("/qradar/_debug/recent")
    assert r.status_code == 403


def test_debug_endpoints_require_correct_key(qradar_client, monkeypatch):
    monkeypatch.setenv("SIEMULATOR_ADMIN_KEY", "admin-tok")
    c = qradar_client(token="t1")
    assert c.get("/qradar/_debug/recent").status_code == 403
    assert (
        c.get("/qradar/_debug/recent", headers={"X-Admin-Key": "wrong"}).status_code
        == 403
    )
    r = c.get("/qradar/_debug/recent", headers={"X-Admin-Key": "admin-tok"})
    assert r.status_code == 200
    assert r.json()["x-mock-source"] == "siemulator"
