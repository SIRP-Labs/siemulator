"""Pinned regressions for the LogScale mock surface.

Mirrors the contract tests from sara-open/tests/test_siem_mock.py
(LogScale half), retargeted at the siemulator package.
"""

from __future__ import annotations


def test_status_no_auth(logscale_client):
    r = logscale_client().get("/logscale/api/v1/status")
    assert r.status_code == 200
    body = r.json()
    assert body["mock"] is True
    assert "Falcon LogScale" in body["name"]
    assert body["x-mock-source"] == "siemulator"
    assert r.headers.get("X-Mock-Source") == "siemulator"


def test_repositories_no_auth(logscale_client):
    r = logscale_client().get("/logscale/api/v1/repositories")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert body[0]["name"] == "detections"


def test_alerts_requires_auth(logscale_client):
    r = logscale_client().get("/logscale/api/v1/repositories/detections/alerts")
    assert r.status_code == 401


def test_alerts_wrong_token_401(logscale_client):
    r = logscale_client(token="right").get(
        "/logscale/api/v1/repositories/detections/alerts",
        headers={"Authorization": "Bearer wrong"},
    )
    assert r.status_code == 401


def test_alerts_returns_humio_envelope(logscale_client):
    r = logscale_client(token="abc").get(
        "/logscale/api/v1/repositories/detections/alerts?limit=2",
        headers={"Authorization": "Bearer abc"},
    )
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) >= {"events", "metadata"}
    assert len(body["events"]) == 2
    e0 = body["events"][0]
    for k in ("@timestamp", "@id", "@rawstring", "#repo", "#type"):
        assert k in e0
    for k in (
        "metadata.eventType",
        "event.DetectName",
        "event.DetectId",
        "event.Severity",
        "event.Tactic",
        "event.TechniqueId",
        "event.ComputerName",
        "event.MD5String",
        "event.SHA256String",
        "event.FalconHostLink",
    ):
        assert k in e0, f"missing field {k} from synthetic event"
    assert e0["x-mock-source"] == "siemulator"
    assert body["metadata"]["extraData"]["x-mock-source"] == "siemulator"


def test_alerts_limit_clamping(logscale_client):
    c = logscale_client(token="abc")
    h = {"Authorization": "Bearer abc"}
    big = c.get(
        "/logscale/api/v1/repositories/detections/alerts?limit=999", headers=h
    ).json()
    assert len(big["events"]) == 50
    tiny = c.get(
        "/logscale/api/v1/repositories/detections/alerts?limit=0", headers=h
    ).json()
    assert len(tiny["events"]) == 1


def test_query_endpoint_works(logscale_client):
    r = logscale_client(token="abc").get(
        "/logscale/api/v1/repositories/detections/query?q=foo&limit=1",
        headers={"Authorization": "Bearer abc"},
    )
    assert r.status_code == 200
    assert len(r.json()["events"]) == 1


def test_queryjobs_post_then_poll(logscale_client):
    c = logscale_client(token="abc")
    h = {"Authorization": "Bearer abc"}
    submit = c.post(
        "/logscale/api/v1/repositories/detections/queryjobs",
        json={"limit": 2},
        headers=h,
    )
    assert submit.status_code == 200
    job_id = submit.json()["id"]
    poll = c.get(
        f"/logscale/api/v1/repositories/detections/queryjobs/{job_id}",
        headers=h,
    )
    assert poll.status_code == 200
    body = poll.json()
    assert len(body["events"]) == 2
    poll2 = c.get(
        f"/logscale/api/v1/repositories/detections/queryjobs/{job_id}",
        headers=h,
    )
    assert poll2.json()["events"][0]["@id"] == body["events"][0]["@id"]


def test_unknown_queryjob_404(logscale_client):
    r = logscale_client(token="abc").get(
        "/logscale/api/v1/repositories/detections/queryjobs/does-not-exist",
        headers={"Authorization": "Bearer abc"},
    )
    assert r.status_code == 404


def test_templates_provide_variety(logscale_client):
    c = logscale_client(token="abc")
    body = c.get(
        "/logscale/api/v1/repositories/detections/alerts?limit=20",
        headers={"Authorization": "Bearer abc"},
    ).json()
    names = {e["event.DetectName"] for e in body["events"]}
    assert len(names) >= 3, (
        f"expected variety across templates; only saw {names}. "
        "If this fails repeatedly the template-rotation logic regressed."
    )


def test_safety_markers_present_in_every_event(logscale_client):
    c = logscale_client(token="abc")
    body = c.get(
        "/logscale/api/v1/repositories/detections/alerts?limit=10",
        headers={"Authorization": "Bearer abc"},
    ).json()
    for e in body["events"]:
        assert "x-mock-source" in e
        assert e["x-mock-source"] == "siemulator"


def test_accepts_token_query_param(logscale_client):
    """Query-param token survives header-stripping proxies — pinned channel."""
    c = logscale_client(token="qp-tok")
    r = c.get("/logscale/api/v1/repositories/detections/alerts?token=qp-tok")
    assert r.status_code == 200
    assert "events" in r.json()
