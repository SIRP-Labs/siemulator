"""Pinned regressions for the sophisticated multi-source attack scenarios."""

from __future__ import annotations


def test_scenarios_module_loads():
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    assert len(out) == 22, "expected exactly 22 scenario alerts (12 S1-S5 + 10 v2 TEST A-J)"
    ids = [s["id"] for s in out]
    assert all(90_000 < i < 90_100 for i in ids)
    assert len(set(ids)) == 22, "scenario IDs must be unique"


def test_scenarios_have_qradar_shape():
    from siemulator import scenarios

    for s in scenarios.all_scenarios_as_qradar():
        assert isinstance(s["id"], int)
        assert isinstance(s["start_time"], int)
        assert s["start_time"] > 1_000_000_000_000, "start_time must be ms epoch"
        assert isinstance(s.get("magnitude"), int)
        assert "description" in s
        assert "_raw_alert" in s, "raw alert must be preserved for downstream agents"
        assert "_scenario_id" in s
        assert s["x-mock-source"] == "siemulator"


def test_scenarios_endpoint_direct(qradar_client):
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/scenarios?token=stok")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 22
    s1_ids = sorted(s["id"] for s in items if s.get("_scenario_id") == "S1")
    assert s1_ids == [90011, 90012, 90013, 90014, 90015]


def test_scenarios_via_query_param(qradar_client):
    """``?scenarios=all`` on /api/siem/offenses returns all 22 scenarios."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all")
    assert r.status_code == 200
    assert len(r.json()) == 22


def test_scenarios_mix_mode(qradar_client):
    """``?scenarios=mix`` returns scenarios + synthetic templates."""
    c = qradar_client(token="stok")
    r = c.get(
        "/qradar/api/siem/offenses?token=stok&scenarios=mix",
        headers={"Range": "items=0-2"},
    )
    items = r.json()
    assert len(items) >= 25  # 22 scenarios + 3 templates


def test_scenarios_preserve_multi_source_narratives():
    """Spot-check Scenario 1's 5-alert chain — Proofpoint → Defender →
    CrowdStrike → Defender → Zscaler all present + tagged S1."""
    from siemulator import scenarios

    s1 = [
        s
        for s in scenarios.all_scenarios_as_qradar()
        if s.get("_scenario_id") == "S1"
    ]
    assert len(s1) == 5
    sources = {s["_raw_alert"]["source"] for s in s1}
    assert sources == {
        "Proofpoint TAP",
        "Microsoft Defender for Endpoint",
        "CrowdStrike Falcon",
        "Zscaler ZIA",
    }
