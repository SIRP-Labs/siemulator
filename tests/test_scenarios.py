"""Pinned regressions for the sophisticated multi-source attack scenarios."""

from __future__ import annotations


def test_scenarios_module_loads():
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    assert len(out) == 30, (
        "expected exactly 30 scenario alerts (12 S1-S5 + 10 v2 TEST A-J + 8 v3 DEMO A-H)"
    )
    ids = [s["id"] for s in out]
    assert all(90_000 < i < 90_100 for i in ids)
    assert len(set(ids)) == 30, "scenario IDs must be unique"


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
    assert len(items) == 30
    s1_ids = sorted(s["id"] for s in items if s.get("_scenario_id") == "S1")
    assert s1_ids == [90011, 90012, 90013, 90014, 90015]


def test_scenarios_via_query_param(qradar_client):
    """``?scenarios=all`` on /api/siem/offenses returns all 30 scenarios."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all")
    assert r.status_code == 200
    assert len(r.json()) == 30


def test_scenarios_mix_mode(qradar_client):
    """``?scenarios=mix`` returns scenarios + synthetic templates."""
    c = qradar_client(token="stok")
    r = c.get(
        "/qradar/api/siem/offenses?token=stok&scenarios=mix",
        headers={"Range": "items=0-2"},
    )
    items = r.json()
    assert len(items) >= 33  # 30 scenarios + 3 templates


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


# ── v3 DEMO scenarios — synthetic-IOC fixtures (sara-open#1083) ──


def test_demo_scenarios_present():
    """All 8 DEMO scenarios (A-H) at offence IDs 90081-90088."""
    from siemulator import scenarios

    demos = [
        s
        for s in scenarios.all_scenarios_as_qradar()
        if s.get("_scenario_id", "").startswith("DEMO-")
    ]
    assert len(demos) == 8
    labels = sorted(s["_scenario_id"] for s in demos)
    assert labels == [
        "DEMO-A", "DEMO-B", "DEMO-C", "DEMO-D",
        "DEMO-E", "DEMO-F", "DEMO-G", "DEMO-H",
    ]
    ids = sorted(s["id"] for s in demos)
    assert ids == list(range(90081, 90089))


def test_demo_scenarios_carry_synthetic_iocs():
    """Each DEMO scenario raw alert must declare its IOCs with a `pattern`
    field — that's what downstream enrichment-bypass code matches on."""
    from siemulator import scenarios

    demos = [
        s
        for s in scenarios.all_scenarios_as_qradar()
        if s.get("_scenario_id", "").startswith("DEMO-")
    ]
    for d in demos:
        raw = d["_raw_alert"]
        assert "iocs" in raw, f"{d['_scenario_id']} missing iocs[]"
        assert raw["iocs"], f"{d['_scenario_id']} has empty iocs[]"
        for ioc in raw["iocs"]:
            assert "pattern" in ioc, (
                f"{d['_scenario_id']} IOC {ioc.get('value')!r} missing `pattern` tag"
            )
    # The four documented synthetic patterns (plus tor_exit_node for DEMO-H)
    # must all be represented across the corpus
    all_patterns = {
        ioc["pattern"]
        for d in demos
        for ioc in d["_raw_alert"]["iocs"]
    }
    expected = {
        "rfc5737_testnet",
        "fictional",
        "placeholder_48char",
        "netbios_internal",
        "tor_exit_node",
    }
    assert expected.issubset(all_patterns), (
        f"missing patterns: {expected - all_patterns}"
    )


def test_demo_a_matches_issue_1083_shape():
    """DEMO-A pins the issue#1083 incident 285759 shape — 107 Malware,
    4 IOCs, BENIGN_AUTHORIZED expected verdict."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    demo_a = next(s for s in out if s["_scenario_id"] == "DEMO-A")
    raw = demo_a["_raw_alert"]
    assert "107 Malware" in raw["category"]
    assert len(raw["iocs"]) == 4
    assert raw["expected_verdict"] == "BENIGN_AUTHORIZED"


def test_demo_h_is_only_demo_with_real_ti_hit():
    """DEMO-H uses a real Tor exit IP — the only IOC in the demo corpus
    that public TI consistently identifies. Pinned so future scenario
    additions don't accidentally regress this."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    demo_h = next(s for s in out if s["_scenario_id"] == "DEMO-H")
    iocs = demo_h["_raw_alert"]["iocs"]
    tor_iocs = [i for i in iocs if i.get("pattern") == "tor_exit_node"]
    assert len(tor_iocs) >= 1

    # And no other DEMO scenario uses the tor_exit_node pattern
    for s in out:
        if (
            s.get("_scenario_id", "").startswith("DEMO-")
            and s["_scenario_id"] != "DEMO-H"
        ):
            for ioc in s["_raw_alert"]["iocs"]:
                assert ioc.get("pattern") != "tor_exit_node"
