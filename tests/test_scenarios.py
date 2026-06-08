"""Pinned regressions for the sophisticated multi-source attack scenarios."""

from __future__ import annotations


def test_scenarios_module_loads():
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    assert len(out) == 38, (
        "expected exactly 38 scenario alerts (12 S1-S5 + 10 v2 TEST A-J + 8 v3 DEMO A-H + 3 v4 HASHIR A-C + 5 v5 ENRICH A-E)"
    )
    ids = [s["id"] for s in out]
    assert all(90_000 < i < 90_100 for i in ids)
    assert len(set(ids)) == 38, "scenario IDs must be unique"


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
    assert len(items) == 38
    s1_ids = sorted(s["id"] for s in items if s.get("_scenario_id") == "S1")
    assert s1_ids == [90011, 90012, 90013, 90014, 90015]


def test_scenarios_via_query_param(qradar_client):
    """``?scenarios=all`` on /api/siem/offenses returns all 38 scenarios."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all")
    assert r.status_code == 200
    assert len(r.json()) == 38


def test_scenarios_mix_mode(qradar_client):
    """``?scenarios=mix`` returns scenarios + synthetic templates."""
    c = qradar_client(token="stok")
    r = c.get(
        "/qradar/api/siem/offenses?token=stok&scenarios=mix",
        headers={"Range": "items=0-2"},
    )
    items = r.json()
    assert len(items) >= 41  # 38 scenarios + 3 templates


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


# ── v4 HASHIR scenarios — authorized-pentest recon chain ──────────


def test_hashir_scenarios_present():
    """All 3 HASHIR scenarios (A-C) at offence IDs 90091-90093."""
    from siemulator import scenarios

    hashirs = [
        s
        for s in scenarios.all_scenarios_as_qradar()
        if s.get("_scenario_id", "").startswith("HASHIR-")
    ]
    assert len(hashirs) == 3
    labels = sorted(s["_scenario_id"] for s in hashirs)
    assert labels == ["HASHIR-A", "HASHIR-B", "HASHIR-C"]
    ids = sorted(s["id"] for s in hashirs)
    assert ids == [90091, 90092, 90093]


def test_hashir_share_source_ip_and_actor():
    """All 3 HASHIR alerts share source_ip + actor — load-bearing for
    related_incidents clustering (same_source_ip + same_user anchors)."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    hashirs = [s for s in out if s.get("_scenario_id", "").startswith("HASHIR-")]
    assert len(hashirs) == 3
    actors = {h["_raw_alert"]["actor"]["username"] for h in hashirs}
    source_ips = {h["_raw_alert"]["actor"]["source_ip"] for h in hashirs}
    assert actors == {"HASHIR-VAPT-KHI"}, "all 3 must share actor for Entity Agent"
    assert source_ips == {"10.50.5.42"}, (
        "all 3 must share source_ip for related_incidents same_source_ip anchor"
    )


def test_hashir_target_each_different_host():
    """Each HASHIR alert targets a different production host — the
    chain shape (one actor, one source, three targets) is what makes
    the disposition recommender able to roll all three into one
    authorized-pentest verdict."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    hashirs = [s for s in out if s.get("_scenario_id", "").startswith("HASHIR-")]
    targets = sorted(h["_raw_alert"]["target"]["hostname"] for h in hashirs)
    assert targets == ["WIN-PROD-APP-01", "WIN-PROD-DB-01", "WIN-PROD-WEB-01"]
    target_ips = sorted(h["_raw_alert"]["target"]["ip"] for h in hashirs)
    assert target_ips == ["10.10.20.30", "10.10.20.31", "10.10.20.32"]


def test_hashir_iocs_drive_entity_agent_lookup():
    """Each HASHIR raw alert must declare a user-type IOC with the
    HASHIR-VAPT-KHI value — that's what triggers Entity Agent (Q1)."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    hashirs = [s for s in out if s.get("_scenario_id", "").startswith("HASHIR-")]
    for h in hashirs:
        user_iocs = [
            i for i in h["_raw_alert"]["iocs"] if i["type"] == "user"
        ]
        assert len(user_iocs) == 1, (
            f"{h['_scenario_id']} must have exactly one user-type IOC"
        )
        assert user_iocs[0]["value"] == "HASHIR-VAPT-KHI"


def test_hashir_qradar_categories_override():
    """HASHIR scenarios override the default `Sophisticated-Test`
    category with realistic Port Scan / Network Reconnaissance labels
    so OmniSense routes the iti_category correctly."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    hashirs = [s for s in out if s.get("_scenario_id", "").startswith("HASHIR-")]
    for h in hashirs:
        assert "Sophisticated-Test" not in h["categories"], (
            f"{h['_scenario_id']} should override the default category"
        )
        # At least one of Port Scan / Network Reconnaissance / Suspicious
        # Network Activity must appear
        has_recon_label = any(
            label in h["categories"]
            for label in (
                "Port Scan",
                "Network Reconnaissance",
                "Suspicious Network Activity",
            )
        )
        assert has_recon_label, (
            f"{h['_scenario_id']} categories={h['categories']} lacks any recon label"
        )


def test_hashir_borderline_severity_drives_sev3():
    """Severity=Medium → magnitude=5 → maps to SEV3 in OmniSense.
    Confidence=55-60 → credibility=5-6 → drives s3_score 50-60.
    Pinned so future changes don't accidentally drift the boundary."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    hashirs = [s for s in out if s.get("_scenario_id", "").startswith("HASHIR-")]
    for h in hashirs:
        # Severity 5 in QRadar = Medium = should map to SEV3 in OmniSense
        assert h["severity"] == 5, (
            f"{h['_scenario_id']} severity must be 5 (Medium) to drive SEV3"
        )
        # Credibility derived from confidence//10; for confidence 55-60 → 5-6
        assert h["credibility"] in (5, 6), (
            f"{h['_scenario_id']} credibility={h['credibility']} outside 5-6 range"
        )
        # Expected-verdict pin — drives the "borderline, needs context" shape
        assert h["_raw_alert"]["expected_verdict"] == "VERIFICATION_REQUIRED"
        assert h["_raw_alert"]["expected_disposition"] == "true_positive_benign_authorized"


# ── v5 ENRICH scenarios — real public-TI-confirmed IOCs ──────────


def test_enrich_scenarios_present():
    """All 5 ENRICH scenarios (A-E) at offence IDs 90094-90098."""
    from siemulator import scenarios

    enrichs = [
        s
        for s in scenarios.all_scenarios_as_qradar()
        if s.get("_scenario_id", "").startswith("ENRICH-")
    ]
    assert len(enrichs) == 5
    labels = sorted(s["_scenario_id"] for s in enrichs)
    assert labels == [
        "ENRICH-A", "ENRICH-B", "ENRICH-C", "ENRICH-D", "ENRICH-E",
    ]
    ids = sorted(s["id"] for s in enrichs)
    assert ids == [90094, 90095, 90096, 90097, 90098]


def test_enrich_iocs_all_carry_ti_pattern_tag():
    """Every ENRICH IOC must carry a `ti_*` pattern tag — the discriminator
    that tells downstream consumers this IOC should round-trip to public TI
    (vs DEMO's `synthetic_*` patterns that should be bypassed)."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    enrichs = [s for s in out if s.get("_scenario_id", "").startswith("ENRICH-")]
    for e in enrichs:
        raw = e["_raw_alert"]
        assert "iocs" in raw and raw["iocs"], f"{e['_scenario_id']} has empty iocs"
        for ioc in raw["iocs"]:
            assert "pattern" in ioc, (
                f"{e['_scenario_id']} IOC {ioc.get('value')!r} missing pattern"
            )
            assert ioc["pattern"].startswith("ti_"), (
                f"{e['_scenario_id']} IOC pattern {ioc['pattern']!r} "
                f"must start with `ti_` (real public-TI-attributable)"
            )


def test_enrich_known_wannacry_hash_pinned():
    """ENRICH-A must carry the canonical WannaCry SHA-256. If this hash
    ever changes, the public-TI test fixture stops working — every TI
    feed has this specific hash on file as WannaCry v2."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    enrich_a = next(s for s in out if s["_scenario_id"] == "ENRICH-A")
    iocs = enrich_a["_raw_alert"]["iocs"]
    wannacry_hashes = [
        i for i in iocs if i.get("pattern") == "ti_known_wannacry"
    ]
    assert wannacry_hashes
    assert wannacry_hashes[0]["value"] == (
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    )


def test_enrich_c_has_canonical_eicar_hash():
    """ENRICH-C is the positive-control scenario — must carry the
    universal EICAR SHA-256 (every AV/TI source identifies it)."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    enrich_c = next(s for s in out if s["_scenario_id"] == "ENRICH-C")
    iocs = enrich_c["_raw_alert"]["iocs"]
    eicar_iocs = [i for i in iocs if i.get("pattern") == "ti_eicar_test"]
    assert eicar_iocs
    sha_iocs = [i for i in eicar_iocs if i.get("type") == "hash_sha256"]
    assert sha_iocs[0]["value"] == (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )
    # Disposition for EICAR is benign-test, not full malicious
    assert enrich_c["_raw_alert"]["expected_disposition"] == (
        "true_positive_benign_test"
    )


def test_enrich_d_uses_real_tor_exit_range():
    """ENRICH-D's Tor IP must be in the documented 185.220.101.0/24 Tor
    exit range — that's what GreyNoise + TorProject + AbuseIPDB all
    confirm. Verifies the IP isn't drifted to a non-Tor address."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    enrich_d = next(s for s in out if s["_scenario_id"] == "ENRICH-D")
    iocs = enrich_d["_raw_alert"]["iocs"]
    tor_iocs = [i for i in iocs if i.get("pattern") == "ti_tor_exit_real"]
    assert tor_iocs
    assert tor_iocs[0]["value"].startswith("185.220.101."), (
        f"ENRICH-D Tor IP {tor_iocs[0]['value']!r} must be in 185.220.101.0/24"
    )


def test_enrich_expected_verdicts_span_full_spectrum():
    """The 5 ENRICH scenarios should cover the full disposition spectrum
    so the enrichment pipeline is tested end-to-end:
    - MALICIOUS_CONFIRMED (WannaCry, Stuxnet, EICAR)
    - SUSPICIOUS (Tor egress — needs human review)
    - BENIGN_AUTHORIZED (Shodan scanner — false-positive noise)"""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    enrichs = [s for s in out if s.get("_scenario_id", "").startswith("ENRICH-")]
    verdicts = {e["_raw_alert"]["expected_verdict"] for e in enrichs}
    assert "MALICIOUS_CONFIRMED" in verdicts
    assert "SUSPICIOUS" in verdicts
    assert "BENIGN_AUTHORIZED" in verdicts


def test_enrich_each_declares_expected_ti_sources():
    """Every ENRICH scenario should list which public TI sources are
    expected to confirm the IOCs — that's the test contract the
    enrichment agent's positive path validates against."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    enrichs = [s for s in out if s.get("_scenario_id", "").startswith("ENRICH-")]
    for e in enrichs:
        sources = e["_raw_alert"].get("expected_ti_sources")
        assert sources, f"{e['_scenario_id']} missing expected_ti_sources"
        assert len(sources) >= 1


def test_enrich_vs_demo_pattern_separation():
    """No ENRICH scenario should carry a `synthetic_*` pattern, and no
    DEMO scenario should carry a `ti_*` pattern. The two batches must
    stay cleanly separated so the bypass-vs-enrich routing works."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    enrichs = [s for s in out if s.get("_scenario_id", "").startswith("ENRICH-")]
    demos = [s for s in out if s.get("_scenario_id", "").startswith("DEMO-")]

    for e in enrichs:
        for ioc in e["_raw_alert"]["iocs"]:
            assert not ioc["pattern"].startswith("synthetic_"), (
                f"{e['_scenario_id']} ENRICH should not carry synthetic IOC"
            )
    for d in demos:
        for ioc in d["_raw_alert"]["iocs"]:
            assert not ioc["pattern"].startswith("ti_"), (
                f"{d['_scenario_id']} DEMO should not carry ti_* IOC"
            )
