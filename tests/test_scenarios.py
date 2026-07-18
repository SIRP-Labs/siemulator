"""Pinned regressions for the sophisticated multi-source attack scenarios."""

from __future__ import annotations


def test_scenarios_module_loads():
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    assert len(out) == 57, (
        "expected exactly 38 scenario alerts (12 S1-S5 + 10 v2 TEST A-J + 8 v3 DEMO A-H + 3 v4 SCAN A-C + 5 v5 ENRICH A-E)"
    )
    ids = [s["id"] for s in out]
    assert all(90_000 < i < 90_200 for i in ids)
    assert len(set(ids)) == 57, "scenario IDs must be unique"


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
    assert len(items) == 57
    s1_ids = sorted(s["id"] for s in items if s.get("_scenario_id") == "S1")
    assert s1_ids == [90011, 90012, 90013, 90014, 90015]


def test_scenarios_via_query_param(qradar_client):
    """``?scenarios=all`` returns all 57 curated + 500 random noise by default."""
    c = qradar_client(token="stok")
    from siemulator.qradar import _SCENARIOS_SERVED
    _SCENARIOS_SERVED.clear()
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all&extras=0")
    assert r.status_code == 200
    assert len(r.json()) == 57


def test_scenarios_mix_mode(qradar_client):
    """``?scenarios=mix`` returns scenarios + synthetic templates."""
    c = qradar_client(token="stok")
    r = c.get(
        "/qradar/api/siem/offenses?token=stok&scenarios=mix",
        headers={"Range": "items=0-2"},
    )
    items = r.json()
    assert len(items) >= 60  # 57 scenarios + 3 templates


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


# ── v3 DEMO scenarios — synthetic-IOC fixtures (bypass-detector positive cases) ──


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


def test_demo_a_shape():
    """DEMO-A is the BENIGN_AUTHORIZED malware fixture — 107 Malware,
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


# ── v4 SCAN scenarios — authorized-pentest recon chain ──────────


def test_scan_scenarios_present():
    """All 3 SCAN scenarios (A-C) at offence IDs 90091-90093."""
    from siemulator import scenarios

    scans = [
        s
        for s in scenarios.all_scenarios_as_qradar()
        if s.get("_scenario_id", "").startswith("SCAN-")
    ]
    assert len(scans) == 3
    labels = sorted(s["_scenario_id"] for s in scans)
    assert labels == ["SCAN-A", "SCAN-B", "SCAN-C"]
    ids = sorted(s["id"] for s in scans)
    assert ids == [90091, 90092, 90093]


def test_scan_share_source_ip_and_actor():
    """All 3 SCAN alerts share source_ip + actor — load-bearing for
    related_incidents clustering (same_source_ip + same_user anchors)."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    scans = [s for s in out if s.get("_scenario_id", "").startswith("SCAN-")]
    assert len(scans) == 3
    actors = {h["_raw_alert"]["actor"]["username"] for h in scans}
    source_ips = {h["_raw_alert"]["actor"]["source_ip"] for h in scans}
    assert actors == {"SECTEAM\\pentester-01"}, "all 3 must share actor for Entity Agent"
    assert source_ips == {"10.50.5.42"}, (
        "all 3 must share source_ip for related_incidents same_source_ip anchor"
    )


def test_scan_target_each_different_host():
    """Each SCAN alert targets a different production host — the
    chain shape (one actor, one source, three targets) is what makes
    the disposition recommender able to roll all three into one
    authorized-pentest verdict."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    scans = [s for s in out if s.get("_scenario_id", "").startswith("SCAN-")]
    targets = sorted(h["_raw_alert"]["target"]["hostname"] for h in scans)
    assert targets == ["WIN-PROD-APP-01", "WIN-PROD-DB-01", "WIN-PROD-WEB-01"]
    target_ips = sorted(h["_raw_alert"]["target"]["ip"] for h in scans)
    assert target_ips == ["10.10.20.30", "10.10.20.31", "10.10.20.32"]


def test_scan_iocs_drive_entity_agent_lookup():
    """Each SCAN raw alert must declare a user-type IOC with the
    SECTEAM\\pentester-01 value — that's what triggers Entity Agent (Q1)."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    scans = [s for s in out if s.get("_scenario_id", "").startswith("SCAN-")]
    for h in scans:
        user_iocs = [
            i for i in h["_raw_alert"]["iocs"] if i["type"] == "user"
        ]
        assert len(user_iocs) == 1, (
            f"{h['_scenario_id']} must have exactly one user-type IOC"
        )
        assert user_iocs[0]["value"] == "SECTEAM\\pentester-01"


def test_scan_qradar_categories_override():
    """SCAN scenarios override the default `Sophisticated-Test`
    category with realistic Port Scan / Network Reconnaissance labels
    so consumers route the category correctly."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    scans = [s for s in out if s.get("_scenario_id", "").startswith("SCAN-")]
    for h in scans:
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


def test_scan_borderline_severity_drives_sev3():
    """Severity=Medium → magnitude=5 → maps to SEV3 in a typical consumer.
    Confidence=55-60 → credibility=5-6 → drives s3_score 50-60.
    Pinned so future changes don't accidentally drift the boundary."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    scans = [s for s in out if s.get("_scenario_id", "").startswith("SCAN-")]
    for h in scans:
        # Severity 5 in QRadar = Medium = should map to SEV3 in a typical consumer
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


# ── v6 SIEM-shape scenarios — _test_meta block for deterministic grading ──


def test_v6_scenarios_carry_test_meta():
    """Every v6 scenario (offence IDs 90101-90114) must carry a top-level
    `_test_meta` block with test_payload_id / expected_verdict /
    expected_category_id / expected_guardrails_that_should_fire /
    expected_vendor_semantics. Faiz uses these to match ingested incidents
    back to their source payload deterministically rather than guessing
    from Planner hypothesis text."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    v6 = [s for s in out if 90101 <= s["id"] <= 90114]
    assert len(v6) == 14, f"expected 14 v6 scenarios, got {len(v6)}"

    required_keys = {
        "test_payload_id",
        "expected_verdict",
        "expected_category_id",
        "expected_guardrails_that_should_fire",
        "expected_vendor_semantics",
    }
    for s in v6:
        raw = s["_raw_alert"]
        assert "_test_meta" in raw, f"{s['_scenario_id']} missing _test_meta"
        meta = raw["_test_meta"]
        missing = required_keys - set(meta.keys())
        assert not missing, f"{s['_scenario_id']} _test_meta missing keys: {missing}"
        # test_payload_id must be a stable slug — used as a grep key
        assert meta["test_payload_id"].startswith("P"), (
            f"{s['_scenario_id']} test_payload_id must be P<n>_... slug"
        )
        # guardrails + vendor semantics must be non-empty lists
        assert isinstance(meta["expected_guardrails_that_should_fire"], list)
        assert isinstance(meta["expected_vendor_semantics"], list)
        assert meta["expected_vendor_semantics"], (
            f"{s['_scenario_id']} needs at least one vendor semantic"
        )


def test_v6_test_payload_ids_are_unique():
    """test_payload_id must uniquely identify a scenario — that's what
    makes cross-referencing an ingested incident to its source payload
    deterministic."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    v6 = [s for s in out if 90101 <= s["id"] <= 90114]
    ids = [s["_raw_alert"]["_test_meta"]["test_payload_id"] for s in v6]
    assert len(ids) == len(set(ids)), f"duplicate test_payload_ids: {ids}"


def test_v6_category_ids_match_guardrail_intent():
    """Load-bearing category-id pins: negative-tests (never-classify-as-X)
    must ingest under the correct category so the guardrail actually
    gets exercised on the right code path."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    by_sid = {s["_scenario_id"]: s for s in out}

    # TRELLIX-A must ingest as 111 (Endpoint Defense Evasion), NOT 107,
    # so never_ransomware_without_cat107_encryption is exercised on
    # the correct category path.
    assert by_sid["TRELLIX-A"]["_raw_alert"]["expected_iti_category_id"] == 111

    # RANSOM-D (locky.exe filename FP) must ingest as 111, NOT 107 —
    # the whole point is that filename alone must not classify Ransomware.
    assert by_sid["RANSOM-D"]["_raw_alert"]["expected_iti_category_id"] == 111

    # RANSOM-A must ingest as 107 (positive Ransomware baseline —
    # all four required-evidence signals present).
    assert by_sid["RANSOM-A"]["_raw_alert"]["expected_iti_category_id"] == 107


def test_v6_literal_field_values_preserved():
    """Load-bearing literal strings that specific guardrails match on.
    Paraphrasing these regresses the test — the guardrail wouldn't
    fire on a paraphrased shape even though the shape looks right."""
    from siemulator import scenarios

    out = scenarios.all_scenarios_as_qradar()
    by_sid = {s["_scenario_id"]: s for s in out}

    trellix_body = by_sid["TRELLIX-A"]["_raw_alert"]["raw_log"]["body"]
    assert "xagt.exe" in trellix_body
    assert r"C:\Users\Public\secur32.dll" in trellix_body
    assert "Host Agent Cert Hash" in trellix_body
    assert "WORKSTATION-CORPS-04" in trellix_body
    assert "FireEye" in trellix_body

    win_body = by_sid["WIN-4672"]["_raw_alert"]["raw_log"]["body"]
    assert "EventID=4672" in win_body
    assert "PKHBLC5EX-11$" in win_body
    assert "Domain=CORP" in win_body
    assert "LogonType=3" in win_body
    for priv in ("SeSecurityPrivilege", "SeBackupPrivilege",
                 "SeDebugPrivilege", "SeImpersonatePrivilege"):
        assert priv in win_body, f"WIN-4672 missing privilege: {priv}"

    ransom_a_parsed = by_sid["RANSOM-A"]["_raw_alert"]["parsed"]
    assert ransom_a_parsed["file_mass_encryption"] is True
    assert ransom_a_parsed["shadow_copy_deletion"] is True
    assert ransom_a_parsed["ransom_note_dropped"] == "READMEDEC.txt"

    ransom_d_parsed = by_sid["RANSOM-D"]["_raw_alert"]["parsed"]
    assert "locky.exe" in ransom_d_parsed["process"]["filename"]
    b = ransom_d_parsed["behaviors"]
    assert b["file_mass_encryption"] is False
    assert b["shadow_copy_deletion"] is False
    assert b["ransom_note_dropped"] is None
    assert b["file_mass_rename"] is False

    benign_body = by_sid["BENIGN-C2-A"]["_raw_alert"]["parsed"]["process"]["cmdline"]
    assert benign_body == "svchost.exe -k netsvcs -s wuauserv"

    dns_a = by_sid["PA-DNS-A"]["_raw_alert"]["parsed"]
    assert dns_a["dst"] == "8.8.8.8"
    assert dns_a["action"] == "sinkhole"
    assert dns_a["misc_queried_domain"] == "suspicious.malware-family.example"

    dns_c2 = by_sid["DNS-C2-A"]["_raw_alert"]["parsed"]
    assert dns_c2["misc_queried_domain"] == "cobaltstrike-c2-known.badactor.example"
    assert dns_c2["cardinality_signals"]["queries_observed_last_60s"] == 1


# ── ?extras=<N> — appends N randomised synthetic offences ──────────


def test_scenarios_all_with_extras_appends_random(qradar_client):
    from siemulator.qradar import _SCENARIOS_SERVED
    _SCENARIOS_SERVED.clear()
    """``?scenarios=all&extras=20`` returns the 57 curated + 20 random
    synthetic offences in a single poll. Randomised offences are drawn
    from ALERT_TEMPLATES with per-call random host / user / IP /
    offence_id — they're noise to fill the pool, not test fixtures."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all&extras=20")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 57 + 20
    # Curated 52 come first, extras tail after
    curated = [i for i in items if 90_010 < i["id"] < 90_120]
    extras = [i for i in items if i["id"] > 30_000 and i["id"] < 30_000_000 and not (90_010 < i["id"] < 90_120)]
    assert len(curated) == 57
    assert len(extras) == 20
    # The extras carry x-mock-source but no _scenario_id (they're not curated scenarios)
    assert all(e.get("_scenario_id") is None for e in extras)


def test_scenarios_all_extras_cap(qradar_client):
    from siemulator.qradar import _SCENARIOS_SERVED
    _SCENARIOS_SERVED.clear()
    """extras is capped at 1000 — larger values silently truncate."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all&extras=1500")
    items = r.json()
    assert len(items) == 57 + 1000


def test_scenarios_batch_with_extras(qradar_client):
    """``?scenarios=batch&extras=5`` returns 1 rotated scenario + 5 random."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=batch&extras=5")
    items = r.json()
    assert len(items) == 7


def test_scenarios_all_default_returns_curated_only(qradar_client):
    """``?scenarios=all`` with no extras= param returns just the 57
    curated scenarios — extras is opt-in only after the runaway-flood
    incident (was: 500 baked in by default)."""
    from siemulator.qradar import _SCENARIOS_SERVED
    _SCENARIOS_SERVED.clear()
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all")
    items = r.json()
    assert len(items) == 57


def test_scenarios_all_extras_zero_returns_bare_curated(qradar_client):
    from siemulator.qradar import _SCENARIOS_SERVED
    _SCENARIOS_SERVED.clear()
    """``?scenarios=all&extras=0`` opts out of the default 500 noise,
    returning just the curated pool."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=all&extras=0")
    items = r.json()
    assert len(items) == 57


# ── Vendor-native endpoints ───────────────────────────────────────


def _vendor_client():
    import os
    os.environ["SIEMULATOR_CROWDSTRIKE_TOKEN"] = ""
    os.environ["SIEMULATOR_DEFENDER_TOKEN"] = ""
    os.environ["SIEMULATOR_NETWITNESS_TOKEN"] = ""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from siemulator.vendor_native import build_router
    app = FastAPI()
    app.include_router(build_router(token_getter=lambda v: ""))
    return TestClient(app)


def test_crowdstrike_endpoint_returns_alerts_v2_envelope():
    """Both Falcon paths return the DetectsapiPostEntitiesAlertsV2Response
    envelope — meta (with pagination + writes) / resources / errors."""
    c = _vendor_client()
    for path in ("/alerts/entities/alerts/v2", "/crowdstrike/api/v1/detects"):
        r = c.get(f"{path}?scenarios=replay")
        assert r.status_code == 200, path
        body = r.json()
        assert set(body.keys()) >= {"meta", "resources", "errors"}, path
        meta = body["meta"]
        for k in ("query_time", "powered_by", "trace_id", "pagination", "writes"):
            assert k in meta, f"{path} meta missing {k!r}"
        for k in ("limit", "offset", "total"):
            assert k in meta["pagination"], f"{path} pagination missing {k!r}"
        assert body["resources"], f"{path} returned no alerts"
        r0 = body["resources"][0]
        # No QRadar wrapper leakage
        assert "offense_source" not in r0
        assert "log_sources" not in r0


def test_crowdstrike_alert_uses_detects_alert_field_names():
    """Resources follow CrowdStrike's DetectsAlert model: composite_id
    identity, int severity 0-100 alongside severity_name, flat ATT&CK
    fields plus mitre_attack[], and Falcon's process/host/user names."""
    c = _vendor_client()
    a = c.get("/alerts/entities/alerts/v2?scenarios=replay").json()["resources"][0]

    # Identity — composite_id is <cid>:ind:<agent_id>:<local>
    assert isinstance(a["composite_id"], str)
    parts = a["composite_id"].split(":")
    assert len(parts) == 4 and parts[1] == "ind", a["composite_id"]
    assert a["id"] == a["composite_id"]
    assert len(a["agent_id"]) == 32
    assert len(a["cid"]) == 32
    assert a["aggregate_id"].startswith("aggind:")

    # Scoring — severity is the 0-100 int, band mirrored in severity_name
    assert isinstance(a["severity"], int) and 0 <= a["severity"] <= 100
    assert a["severity_name"] in (
        "Critical", "High", "Medium", "Low", "Informational"
    )
    assert isinstance(a["confidence"], int)

    # Classification + triage
    assert a["product"] == "epp"
    assert a["type"] == "ldt"
    assert isinstance(a["pattern_id"], int)
    assert a["status"] == "new"
    assert a["show_in_ui"] is True

    # ATT&CK appears flat and structured
    for k in ("tactic", "tactic_id", "technique", "technique_id", "objective"):
        assert k in a, f"missing {k}"
    assert isinstance(a["mitre_attack"], list)

    # Falcon's own process / host / user field names
    for k in ("filename", "filepath", "cmdline", "sha256", "md5",
              "hostname", "local_ip", "platform", "user_name",
              "logon_domain", "device_id", "falcon_host_link"):
        assert k in a, f"missing Falcon field {k}"

    # Provenance
    assert a["source_vendors"] == ["CrowdStrike"]
    assert a["source_products"] == ["Falcon Insight"]
    assert a["data_domains"] == ["Endpoint"]


def test_crowdstrike_paging_honours_limit_offset():
    """limit / offset slice resources and are echoed in meta.pagination
    with the unsliced total."""
    c = _vendor_client()
    body = c.get("/alerts/entities/alerts/v2?scenarios=replay&limit=2&offset=0").json()
    assert len(body["resources"]) <= 2
    assert body["meta"]["pagination"]["limit"] == 2
    assert body["meta"]["pagination"]["offset"] == 0
    assert body["meta"]["pagination"]["total"] >= len(body["resources"])


def test_defender_endpoint_returns_graph_envelope():
    """/defender/api/security/v1.0/alerts returns Graph Security shape
    ({@odata.context, value})."""
    c = _vendor_client()
    r = c.get("/defender/api/security/v1.0/alerts?scenarios=replay")
    assert r.status_code == 200
    body = r.json()
    assert "@odata.context" in body
    assert "graph.microsoft.com" in body["@odata.context"]
    assert isinstance(body["value"], list)
    assert body["value"], "no Defender scenarios matched"
    for alert in body["value"]:
        assert "defender" in alert["source"].lower()


def test_netwitness_endpoint_returns_respond_envelope():
    """Both NetWitness paths return the documented Respond paging
    envelope: items[] plus the full pageNumber/pageSize/totalPages/
    totalItems/hasNext/hasPrevious set."""
    c = _vendor_client()
    for path in ("/rest/api/incidents", "/netwitness/api/v1/incidents"):
        r = c.get(f"{path}?scenarios=replay")
        assert r.status_code == 200, path
        body = r.json()
        for k in ("items", "pageNumber", "pageSize", "totalPages",
                  "totalItems", "hasNext", "hasPrevious"):
            assert k in body, f"{path} missing envelope key {k!r}"
        assert body["totalItems"] == len(body["items"])
        assert body["items"], f"{path} returned no incidents"
        assert any("netwitness" in i["source"].lower() for i in body["items"])


def test_netwitness_incident_uses_respond_field_names():
    """Incident objects follow the Respond schema — INC- string id,
    title/detail rather than a nested alert{}, riskScore+priority
    rather than a severity label, and entities under events[]."""
    c = _vendor_client()
    inc = c.get("/rest/api/incidents?scenarios=replay").json()["items"][0]

    assert isinstance(inc["id"], str) and inc["id"].startswith("INC-")
    assert inc["title"], "title must carry the human-readable name"
    assert inc["detail"], "detail must carry the description"
    assert isinstance(inc["riskScore"], int)
    assert 0 <= inc["riskScore"] <= 100
    assert inc["priority"] in ("Low", "Medium", "High", "Critical")
    assert inc["status"] == "New"
    assert isinstance(inc["alertCount"], int)

    assert isinstance(inc["events"], list) and inc["events"]
    ev = inc["events"][0]
    assert "source" in ev and "destination" in ev
    assert "device" in ev["source"] and "device" in ev["destination"]
    # esrc/edst from the raw packet meta land on the right side
    assert ev["source"]["device"]["ipAddress"] == "10.20.30.42"
    assert ev["destination"]["device"]["ipAddress"] == "192.0.2.77"


def test_netwitness_paging_honours_page_params():
    """pageSize / pageNumber slice the pool and drive the has*/total
    flags, matching Respond's paging contract."""
    c = _vendor_client()
    body = c.get("/rest/api/incidents?scenarios=replay&pageSize=1&pageNumber=0").json()
    assert body["pageSize"] == 1
    assert body["pageNumber"] == 0
    assert len(body["items"]) <= 1
    assert body["hasPrevious"] is False
    # With one incident in the pool there is exactly one page
    assert body["totalPages"] == body["totalItems"]
    assert body["hasNext"] is (body["totalPages"] > 1)


def test_vendor_endpoints_scenarios_batch_rotates():
    """?scenarios=batch on a vendor endpoint returns one alert at a time
    and rotates through the vendor's scenario pool."""
    c = _vendor_client()
    # Reset first
    c.post("/_debug/reset_vendor?vendor=crowdstrike")
    seen = set()
    for _ in range(20):
        r = c.get("/alerts/entities/alerts/v2?scenarios=batch")
        for res in r.json()["resources"]:
            seen.add(res.get("_offense_id"))
    assert len(seen) >= 2, "batch mode should rotate through CrowdStrike pool"


def test_vendor_endpoints_no_qradar_shape_leaks():
    """None of the vendor-native endpoints should ever emit QRadar
    offence-wrapper keys (id, offense_id, offense_source, log_sources)
    on their alert payloads."""
    c = _vendor_client()
    for path, key in (
        ("/alerts/entities/alerts/v2?scenarios=replay", "resources"),
        ("/defender/api/security/v1.0/alerts?scenarios=replay", "value"),
        ("/rest/api/incidents?scenarios=replay", "items"),
    ):
        r = c.get(path)
        for alert in r.json()[key]:
            for banned in ("offense_source", "log_sources", "magnitude",
                           "credibility", "relevance", "source_address_ids"):
                assert banned not in alert, (
                    f"{path} leaked QRadar field {banned!r} in payload"
                )


def test_vendor_alerts_carry_portable_id_and_start_time():
    """Every vendor payload must expose an int alert id and an int
    ms-epoch `start_time`, so consumers written against the QRadar
    shape contract work unchanged.

    Falcon and Graph Security can carry the int directly on `id`.
    NetWitness cannot — Respond's `id` is the `INC-<n>` string — so
    there the int lives on `_offense_id`. Consumers should read
    `id` when it is an int and fall back to `_offense_id`.
    """
    c = _vendor_client()
    for path, key in (
        ("/alerts/entities/alerts/v2?scenarios=replay", "resources"),
        ("/defender/api/security/v1.0/alerts?scenarios=replay", "value"),
        ("/rest/api/incidents?scenarios=replay", "items"),
    ):
        alerts = c.get(path).json()[key]
        assert alerts, f"{path} returned no alerts"
        for a in alerts:
            portable = a["id"] if isinstance(a.get("id"), int) else a.get("_offense_id")
            assert isinstance(portable, int), (
                f"{path}: no int id on `id` or `_offense_id`"
            )
            st = a.get("start_time")
            assert isinstance(st, int) and st > 1_000_000_000_000, (
                f"{path}: start_time must be int ms-epoch, got {st!r}"
            )


def test_vendor_alerts_carry_vendor_canonical_id_fields():
    """Each vendor gets its own canonical identity + timestamp field
    names, so a vendor-specific parser finds what it expects."""
    c = _vendor_client()
    cases = (
        ("/alerts/entities/alerts/v2?scenarios=replay", "resources",
         "composite_id", "created_timestamp"),
        ("/defender/api/security/v1.0/alerts?scenarios=replay", "value",
         "id", "createdDateTime"),
        ("/rest/api/incidents?scenarios=replay", "items",
         "id", "created"),
    )
    for path, key, id_field, ts_field in cases:
        alerts = c.get(path).json()[key]
        assert alerts, f"{path} returned no alerts"
        for a in alerts:
            assert id_field in a, f"{path}: missing {id_field}"
            assert ts_field in a, f"{path}: missing {ts_field}"


def test_iso_to_ms_epoch_conversion():
    """Timestamp conversion produces a valid 13-digit ms epoch, and
    degrades to a valid sentinel rather than 0 on unparseable input."""
    from siemulator.vendor_native import _iso_to_ms_epoch

    ms = _iso_to_ms_epoch("2026-07-05T04:15:22Z")
    assert ms > 1_000_000_000_000
    # Unparseable input still yields a valid ms-epoch (never 0/None),
    # so the downstream shape check can't be tripped by bad data.
    for bad in ("", "not-a-date", None):
        assert _iso_to_ms_epoch(bad) > 1_000_000_000_000


def test_vendor_prefixes_are_access_log_bound():
    """Vendor paths must be in bound_prefixes — otherwise a consumer
    polling /crowdstrike/* is invisible in /api/access-log, which is
    the surface used to confirm ingestion is happening."""
    import inspect

    from siemulator import app as app_mod

    src = inspect.getsource(app_mod.create_app)
    assert '"/crowdstrike"' in src
    assert '"/defender"' in src
    assert '"/netwitness"' in src
    assert '"/rest"' in src
    assert '"/alerts"' in src
