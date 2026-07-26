"""CI gate for corpus gradeability + coverage (Alert Generation Brief §8).

These pins turn "is the corpus still complete?" into a build check. The
floors are ratchets: they encode the current committed state and fail if
a change *regresses* coverage. As gaps are filled the floors get raised
in the same commit — they never block an improvement, only a regression.
"""

from __future__ import annotations

from siemulator.labels import all_labels, derive_label
from siemulator.scorecard import coverage

# ── label envelope contract ─────────────────────────────────────────


def test_every_scenario_has_an_envelope():
    """derive_label returns the full envelope schema for every scenario —
    the keys always exist even when their values are None (a label gap)."""
    required = {
        "offense_id", "scenario_id", "category_id", "assessment",
        "severity_band", "is_true_positive", "must_extract_iocs",
        "rationale", "complete",
    }
    for env in all_labels():
        assert required <= set(env), f"{env.get('scenario_id')} missing keys"
        assert isinstance(env["must_extract_iocs"], list)


def test_assessment_is_a_valid_bucket_or_none():
    valid = {"BENIGN", "VERIFICATION_REQUIRED", "MALICIOUS", None}
    for env in all_labels():
        assert env["assessment"] in valid, (
            f"{env['scenario_id']} bad assessment {env['assessment']!r}"
        )


def test_severity_band_is_sev1_to_5_or_none():
    valid = {"SEV1", "SEV2", "SEV3", "SEV4", "SEV5", None}
    for env in all_labels():
        assert env["severity_band"] in valid


def test_is_true_positive_tracks_assessment():
    """Benign -> not a true positive; verification/malicious -> true
    positive; unknown assessment -> unknown."""
    for env in all_labels():
        if env["assessment"] == "BENIGN":
            assert env["is_true_positive"] is False
        elif env["assessment"] in ("VERIFICATION_REQUIRED", "MALICIOUS"):
            assert env["is_true_positive"] is True
        else:
            assert env["is_true_positive"] is None


def test_complete_requires_category_assessment_severity():
    for env in all_labels():
        expect = (
            env["category_id"] is not None
            and env["assessment"] is not None
            and env["severity_band"] is not None
        )
        assert env["complete"] is expect


def test_derive_label_reads_leading_category_from_string():
    """Category resolves from the leading NNN of the `category` field when
    no explicit expected id is present."""
    env = derive_label(1, "X", "108 Phishing — something",
                       {"category": "108 Phishing"})
    assert env["category_id"] == 108


def test_derive_label_prefers_explicit_expected_id():
    env = derive_label(1, "X", "108 label",
                       {"category": "108 Phishing",
                        "expected_iti_category_id": 111})
    assert env["category_id"] == 111


# ── coverage ratchets (raise these as gaps are filled) ──────────────


def test_taxonomy_coverage_floor():
    """At least the currently-covered canonical categories stay covered."""
    tx = coverage()["taxonomy"]
    covered = set(tx["present"])
    floor = {107, 108, 109, 110, 111, 112, 114, 117, 118, 119}
    missing = floor - covered
    assert not missing, f"regressed taxonomy coverage: {sorted(missing)}"


def test_complete_envelope_floor():
    """No fewer complete (fully-labeled) scenarios than the committed floor."""
    assert coverage()["envelope"]["complete"] >= 32


def test_benign_case_floor():
    """Benign cases don't drop below the committed count (brief §4b wants
    this climbing toward 1/3)."""
    assert coverage()["verdict_spread"].get("BENIGN", 0) >= 6


def test_real_ioc_lane_floor():
    """The real-abuse.ch-IOC lane stays populated so enrichment keeps
    being exercised end-to-end."""
    assert coverage()["ioc_lanes"]["real"] >= 15


def test_scorecard_report_renders():
    from siemulator.scorecard import format_report

    report = format_report()
    assert "corpus scorecard" in report
    assert "Taxonomy" in report and "Verdict spread" in report


# ── out-of-band label delivery (brief §3) ───────────────────────────


def test_encode_decode_labels_header_roundtrips():
    from siemulator.labels import (
        decode_labels_header,
        encode_labels_header,
        labels_by_offense_id,
    )

    oids = list(labels_by_offense_id())[:5]
    hdr = encode_labels_header(oids)
    decoded = decode_labels_header(hdr)
    assert set(decoded) == {str(o) for o in oids}
    for o in oids:
        assert decoded[str(o)]["offense_id"] == o


def test_strip_answer_key_removes_grading_fields_keeps_iocs():
    from siemulator.labels import strip_answer_key

    alert = {
        "id": 1, "iocs": [{"value": "x"}],
        "_test_meta": {"expected_verdict": "MALICIOUS"},
        "test_notes": "why",
        "expected_iti_category_id": 107,
        "expected_verdict": "MALICIOUS_CONFIRMED",
        "_raw_alert": {"_test_meta": {}, "expected_severity": "SEV1", "iocs": []},
    }
    out = strip_answer_key(alert)
    assert "_test_meta" not in out
    assert "test_notes" not in out
    assert not any(k.startswith("expected_") for k in out)
    assert out["iocs"] == [{"value": "x"}]      # IOCs preserved
    assert "_test_meta" not in out["_raw_alert"]  # recurses
    assert not any(k.startswith("expected_") for k in out["_raw_alert"])


def test_qradar_emits_labels_header(qradar_client):
    from siemulator.labels import decode_labels_header

    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=replay")
    assert "X-Mock-Labels" in r.headers
    decoded = decode_labels_header(r.headers["X-Mock-Labels"])
    # every curated offence id in the body has a label envelope
    body_ids = {str(a["id"]) for a in r.json() if 90_010 < a["id"] < 90_200}
    assert body_ids <= set(decoded)
    # and the envelope carries the gradeable fields
    sample = next(iter(decoded.values()))
    assert {"category_id", "assessment", "severity_band"} <= set(sample)


def test_qradar_strip_removes_answer_key_from_body(qradar_client):
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=replay&labels=strip")
    assert "X-Mock-Labels" in r.headers   # header still present
    for a in r.json():
        raw = a.get("_raw_alert", {})
        assert "_test_meta" not in raw, f"{a.get('id')} leaked _test_meta in body"
        assert not any(k.startswith("expected_") for k in raw)


def test_qradar_default_keeps_answer_key_in_body(qradar_client):
    """Backward-compat: without ?labels=strip the body is unchanged, so
    the live grep-based grading keeps working until graders migrate."""
    c = qradar_client(token="stok")
    r = c.get("/qradar/api/siem/offenses?token=stok&scenarios=replay")
    metas = [a for a in r.json() if a.get("_raw_alert", {}).get("_test_meta")]
    assert metas, "expected _test_meta still present in body by default"
