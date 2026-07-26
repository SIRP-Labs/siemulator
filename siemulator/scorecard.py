"""Coverage + gradeability scorecard for the scenario corpus.

Answers the Alert Generation Brief's §8 acceptance criteria as a
computed report rather than a hand tally:

  - taxonomy coverage across canonical 103-123 + tail (126/169/172)
  - verdict spread + the >=1/3-benign floor
  - per-vendor distribution
  - label-envelope completeness (every alert must be gradeable)
  - real-vs-synthetic IOC lane split

Run as a module for a human report::

    python -m siemulator.scorecard

`coverage()` returns the structured data; `format_report()` renders it.
The companion CI pin (tests/test_scorecard.py) fails the build when a
regression drops coverage below the committed floors — so "is the corpus
still complete?" is answered on every push, not anecdotally.
"""

from __future__ import annotations

from collections import Counter

# Canonical taxonomy the corpus must span (brief §4a). The names are not
# authoritative here — the scorecard reports which *ids* have a test case;
# assigning the right id to an unlabeled scenario needs the real taxonomy
# and is deliberately not done from memory.
CANONICAL_CATEGORIES = list(range(103, 124))   # 103..123
TAIL_CATEGORIES = [126, 169, 172]              # Server Attack / BEC / Cloud Compromise

BENIGN_FLOOR = 1 / 3  # brief §4b: at least a third benign

VENDORS = ("CrowdStrike", "Defender", "QRadar", "NetWitness", "PaloAlto", "Zscaler")


def _vendor_of(source: str) -> str:
    s = (source or "").lower()
    if "crowdstrike" in s or "falcon" in s:
        return "CrowdStrike"
    if "defender" in s:
        return "Defender"
    if "qradar" in s or "wincollect" in s:
        return "QRadar"
    if "netwitness" in s:
        return "NetWitness"
    if "palo" in s:
        return "PaloAlto"
    if "zscaler" in s:
        return "Zscaler"
    return (source or "?").split()[0] if source else "?"


def coverage() -> dict:
    """Compute the full coverage report as structured data."""
    from siemulator.labels import all_labels
    from siemulator.scenarios import SCENARIOS

    labels = all_labels()
    total = len(labels)

    # By scenario_id -> raw, for vendor + IOC lane
    raw_by_oid = {oid: raw for oid, _sid, _lbl, raw in SCENARIOS}

    present_cats = {x["category_id"] for x in labels if x["category_id"] is not None}
    missing_canonical = [c for c in CANONICAL_CATEGORIES if c not in present_cats]
    missing_tail = [c for c in TAIL_CATEGORIES if c not in present_cats]

    assessments = Counter(x["assessment"] or "UNLABELED" for x in labels)
    benign = assessments.get("BENIGN", 0)
    benign_frac = benign / total if total else 0.0

    vendors = Counter(_vendor_of(raw_by_oid[x["offense_id"]].get("source", "")) for x in labels)

    complete = sum(1 for x in labels if x["complete"])
    label_gaps = [x["scenario_id"] for x in labels if not x["complete"]]

    # Real-vs-synthetic IOC lane
    real_lane = synthetic_lane = neither = 0
    for _oid, _sid, _lbl, raw in SCENARIOS:
        pats = {str(i.get("pattern", "")) for i in raw.get("iocs", []) or []}
        has_real = any(p.startswith(("ti_",)) for p in pats)
        has_synth = any(
            p.startswith(("synthetic_", "rfc5737_", "netbios_", "placeholder_"))
            or p in ("fictional", "fictional_c2")
            for p in pats
        )
        if has_real:
            real_lane += 1
        elif has_synth:
            synthetic_lane += 1
        else:
            neither += 1

    return {
        "total": total,
        "taxonomy": {
            "present": sorted(present_cats),
            "missing_canonical": missing_canonical,
            "missing_tail": missing_tail,
            "coverage_pct": round(
                100
                * (len(CANONICAL_CATEGORIES) - len(missing_canonical))
                / len(CANONICAL_CATEGORIES)
            ),
        },
        "verdict_spread": dict(assessments),
        "benign_fraction": round(benign_frac, 3),
        "benign_floor_met": benign_frac >= BENIGN_FLOOR,
        "vendors": dict(vendors),
        "envelope": {
            "complete": complete,
            "incomplete": total - complete,
            "label_gaps": label_gaps,
        },
        "ioc_lanes": {
            "real": real_lane,
            "synthetic": synthetic_lane,
            "neither": neither,
        },
    }


def format_report(cov: dict | None = None) -> str:
    """Render the coverage dict as a human-readable scorecard."""
    c = cov or coverage()
    lines = []
    lines.append(f"SIEMulator corpus scorecard — {c['total']} scenarios")
    lines.append("=" * 52)

    tx = c["taxonomy"]
    lines.append("")
    lines.append(f"Taxonomy: {tx['coverage_pct']}% of canonical 103-123 covered")
    lines.append(f"  present:            {tx['present']}")
    lines.append(f"  MISSING canonical:  {tx['missing_canonical']}")
    lines.append(f"  MISSING tail:       {tx['missing_tail']}")

    lines.append("")
    lines.append(f"Verdict spread (benign floor {BENIGN_FLOOR:.0%}):")
    for k, v in sorted(c["verdict_spread"].items()):
        lines.append(f"  {k:22s} {v:3d}  ({100 * v // c['total']}%)")
    ok = "OK" if c["benign_floor_met"] else "BELOW FLOOR"
    lines.append(f"  benign fraction: {c['benign_fraction']:.0%}  [{ok}]")

    lines.append("")
    lines.append("Per-vendor:")
    for k, v in sorted(c["vendors"].items(), key=lambda kv: -kv[1]):
        lines.append(f"  {k:14s} {v}")

    e = c["envelope"]
    lines.append("")
    lines.append(f"Label envelope: {e['complete']}/{c['total']} complete")
    if e["incomplete"]:
        lines.append(f"  gaps ({e['incomplete']}): {sorted(set(e['label_gaps']))}")

    lanes = c["ioc_lanes"]
    lines.append("")
    lines.append(
        f"IOC lanes: real={lanes['real']}  synthetic={lanes['synthetic']}  "
        f"other={lanes['neither']}"
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_report())
