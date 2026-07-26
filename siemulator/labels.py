"""Ground-truth label envelope for the scenario corpus.

SIEMulator's whole point is being a *gradeable* corpus: every alert must
carry a machine-readable answer key so OmniStream (parse/category) and
SARA (enrich/classify/respond) can be scored against it automatically.
See the Alert Generation Brief §3.

The envelope schema (brief §3)::

    {
      "category_id":       int | None,     # None == label gap (not yet assigned)
      "assessment":        "BENIGN" | "VERIFICATION_REQUIRED" | "MALICIOUS" | None,
      "severity_band":     "SEV1".."SEV5" | None,
      "is_true_positive":  bool | None,
      "must_extract_iocs": [str, ...],     # artifacts OmniStream must surface
      "rationale":         str,            # why this is the right answer
      "complete":          bool,           # all gradeable fields present
    }

Ground truth is currently scattered across four places with inconsistent
presence — ``expected_iti_category_id``, ``_test_meta.expected_category_id``,
the leading ``NNN`` in the ``category`` string, and the leading ``NNN`` in
the registry label — plus ``expected_verdict`` / ``expected_iti_attack_severity``.
``derive_label`` normalises all of that into the single envelope above.

IMPORTANT — no fabrication. Where a scenario carries no category or verdict
signal (the S1-S5 / TEST-A-J narratives do not), the corresponding field is
left ``None`` and ``complete`` is ``False``. Those are real label gaps to be
filled with the authoritative taxonomy, NOT guessed — a wrong answer key
silently fails every grade that uses it.
"""

from __future__ import annotations

import re

_LEADING_CAT = re.compile(r"^\s*(\d{3})\b")

# expected_verdict vocabulary -> the brief's three assessment buckets.
_ASSESSMENT = {
    "BENIGN": "BENIGN",
    "BENIGN_AUTHORIZED": "BENIGN",
    "VERIFICATION_REQUIRED": "VERIFICATION_REQUIRED",
    "SUSPICIOUS": "VERIFICATION_REQUIRED",
    "TP_LIKELY": "MALICIOUS",
    "MALICIOUS": "MALICIOUS",
    "MALICIOUS_CONFIRMED": "MALICIOUS",
}

_SEV_RE = re.compile(r"SEV[1-5]", re.IGNORECASE)


def _first_category(raw: dict, label: str) -> int | None:
    """Resolve the ground-truth category id from the highest-confidence
    signal available, or None if the scenario declares none."""
    meta = raw.get("_test_meta") or {}
    for candidate in (
        raw.get("expected_iti_category_id"),
        meta.get("expected_category_id"),
    ):
        if isinstance(candidate, int):
            return candidate
    for text in (str(raw.get("category", "")), str(label or "")):
        m = _LEADING_CAT.match(text)
        if m:
            return int(m.group(1))
    return None


def _assessment(raw: dict) -> str | None:
    meta = raw.get("_test_meta") or {}
    vd = str(raw.get("expected_verdict") or meta.get("expected_verdict") or "").upper()
    return _ASSESSMENT.get(vd)


def _severity_band(raw: dict) -> str | None:
    for candidate in (
        raw.get("expected_iti_attack_severity"),
        raw.get("expected_severity"),
        (raw.get("_test_meta") or {}).get("expected_severity"),
    ):
        if candidate:
            m = _SEV_RE.search(str(candidate))
            if m:
                return m.group(0).upper()
    return None


def _must_extract_iocs(raw: dict) -> list[str]:
    """The IOC values OmniStream must surface for this alert. Internal /
    resolver-role indicators (tagged ``internal_*`` / ``*_not_c2`` /
    ``public_dns_resolver*``) are excluded — they are context, not the
    artifacts a grader checks extraction against."""
    out = []
    for ioc in raw.get("iocs", []) or []:
        pat = str(ioc.get("pattern", ""))
        if pat.startswith("internal_") or "resolver" in pat or pat.endswith("_not_c2"):
            continue
        val = ioc.get("value")
        if val and val not in out:
            out.append(val)
    return out


def _rationale(raw: dict, label: str) -> str:
    meta = raw.get("_test_meta") or {}
    for candidate in (
        raw.get("test_notes"),
        (raw.get("alert") or {}).get("description"),
        (raw.get("detection") or {}).get("description"),
        meta.get("test_payload_id"),
        label,
    ):
        if candidate:
            return str(candidate)
    return ""


def derive_label(offense_id: int, sid: str, label: str, raw: dict) -> dict:
    """Normalise a scenario's scattered ground-truth signals into the
    single envelope schema documented at the top of this module."""
    category = _first_category(raw, label)
    assessment = _assessment(raw)
    severity = _severity_band(raw)

    # is_true_positive: a benign alert is not a true positive; anything
    # requiring verification or confirmed malicious is. Unknown when the
    # assessment itself is unknown.
    if assessment == "BENIGN":
        is_tp: bool | None = False
    elif assessment in ("VERIFICATION_REQUIRED", "MALICIOUS"):
        is_tp = True
    else:
        is_tp = None

    complete = (
        category is not None
        and assessment is not None
        and severity is not None
    )

    return {
        "offense_id": offense_id,
        "scenario_id": sid,
        "category_id": category,
        "assessment": assessment,
        "severity_band": severity,
        "is_true_positive": is_tp,
        "must_extract_iocs": _must_extract_iocs(raw),
        "rationale": _rationale(raw, label),
        "complete": complete,
    }


def all_labels() -> list[dict]:
    """Derive the label envelope for every scenario in the registry."""
    from siemulator.scenarios import SCENARIOS

    return [derive_label(oid, sid, label, raw) for oid, sid, label, raw in SCENARIOS]


def labels_by_offense_id() -> dict[int, dict]:
    """{offense_id: envelope} for every scenario, for header lookup."""
    return {env["offense_id"]: env for env in all_labels()}


# ── Out-of-band delivery (brief §3) ─────────────────────────────────
#
# Ground truth must be able to travel with the response WITHOUT sitting
# in the alert body, so it can't leak into whatever the consumer feeds
# its classifier. Two moving parts:
#   - encode_labels_header(): the answer key for the served alerts,
#     base64(JSON), emitted as the ``X-Mock-Labels`` response header
#     (an unknown header every SOAR ignores).
#   - strip_answer_key(): remove the grading fields from an alert body,
#     so a consumer that opts into header-only labels never sees the
#     expected verdict/category in the payload.

import base64  # noqa: E402 — kept local to the delivery section
import json  # noqa: E402

# Keys in an alert body that ARE the answer key — grading metadata, not
# vendor-native fields. Stripped in header-only mode. `iocs` is NOT here:
# real vendor alerts carry indicators, so keeping them preserves realism.
_ANSWER_KEY_FIELDS = ("_test_meta", "test_notes")
_ANSWER_KEY_PREFIX = "expected_"


def encode_labels_header(offense_ids) -> str:
    """base64(JSON) answer key for the given served offence ids, for the
    ``X-Mock-Labels`` response header. Ids with no scenario envelope
    (e.g. synthetic noise templates) are simply omitted."""
    table = labels_by_offense_id()
    payload = {str(oid): table[oid] for oid in offense_ids if oid in table}
    blob = json.dumps(payload, separators=(",", ":")).encode()
    return base64.b64encode(blob).decode()


def decode_labels_header(header_value: str) -> dict:
    """Inverse of encode_labels_header — for a grader reading the header."""
    return json.loads(base64.b64decode(header_value).decode())


def strip_answer_key(alert: dict) -> dict:
    """Return a shallow copy of an alert body with grading metadata
    removed (``_test_meta`` / ``test_notes`` / every ``expected_*`` key),
    recursively into a nested ``_raw_alert``. The IOC list and all
    vendor-native fields are preserved."""
    out = {
        k: v
        for k, v in alert.items()
        if k not in _ANSWER_KEY_FIELDS and not k.startswith(_ANSWER_KEY_PREFIX)
    }
    inner = out.get("_raw_alert")
    if isinstance(inner, dict):
        out["_raw_alert"] = strip_answer_key(inner)
    return out
