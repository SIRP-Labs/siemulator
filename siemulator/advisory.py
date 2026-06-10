"""Threat-intel advisory URL ingestion.

POST /api/advisory — fetch a public advisory URL, extract IOCs, and
return a pair of synthetic alerts (QRadar offense + LogScale event)
ready for integration testing. Alerts are stored in-memory and
available via GET /api/advisories and via the QRadar surface with
``?scenarios=advisory``.

Auth: same token channels as the SIEM surfaces (Bearer / SEC / query-param).
Either the LogScale or QRadar token is accepted.

URL fetching rules:
  - Only http:// and https:// schemes accepted.
  - 10-second connect + read timeout; response body capped at 512 KB.
  - HTML is stripped via stdlib html.parser; plain text passes through.

IOC extraction (regex, best-effort):
  - SHA-256 / SHA-1 / MD5 hashes
  - IPv4 addresses (routable preferred over RFC-1918)
  - CVE identifiers
  - MITRE ATT&CK technique IDs (T####.###)
"""

from __future__ import annotations

import re
import secrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser

from fastapi import APIRouter, HTTPException, Request, Response, status

from siemulator.config import MOCK_SOURCE, logscale_token, qradar_token

# ── In-memory store ───────────────────────────────────────────────────────────

_ADVISORY_STORE: dict[str, dict] = {}
_ADV_COUNTER = [0]

_ADV_OFFENSE_BASE = 700_000
_MAX_ADVISORIES = 100


def get_advisory_offenses() -> list[dict]:
    """Return all stored advisories as QRadar-shaped offenses."""
    return [rec["offense"] for rec in _ADVISORY_STORE.values()]


def get_advisory_events() -> list[dict]:
    """Return all stored advisories as LogScale-shaped events."""
    return [rec["event"] for rec in _ADVISORY_STORE.values()]


# ── IOC extraction ────────────────────────────────────────────────────────────

_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_RE_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RE_RFC1918 = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)"
)


def _extract_iocs(text: str) -> dict:
    sha256s = list(dict.fromkeys(_RE_SHA256.findall(text)))[:20]
    # Exclude hashes that are substrings of a longer match
    sha1s = list(dict.fromkeys(
        h for h in _RE_SHA1.findall(text) if not any(h in s for s in sha256s)
    ))[:10]
    md5s = list(dict.fromkeys(
        h for h in _RE_MD5.findall(text)
        if not any(h in s for s in sha256s) and not any(h in s for s in sha1s)
    ))[:10]
    all_ips = _RE_IPV4.findall(text)
    routable = [ip for ip in all_ips if not _RE_RFC1918.match(ip)]
    ips = list(dict.fromkeys(routable or all_ips))[:10]
    cves = list(dict.fromkeys(c.upper() for c in _RE_CVE.findall(text)))[:20]
    mitre = list(dict.fromkeys(_RE_MITRE.findall(text)))[:20]
    return {
        "sha256": sha256s,
        "sha1": sha1s,
        "md5": md5s,
        "ips": ips,
        "cves": cves,
        "mitre_techniques": mitre,
    }


# ── HTML stripping ────────────────────────────────────────────────────────────

class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip = False
        self._in_title = False
        self._title_parts: list[str] = []
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = True
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = False
        if tag == "title":
            self._in_title = False
        if tag in ("p", "li", "div", "h1", "h2", "h3", "h4", "tr", "br"):
            self._buf.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._in_title:
            self._title_parts.append(data)
        self._buf.append(data)

    @property
    def title(self) -> str:
        return "".join(self._title_parts).strip()

    @property
    def text(self) -> str:
        return " ".join(self._buf)


def _strip_html(raw: str) -> tuple[str, str]:
    """Return (title, plain_text). Handles non-HTML input gracefully."""
    parser = _TextExtractor()
    try:
        parser.feed(raw)
        return parser.title, parser.text
    except Exception:
        return "", raw


# ── URL fetch ─────────────────────────────────────────────────────────────────

_MAX_BYTES = 512 * 1024
_TIMEOUT = 10


def _fetch(url: str) -> tuple[str, str]:
    """Fetch URL and return (title, plain_text).

    Only http:// and https:// schemes accepted. Raises HTTPException on
    bad scheme, network error, or non-2xx response.
    """
    if not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "only http:// and https:// URLs are accepted",
                "url": url,
                "x-mock-source": MOCK_SOURCE,
            },
        )
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "siemulator-advisory/0.1 (threat-intel fetch)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            content_type: str = resp.headers.get_content_type() or ""
            charset: str = resp.headers.get_content_charset() or "utf-8"
            raw_bytes: bytes = resp.read(_MAX_BYTES)
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": f"advisory URL returned HTTP {exc.code}",
                "url": url,
                "x-mock-source": MOCK_SOURCE,
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": f"failed to fetch advisory URL: {exc}",
                "url": url,
                "x-mock-source": MOCK_SOURCE,
            },
        ) from exc

    try:
        raw = raw_bytes.decode(charset, errors="replace")
    except (LookupError, Exception):
        raw = raw_bytes.decode("utf-8", errors="replace")

    if "html" in content_type:
        return _strip_html(raw)
    return "", raw


# ── Severity inference ────────────────────────────────────────────────────────

def _severity(iocs: dict) -> tuple[str, int]:
    cve_count = len(iocs.get("cves", []))
    mitre_count = len(iocs.get("mitre_techniques", []))
    hash_count = len(iocs.get("sha256", [])) + len(iocs.get("md5", []))
    if cve_count >= 3 or mitre_count >= 5:
        return "Critical", 9
    if cve_count >= 1 or mitre_count >= 2 or hash_count >= 5:
        return "High", 7
    if mitre_count >= 1 or hash_count >= 1 or iocs.get("ips"):
        return "Medium", 5
    return "Low", 3


# ── Alert builders ────────────────────────────────────────────────────────────

def _build_offense(
    advisory_id: str,
    offense_id: int,
    url: str,
    label: str,
    title: str,
    iocs: dict,
    fetched_at_ms: int,
) -> dict:
    sev_name, sev_num = _severity(iocs)
    first_ip = (iocs.get("ips") or [""])[0]
    first_sha256 = (iocs.get("sha256") or [""])[0]
    first_md5 = (iocs.get("md5") or [""])[0]
    first_mitre = (iocs.get("mitre_techniques") or [""])[0]
    first_cve = (iocs.get("cves") or [""])[0]
    detect_name = label or title or "Threat Intelligence Advisory"

    desc_parts = [detect_name]
    if first_cve:
        desc_parts.append(first_cve)
    if first_mitre:
        desc_parts.append(first_mitre)
    description = " — ".join(desc_parts)[:1024]

    categories = ["Threat Intelligence"]
    if iocs.get("cves"):
        categories.append("Vulnerability")
    if first_mitre:
        categories.append(first_mitre)

    return {
        "id": offense_id,
        "offense_id": offense_id,
        "description": description,
        "offense_source": first_ip or "threat-intel-advisory",
        "source_ip": first_ip,
        "destination_ip": "",
        "severity": sev_num,
        "magnitude": sev_num,
        "credibility": 8,
        "relevance": 9,
        "status": "OPEN",
        "categories": categories,
        "category_count": len(categories),
        "security_category_count": len(categories),
        "policy_category_count": 0,
        "rules": [{"type": "THREAT_INTEL_ADVISORY", "id": offense_id}],
        "start_time": fetched_at_ms,
        "start_epochtime": fetched_at_ms,
        "first_persisted_time": fetched_at_ms,
        "last_persisted_time": fetched_at_ms + 60_000,
        "last_updated_time": fetched_at_ms + 30_000,
        "event_count": max(1, len(iocs.get("sha256", [])) + len(iocs.get("ips", []))),
        "flow_count": 0,
        "source_count": 1,
        "username_count": 0,
        "device_count": 1,
        "destination_port": "",
        "source_port": "",
        "log_sources": [
            {
                "type_name": "ThreatIntelAdvisory",
                "id": 998,
                "name": "Threat Intel Advisory Feed",
                "type_id": 998,
            }
        ],
        "remote_destination_count": 0,
        "local_destination_count": 0,
        "destination_networks": ["other"],
        "source_network": "Threat-Intel-Net",
        "domain_id": 1,
        "domain_name": "EXTERNAL",
        "assigned_to": None,
        "closing_user": None,
        "closing_reason_id": None,
        "close_time": None,
        "inactive": False,
        "protected": False,
        "follow_up": False,
        "offense_type": 0,
        "source_address_ids": [],
        "local_destination_address_ids": [],
        "_advisory": {
            "advisory_id": advisory_id,
            "url": url,
            "label": label,
            "title": title,
            "iocs": iocs,
            "DetectName": detect_name,
            "Tactic": "Threat Intelligence",
            "TacticId": "TA0000",
            "Technique": first_mitre or "Unknown",
            "TechniqueId": first_mitre or "",
            "Severity": sev_num,
            "SeverityName": sev_name,
            "SHA256String": first_sha256,
            "MD5String": first_md5,
        },
        "x-mock-source": MOCK_SOURCE,
    }


def _build_event(
    advisory_id: str,
    offense_id: int,
    url: str,
    label: str,
    title: str,
    iocs: dict,
    fetched_at_ms: int,
) -> dict:
    sev_name, sev_num = _severity(iocs)
    iso = (
        datetime.fromtimestamp(fetched_at_ms / 1000, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    first_ip = (iocs.get("ips") or [""])[0]
    first_sha256 = (iocs.get("sha256") or [""])[0]
    first_md5 = (iocs.get("md5") or [""])[0]
    first_mitre = (iocs.get("mitre_techniques") or [""])[0]
    detect_name = label or title or "Threat Intelligence Advisory"
    techniques_preview = ",".join(iocs.get("mitre_techniques", [])[:3])

    return {
        "@timestamp": iso,
        "@id": secrets.token_hex(12),
        "@rawstring": (
            f"{iso} siemulator Advisory — {detect_name} | "
            f"source={url} techniques={techniques_preview}"
        ),
        "#repo": "advisory",
        "#type": "threat-intel",
        "metadata.customerIDString": "advisory-feed",
        "metadata.eventType": "ThreatAdvisoryIngestion",
        "metadata.eventCreationTime": fetched_at_ms,
        "metadata.offset": 0,
        "metadata.version": "1.0",
        "event.AdvisoryId": advisory_id,
        "event.DetectId": f"adv:{advisory_id}:1",
        "event.DetectName": detect_name,
        "event.DetectDescription": f"Threat Intel Advisory — {url}",
        "event.Severity": sev_num,
        "event.SeverityName": sev_name,
        "event.Tactic": "Threat Intelligence",
        "event.TacticId": "TA0000",
        "event.Technique": first_mitre or "Unknown",
        "event.TechniqueId": first_mitre or "",
        "event.FileName": "",
        "event.FilePath": "",
        "event.CommandLine": "",
        "event.MD5String": first_md5,
        "event.SHA256String": first_sha256,
        "event.RemoteAddress": first_ip,
        "event.AdvisoryURL": url,
        "event.IOCs": iocs,
        "event.OffenseId": offense_id,
        "x-mock-source": MOCK_SOURCE,
    }


# ── Auth ──────────────────────────────────────────────────────────────────────

def _check_auth(request: Request) -> None:
    valid = (logscale_token(), qradar_token())
    qp = request.query_params.get("token", "")
    if qp and any(secrets.compare_digest(qp, t) for t in valid):
        return
    sec = request.headers.get("SEC", "") or request.headers.get("sec", "")
    if sec and any(secrets.compare_digest(sec, t) for t in valid):
        return
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and any(
        secrets.compare_digest(auth[7:], t) for t in valid
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "missing or invalid token", "x-mock-source": MOCK_SOURCE},
    )


# ── Router ────────────────────────────────────────────────────────────────────

def build_router() -> APIRouter:
    router = APIRouter(prefix="/api", tags=["advisory"])

    @router.post("/advisory", status_code=201)
    async def ingest_advisory(request: Request, response: Response):
        """Fetch a public threat intel advisory URL, extract IOCs, and return
        a synthetic QRadar offense + LogScale event pinned to that advisory.

        Request body (JSON):
          ``url``   — required, http(s) URL to the advisory page
          ``label`` — optional human-readable name; used as offense description
        """
        _check_auth(request)
        response.headers["X-Mock-Source"] = MOCK_SOURCE

        body: dict = {}
        try:
            body = await request.json()
        except Exception:
            body = {}

        url: str = body.get("url", "").strip() if isinstance(body, dict) else ""
        label: str = (body.get("label", "") or "").strip() if isinstance(body, dict) else ""
        if not url:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"error": "'url' field is required", "x-mock-source": MOCK_SOURCE},
            )

        title, text = _fetch(url)
        iocs = _extract_iocs(text)

        _ADV_COUNTER[0] += 1
        advisory_id = f"adv-{_ADV_COUNTER[0]:04d}-{secrets.token_hex(4)}"
        offense_id = _ADV_OFFENSE_BASE + _ADV_COUNTER[0]
        fetched_at_ms = int(time.time() * 1000)

        offense = _build_offense(
            advisory_id, offense_id, url, label, title, iocs, fetched_at_ms
        )
        event = _build_event(
            advisory_id, offense_id, url, label, title, iocs, fetched_at_ms
        )

        record = {
            "advisory_id": advisory_id,
            "url": url,
            "label": label,
            "title": title,
            "fetched_at": datetime.fromtimestamp(
                fetched_at_ms / 1000, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "extracted": iocs,
            "offense": offense,
            "event": event,
            "x-mock-source": MOCK_SOURCE,
        }
        _ADVISORY_STORE[advisory_id] = record

        if len(_ADVISORY_STORE) > _MAX_ADVISORIES:
            oldest_key = next(iter(_ADVISORY_STORE))
            _ADVISORY_STORE.pop(oldest_key, None)

        return record

    @router.get("/advisories")
    async def list_advisories(request: Request, response: Response):
        """List all advisories ingested in this process lifetime (summary only)."""
        _check_auth(request)
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        return {
            "count": len(_ADVISORY_STORE),
            "advisories": [
                {
                    "advisory_id": v["advisory_id"],
                    "url": v["url"],
                    "label": v["label"],
                    "title": v["title"],
                    "fetched_at": v["fetched_at"],
                    "ioc_counts": {k: len(vals) for k, vals in v["extracted"].items()},
                    "offense_id": v["offense"]["offense_id"],
                }
                for v in _ADVISORY_STORE.values()
            ],
            "x-mock-source": MOCK_SOURCE,
        }

    @router.get("/advisories/{advisory_id}")
    async def get_advisory(advisory_id: str, request: Request, response: Response):
        """Return a single advisory including its offense and event payloads."""
        _check_auth(request)
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        rec = _ADVISORY_STORE.get(advisory_id)
        if not rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "advisory not found",
                    "advisory_id": advisory_id,
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        return rec

    @router.delete("/advisories/{advisory_id}")
    async def delete_advisory(advisory_id: str, request: Request, response: Response):
        """Remove an advisory from the in-memory store."""
        _check_auth(request)
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        if advisory_id not in _ADVISORY_STORE:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "advisory not found",
                    "advisory_id": advisory_id,
                    "x-mock-source": MOCK_SOURCE,
                },
            )
        _ADVISORY_STORE.pop(advisory_id)
        return {"deleted": advisory_id, "x-mock-source": MOCK_SOURCE}

    return router
