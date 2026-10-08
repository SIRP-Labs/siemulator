"""Private corpus-only mode — ``SIEMULATOR_MODE=corpus``.

A deployment in this mode serves exactly one thing: offences pulled from an
authenticated upstream (sara-open's gold-corpus export, sara-open ADR 0095
Amendment 4). It exists so a mock SIEM can be pointed at a real customer
tenant without any risk of delivering the synthetic attack scenarios.

What the mode guarantees:

- ``GET <qradar prefix>/api/siem/offenses`` returns ONLY upstream offences,
  whatever the query string says (``scenarios``, ``extras``, ``labels`` are
  ignored). A poller configured for ``?scenarios=all`` still gets the corpus.
- It never falls back to the static scenarios or templates. Any upstream
  failure — or missing configuration — returns ``[]`` and says why in the
  ``X-Mock-Corpus-Upstream`` header.
- Only ``SIEMULATOR_QRADAR_TOKEN`` opens it, and it must be set explicitly.
  The dev default and the LogScale token are refused.
- The LogScale, Splunk and vendor-native surfaces, the web UI, sessions,
  fault injection and the scenario listing are not mounted at all.

No corpus data lives in this repository; the upstream holds it. The
upstream stamps an offence served when it hands it over, so this process
keeps no dedup state and more than one instance would be safe.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import urllib.parse
import urllib.request
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response

from siemulator import __version__
from siemulator.config import MOCK_SOURCE, access_log_enabled, qradar_prefix

logger = logging.getLogger(__name__)

EXPORT_PATH = "/api/internal/quality-corpus/offences"
EXPORT_KEY_HEADER = "x-corpus-export-key"
UPSTREAM_TIMEOUT_S = 20.0


def corpus_mode() -> bool:
    """True when this process runs as a private corpus-only deployment."""
    return os.environ.get("SIEMULATOR_MODE", "").strip().lower() == "corpus"


def _upstream_config() -> tuple[str, str, str]:
    """(base URL, export key, target host) — any may be empty."""
    return (
        os.environ.get("SIEMULATOR_CORPUS_UPSTREAM_URL", "").strip().rstrip("/"),
        os.environ.get("SIEMULATOR_CORPUS_UPSTREAM_KEY", "").strip(),
        os.environ.get("SIEMULATOR_CORPUS_TARGET_HOST", "").strip(),
    )


def _post_json(url: str, headers: dict[str, str], timeout: float) -> Any:
    """POST with an empty body and decode the JSON reply (blocking)."""
    req = urllib.request.Request(url, data=b"", method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — https URL from operator config
        return json.loads(resp.read().decode("utf-8"))


async def fetch_corpus_offences() -> tuple[list[dict], str]:
    """Pull the upstream's unserved offences for the configured target.

    Returns ``(offences, status)``. ``status`` is ``ok``, ``unconfigured`` or
    ``error``; on anything but ``ok`` the list is empty — never a fallback.
    """
    base, key, target = _upstream_config()
    if not (base and key and target):
        return [], "unconfigured"
    if not base.startswith("https://"):
        logger.warning("corpus | upstream URL must be https — refusing to send the key")
        return [], "unconfigured"
    url = f"{base}{EXPORT_PATH}?{urllib.parse.urlencode({'target_host': target})}"
    try:
        body = await asyncio.to_thread(
            _post_json, url, {EXPORT_KEY_HEADER: key, "Accept": "application/json"}, UPSTREAM_TIMEOUT_S
        )
        offences = body.get("offences") if isinstance(body, dict) else None
        if not isinstance(offences, list):
            logger.warning("corpus | upstream reply has no offences list")
            return [], "error"
        return [o for o in offences if isinstance(o, dict)], "ok"
    except Exception as e:  # noqa: BLE001 — any failure is an empty poll, never a fallback
        logger.warning("corpus | upstream fetch failed: %s", type(e).__name__)
        return [], "error"


def check_private_token(request: Request, mode: str) -> None:
    """Only an explicitly configured, non-default ``SIEMULATOR_QRADAR_TOKEN``
    opens a private mode (corpus, pinned)."""
    expected = os.environ.get("SIEMULATOR_QRADAR_TOKEN", "")
    if not expected or expected == "qradar-dev-token":
        raise HTTPException(503, f"{mode} mode requires SIEMULATOR_QRADAR_TOKEN")
    auth = request.headers.get("Authorization", "")
    supplied = (
        request.query_params.get("token", "")
        or request.headers.get("SEC", "")
        or (auth[7:] if auth.startswith("Bearer ") else "")
    )
    if not (supplied and secrets.compare_digest(supplied, expected)):
        raise HTTPException(401, "invalid token")


def _check_corpus_auth(request: Request) -> None:
    """Only an explicitly configured ``SIEMULATOR_QRADAR_TOKEN`` opens the mode."""
    check_private_token(request, "corpus")


def build_corpus_router() -> APIRouter:
    """The QRadar-shaped surface of a corpus-only deployment."""
    router = APIRouter(prefix=qradar_prefix(), tags=["qradar-corpus"])

    @router.get("/")
    @router.get("/api/help")
    @router.get("/api/help/capabilities")
    async def health(response: Response):
        """QRadar help / capabilities. No auth required."""
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        return {"endpoint_categories": ["siem"], "version": "20.0", "x-mock-source": MOCK_SOURCE, "mock": True}

    @router.get("/api/siem/offenses")
    async def list_offenses(request: Request, response: Response):
        """Corpus offences only — every query parameter is ignored."""
        _check_corpus_auth(request)
        offences, status = await fetch_corpus_offences()
        response.headers["X-Mock-Source"] = MOCK_SOURCE
        response.headers["X-Mock-Mode"] = "corpus"
        response.headers["X-Mock-Corpus-Upstream"] = status
        response.headers["X-Mock-Corpus-Returned"] = str(len(offences))
        return offences

    return router


def create_corpus_app() -> FastAPI:
    """App factory for ``SIEMULATOR_MODE=corpus``: the corpus surface and nothing else."""
    app = FastAPI(title="siemulator (corpus)", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    meta = {"name": "siemulator", "version": __version__, "mode": "corpus", "x-mock-source": MOCK_SOURCE}

    @app.get("/")
    @app.get("/api/info")
    async def info():
        return meta

    app.include_router(build_corpus_router())
    if access_log_enabled():
        from siemulator.access_log import AccessLogMiddleware
        app.add_middleware(AccessLogMiddleware, bound_prefixes=(qradar_prefix(),))
    return app
