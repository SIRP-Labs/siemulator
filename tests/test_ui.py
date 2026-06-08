"""Pinned regressions for the web UI."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate_env():
    """Stop UI env from leaking into sibling tests."""
    saved = {k: os.environ.get(k) for k in ("SIEMULATOR_UI_ENABLED",)}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _client():
    from siemulator.app import create_app

    return TestClient(create_app())


def test_root_serves_html_by_default():
    """UI is on by default — / returns text/html, not JSON."""
    r = _client().get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert "<title>siemulator" in body
    assert "Multi-source attack scenarios" in body
    assert "Detection templates" in body


def test_ui_includes_baked_prefixes(monkeypatch):
    """Configured prefixes get rendered into the curl examples."""
    monkeypatch.setenv("SIEMULATOR_LOGSCALE_PREFIX", "/custom-ls")
    monkeypatch.setenv("SIEMULATOR_QRADAR_PREFIX", "/custom-qr")
    r = _client().get("/")
    body = r.text
    assert "/custom-ls/api/v1/status" in body
    assert "/custom-qr/api/help" in body


def test_ui_can_be_disabled(monkeypatch):
    """SIEMULATOR_UI_ENABLED=false → / returns JSON metadata."""
    monkeypatch.setenv("SIEMULATOR_UI_ENABLED", "false")
    r = _client().get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["name"] == "siemulator"
    assert body["surfaces"] == ["logscale", "qradar"]


def test_ui_disabled_also_accepts_0_no_off(monkeypatch):
    """Truthiness accepts the usual aliases."""
    for falsey in ("0", "no", "off", "FALSE", "No"):
        monkeypatch.setenv("SIEMULATOR_UI_ENABLED", falsey)
        r = _client().get("/")
        assert r.headers["content-type"].startswith("application/json"), (
            f"value {falsey!r} should disable UI; got HTML"
        )


def test_api_info_always_returns_json():
    """/api/info is the machine-readable metadata endpoint, regardless of
    UI state. Always JSON, never HTML."""
    r = _client().get("/api/info")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["name"] == "siemulator"
    assert "x-mock-source" in body


def test_api_info_works_when_ui_disabled(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_UI_ENABLED", "false")
    r = _client().get("/api/info")
    assert r.status_code == 200
    assert r.json()["name"] == "siemulator"


def test_ui_route_excluded_from_openapi_schema():
    """The UI route shouldn't pollute /docs — it's HTML, not API."""
    r = _client().get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert "/" not in paths or "get" not in paths.get("/", {})
    assert "/api/info" in paths


def test_ui_links_to_github_and_docs():
    """Sanity: the rendered page should point at the repo + /docs."""
    body = _client().get("/").text
    assert "github.com/SIRP-Labs/siemulator" in body
    assert 'href="/docs"' in body


def test_ui_links_to_ingestion_guide():
    """Pin the link to docs/ingestion-guide.md so it stays discoverable
    from the live demo without code changes."""
    body = _client().get("/").text
    assert "docs/ingestion-guide.md" in body
