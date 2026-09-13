"""Pinned regressions for the self-hosted ingestion guide.

The guide is the doc a user needs to configure siemulator as an
ingestion source in their SOAR. Before this it lived only on github.com,
so someone on the deployed host had to leave the site to find it — and
``/docs`` (the URL people guess) serves Swagger, not setup docs.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL = REPO_ROOT / "docs" / "ingestion-guide.md"
PACKAGED = REPO_ROOT / "siemulator" / "ingestion_guide.md"


@pytest.fixture(autouse=True)
def _isolate_env():
    saved = os.environ.get("SIEMULATOR_UI_ENABLED")
    yield
    if saved is None:
        os.environ.pop("SIEMULATOR_UI_ENABLED", None)
    else:
        os.environ["SIEMULATOR_UI_ENABLED"] = saved


def _client() -> TestClient:
    from siemulator.app import create_app

    return TestClient(create_app())


# ── the two copies must not drift ───────────────────────────────────


def test_packaged_guide_matches_canonical():
    """``docs/ingestion-guide.md`` is the canonical, externally-linked
    copy; ``siemulator/ingestion_guide.md`` is what actually ships in the
    wheel and image. If they drift, the live site serves stale docs.

    To fix a failure here::

        cp docs/ingestion-guide.md siemulator/ingestion_guide.md
    """
    assert CANONICAL.is_file(), "canonical guide missing"
    assert PACKAGED.is_file(), "packaged guide missing — /guide would 500"
    assert PACKAGED.read_text(encoding="utf-8") == CANONICAL.read_text(
        encoding="utf-8"
    ), "packaged guide drifted — run: cp docs/ingestion-guide.md siemulator/ingestion_guide.md"


def test_guide_loads_via_package_resources():
    """Loading must go through importlib.resources, not a filesystem
    path relative to the repo — that's what makes it work inside the
    Docker image and a pip install."""
    from siemulator.guide import load_guide_markdown

    md = load_guide_markdown()
    assert "Platform recipes" in md
    assert len(md.splitlines()) > 400


# ── the route ───────────────────────────────────────────────────────


def test_guide_route_serves_html():
    r = _client().get("/guide")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "<title>Ingestion guide · siemulator</title>" in r.text


def test_guide_contains_every_platform_recipe():
    """The whole point of hosting it: all 8 recipes reachable on-host."""
    body = _client().get("/guide").text
    for recipe in (
        "IBM QRadar SOAR",
        "Splunk SOAR",
        "Cortex XSOAR",
        "Microsoft Sentinel",
        "Splunk Enterprise",
        "Elastic Stack",
        "Tines",
        "Custom Python poller",
    ):
        assert recipe in body, f"recipe missing from rendered guide: {recipe}"


def test_guide_renders_structure_not_raw_markdown():
    body = _client().get("/guide").text
    assert "<table>" in body and "<th>" in body          # 72 table rows
    assert "<pre" in body and "<code>" in body           # fenced code
    assert "<blockquote>" in body
    # raw markdown must not leak through
    assert "```" not in body
    assert "\n## " not in body


def test_guide_toc_anchors_resolve():
    """Every anchor the guide's own table of contents links to must exist
    as a heading id, or in-page navigation is dead.

    This asserts EVERY TOC target rather than a hand-picked few — the
    first version of this test sampled four punctuation-free anchors and
    passed while 6 of the 8 platform recipes were broken.
    """
    import re

    body = _client().get("/guide").text
    targets = set(re.findall(r'href="#([^"]+)"', body))
    ids = set(re.findall(r'id="([^"]+)"', body))
    assert targets, "no in-page links found — TOC missing?"
    dangling = sorted(targets - ids)
    assert not dangling, f"TOC links with no matching heading id: {dangling}"


def test_slug_matches_github_for_punctuated_headings():
    """GitHub drops punctuation but keeps the spaces around it, so
    `SOAR / Resilient` yields a DOUBLE hyphen. Collapsing whitespace runs
    breaks every heading containing / + or an em-dash."""
    from siemulator.guide import _slug

    assert _slug("Polling patterns + dedup") == "polling-patterns--dedup"
    assert _slug("IBM QRadar SOAR / Resilient") == "ibm-qradar-soar--resilient"
    assert _slug("Tines / n8n / Zapier") == "tines--n8n--zapier"
    assert _slug("Elastic Stack — Logstash http_poller") == (
        "elastic-stack--logstash-http_poller"
    )
    assert _slug("Platform recipes") == "platform-recipes"


# ── the guessed URLs ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "alias", ["/ingestion", "/ingestion-guide", "/setup", "/help", "/integrations"]
)
def test_guessed_urls_redirect_to_guide(alias):
    """Every one of these 404'd before. They're what a user types when
    hunting for setup docs."""
    r = _client().get(alias, follow_redirects=False)
    assert r.status_code == 308, f"{alias} did not redirect"
    assert r.headers["location"] == "/guide"

    followed = _client().get(alias)
    assert followed.status_code == 200
    assert "Platform recipes" in followed.text


def test_landing_page_links_to_hosted_guide():
    """Home must point at the on-host guide, not send users to GitHub."""
    body = _client().get("/").text
    assert 'href="/guide"' in body


def test_guide_absent_in_pure_api_mode(monkeypatch):
    """UI disabled => no guide route, consistent with / falling back to
    JSON metadata."""
    monkeypatch.setenv("SIEMULATOR_UI_ENABLED", "false")
    assert _client().get("/guide").status_code == 404


# ── renderer safety ─────────────────────────────────────────────────


def test_renderer_escapes_html():
    """The guide is trusted content, but the renderer must still escape —
    a future edit shouldn't be able to inject markup."""
    from siemulator.guide import render_markdown

    out = render_markdown("A <script>alert(1)</script> B\n")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_renderer_leaves_code_span_contents_literal():
    from siemulator.guide import render_markdown

    out = render_markdown("Use `**not bold**` here\n")
    assert "<strong>" not in out
    assert "**not bold**" in out


def test_renderer_rejects_non_http_link_targets():
    """javascript: targets render as plain text, never as a live link."""
    from siemulator.guide import render_markdown

    out = render_markdown("[click](javascript:alert(1))\n")
    assert "javascript:" not in out
    assert "click" in out
