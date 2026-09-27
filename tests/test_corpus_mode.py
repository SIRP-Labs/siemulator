"""SIEMULATOR_MODE=corpus — the private deployment that may face a customer tenant.

Only the upstream HTTP call is faked (``urllib.request.urlopen``); the app
factory, the mode switch, auth and the route run for real.
"""
from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient

from siemulator import corpus

TOKEN = "private-qradar-token"
CORPUS = [{"offense_id": 91000, "description": "[QC:rc-000000000001] corpus case"}]


@pytest.fixture
def corpus_env(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_MODE", "corpus")
    monkeypatch.setenv("SIEMULATOR_QRADAR_TOKEN", TOKEN)
    monkeypatch.setenv("SIEMULATOR_LOGSCALE_TOKEN", "logscale-token")
    monkeypatch.setenv("SIEMULATOR_QRADAR_PREFIX", "/qradar")
    monkeypatch.setenv("SIEMULATOR_CORPUS_UPSTREAM_URL", "https://sara.example/")
    monkeypatch.setenv("SIEMULATOR_CORPUS_UPSTREAM_KEY", "export-key")
    monkeypatch.setenv("SIEMULATOR_CORPUS_TARGET_HOST", "us.example")
    monkeypatch.setenv("SIEMULATOR_ACCESS_LOG_ENABLED", "false")
    return monkeypatch


def _client() -> TestClient:
    from siemulator.app import create_app
    return TestClient(create_app())


class _Upstream:
    def __init__(self, body=None, exc: Exception | None = None):
        self.body = {"offences": CORPUS, "returned": 1} if body is None else body
        self.exc = exc
        self.calls: list = []

    def __call__(self, req, timeout=None):
        self.calls.append(req)
        if self.exc:
            raise self.exc
        return io.BytesIO(json.dumps(self.body).encode())


def _install(monkeypatch, upstream: _Upstream) -> _Upstream:
    class _Ctx(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        return _Ctx(upstream(req, timeout).getvalue())

    monkeypatch.setattr(corpus.urllib.request, "urlopen", fake_urlopen)
    return upstream


@pytest.mark.parametrize("query", ["", "?scenarios=all", "?scenarios=replay&extras=50", "?scenarios=mix",
                                   "?scenarios=batch&labels=strip"])
def test_every_query_gets_the_corpus_and_nothing_synthetic(corpus_env, query):
    up = _install(corpus_env, _Upstream())
    r = _client().get(f"/qradar/api/siem/offenses{query}", headers={"SEC": TOKEN})
    assert r.status_code == 200, r.text
    assert r.json() == CORPUS
    assert r.headers["X-Mock-Mode"] == "corpus" and r.headers["X-Mock-Corpus-Upstream"] == "ok"
    req = up.calls[0]
    assert req.full_url == "https://sara.example/api/internal/quality-corpus/offences?target_host=us.example"
    assert req.get_method() == "POST"
    assert req.get_header("X-corpus-export-key") == "export-key"


@pytest.mark.parametrize("exc", [TimeoutError(), OSError("refused"), ValueError("bad json")])
def test_an_upstream_failure_is_an_empty_poll_never_a_fallback(corpus_env, exc):
    _install(corpus_env, _Upstream(exc=exc))
    r = _client().get("/qradar/api/siem/offenses?scenarios=all", headers={"SEC": TOKEN})
    assert r.status_code == 200 and r.json() == []
    assert r.headers["X-Mock-Corpus-Upstream"] == "error"


def test_a_malformed_upstream_reply_is_an_empty_poll(corpus_env):
    _install(corpus_env, _Upstream(body={"unexpected": True}))
    r = _client().get("/qradar/api/siem/offenses", headers={"SEC": TOKEN})
    assert r.json() == [] and r.headers["X-Mock-Corpus-Upstream"] == "error"


@pytest.mark.parametrize("missing", ["SIEMULATOR_CORPUS_UPSTREAM_URL", "SIEMULATOR_CORPUS_UPSTREAM_KEY",
                                     "SIEMULATOR_CORPUS_TARGET_HOST"])
def test_missing_upstream_config_is_an_empty_poll(corpus_env, missing):
    up = _install(corpus_env, _Upstream())
    corpus_env.delenv(missing)
    r = _client().get("/qradar/api/siem/offenses", headers={"SEC": TOKEN})
    assert r.json() == [] and r.headers["X-Mock-Corpus-Upstream"] == "unconfigured"
    assert up.calls == []


def test_the_key_is_never_sent_over_plain_http(corpus_env):
    up = _install(corpus_env, _Upstream())
    corpus_env.setenv("SIEMULATOR_CORPUS_UPSTREAM_URL", "http://sara.example")
    r = _client().get("/qradar/api/siem/offenses", headers={"SEC": TOKEN})
    assert r.json() == [] and up.calls == []


@pytest.mark.parametrize("headers", [{}, {"SEC": "wrong"}, {"SEC": "logscale-token"}])
def test_only_the_qradar_token_opens_it(corpus_env, headers):
    _install(corpus_env, _Upstream())
    assert _client().get("/qradar/api/siem/offenses", headers=headers).status_code == 401


@pytest.mark.parametrize("token", ["", "qradar-dev-token"])
def test_an_unset_or_default_token_refuses_everyone(corpus_env, token):
    _install(corpus_env, _Upstream())
    corpus_env.setenv("SIEMULATOR_QRADAR_TOKEN", token)
    r = _client().get("/qradar/api/siem/offenses", headers={"SEC": token})
    assert r.status_code == 503


@pytest.mark.parametrize("path", ["/qradar/api/siem/scenarios", "/qradar/api/siem/offenses/90011",
                                  "/logscale/api/v1/status", "/splunk/services/server/info",
                                  "/guide", "/api/faults", "/api/access-log", "/docs"])
def test_no_synthetic_surface_is_mounted(corpus_env, path):
    _install(corpus_env, _Upstream())
    assert _client().get(path, headers={"SEC": TOKEN}).status_code == 404


def test_without_the_mode_the_public_app_is_unchanged(monkeypatch):
    monkeypatch.delenv("SIEMULATOR_MODE", raising=False)
    monkeypatch.setenv("SIEMULATOR_QRADAR_TOKEN", TOKEN)
    monkeypatch.setenv("SIEMULATOR_QRADAR_PREFIX", "/qradar")
    r = _client().get("/qradar/api/siem/scenarios", headers={"SEC": TOKEN})
    assert r.status_code == 200 and len(r.json()) > 0
