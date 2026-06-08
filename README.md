# siemulator

> Synthetic SIEM endpoints in real-vendor shapes — for SOAR / agent
> integration testing without touching real customer data.

`siemulator` is a small FastAPI service that emulates two SIEM REST surfaces
from a single pool of synthetic CrowdStrike-flavoured detections and
hand-crafted multi-source attack narratives:

| Mount             | Shape                            | Auth                                    |
| ----------------- | -------------------------------- | --------------------------------------- |
| `/logscale/*`     | Falcon LogScale (Humio REST API) | `Authorization: Bearer` or `?token=`    |
| `/qradar/*`       | IBM QRadar (offences + Ariel)    | `SEC` header, `Bearer`, or `?token=`    |

It's the thing you point a SOAR ingestion job, a detection-engineering
test harness, or an agent-chain integration test at when you want a
stable, reproducible stream of realistic alerts without standing up
real SIEMs or touching customer telemetry.

**Status:** v0.1.0 · MIT-licensed · Python 3.10+ · Docker (amd64 + arm64).

---

## Table of contents

- [Why](#why)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [Response shape — quick reference](#response-shape--quick-reference)
- [Scenario modes](#scenario-modes)
- [What's in the box](#whats-in-the-box)
  - [Detection templates (MITRE ATT&CK mapped)](#detection-templates-mitre-attck-mapped)
  - [Multi-source attack scenarios](#multi-source-attack-scenarios)
- [Use as a test fixture](#use-as-a-test-fixture)
- [Debug endpoints](#debug-endpoints)
- [Safety markers](#safety-markers)
- [Architecture](#architecture)
- [What siemulator IS / ISN'T](#what-siemulator-is--isnt)
- [Performance & limits](#performance--limits)
- [Roadmap](#roadmap)
- [Deploy on DigitalOcean App Platform](#deploy-on-digitalocean-app-platform)
- [Development](#development)
- [FAQ](#faq)
- [License](#license)

---

## Why

Real SIEMs are slow to stand up for tests, real customer data can't be
replayed across environments, and "just hit a record-and-replay fixture"
fails the moment your integration code starts negotiating shape
(`SEC` vs `Bearer`, `start_time` as int-ms vs string, `id` vs `offense_id`,
…). `siemulator` lets you:

- **Pin shape regressions in CI.** Every endpoint has a contract test —
  fork them as your integration's golden-shape pins.
- **Replay 22 hand-crafted multi-source attack scenarios** (phishing →
  MFA fatigue → token theft → UEFI bootkit → insider exfil → 0-day SSTI
  → ProxyShell → Golden Ticket → BEC + 10 more). Each is tagged with a
  stable offence ID so dedup-by-ID works across replays — your SOAR
  doesn't create 47 incidents from one scenario when the poller runs
  every 60 s.
- **Cross-token acceptance** — either token works on either surface.
  Config-paste mistakes during initial integration setup don't burn
  you; both surfaces serve synthetic data so cross-acceptance has
  zero security impact.
- **Three auth channels per surface** — `Authorization: Bearer`,
  `SEC` header (QRadar canonical), and `?token=` query param. The
  query-param channel survives forward proxies that strip `Authorization`
  / `Sec-*` headers in egress.
- **One-shot dedup mode** — `?scenarios=all` returns each scenario ID
  exactly once per process lifetime, so a cron poller can drain the
  whole scenario library over N polls without re-ingesting the same
  incidents on every cycle.

## Quickstart

```bash
pip install siemulator
python -m siemulator                 # listens on :8080 by default
```

Or with Docker (multi-arch, amd64 + arm64):

```bash
docker run -p 8080:8080 ghcr.io/sirp-labs/siemulator:latest
# or
docker compose up
```

Then:

```bash
# Health (no auth)
curl http://localhost:8080/logscale/api/v1/status

# LogScale alerts (default token: logscale-dev-token)
curl -H "Authorization: Bearer logscale-dev-token" \
  "http://localhost:8080/logscale/api/v1/repositories/detections/alerts?limit=3"

# QRadar offences
curl -H "SEC: qradar-dev-token" \
  "http://localhost:8080/qradar/api/siem/offenses"

# All 22 multi-source attack scenarios
curl "http://localhost:8080/qradar/api/siem/scenarios?token=qradar-dev-token"
```

## Configuration

All via env vars. Defaults work for local testing — override in production.

| Variable                       | Default                | Purpose                                                |
| ------------------------------ | ---------------------- | ------------------------------------------------------ |
| `SIEMULATOR_LOGSCALE_TOKEN`    | `logscale-dev-token`   | Bearer token for `/logscale/*`                         |
| `SIEMULATOR_QRADAR_TOKEN`      | `qradar-dev-token`     | SEC / Bearer token for `/qradar/*`                     |
| `SIEMULATOR_ADMIN_KEY`         | _(empty — disabled)_   | Admin key for `/qradar/_debug/*`                       |
| `SIEMULATOR_LOGSCALE_PREFIX`   | `/logscale`            | URL prefix override                                    |
| `SIEMULATOR_QRADAR_PREFIX`     | `/qradar`              | URL prefix override                                    |
| `SIEMULATOR_HOST`              | `0.0.0.0`              | Bind host                                              |
| `SIEMULATOR_PORT`              | `8080`                 | Bind port                                              |

See [`.env.example`](.env.example).

**Prefix overrides** are useful if you're emulating an existing
integration that was pointed at non-default URLs and you don't want to
change the consumer-side config. Setting
`SIEMULATOR_LOGSCALE_PREFIX=/api/v1/falcon-logscale` and
`SIEMULATOR_QRADAR_PREFIX=/siem-mock` is supported — both prefixes can
take any path.

## Endpoints

### LogScale (`/logscale/*`)

| Method | Path                                                    | Auth | Purpose                                |
| ------ | ------------------------------------------------------- | ---- | -------------------------------------- |
| GET    | `/api/v1/status`                                        | —    | Health (Humio version shape)           |
| GET    | `/api/v1/repositories`                                  | —    | List repos (always `[{detections}]`)   |
| GET    | `/api/v1/repositories/{repo}/alerts?limit=N`            | ✅   | Synthetic Humio events (1-50)          |
| GET    | `/api/v1/repositories/{repo}/query?q=…&limit=N`         | ✅   | Same shape; `q` accepted but ignored   |
| POST   | `/api/v1/repositories/{repo}/queryjobs`                 | ✅   | Async submit → returns `{id}`          |
| GET    | `/api/v1/repositories/{repo}/queryjobs/{id}`            | ✅   | Poll — stable across repeated reads    |

### QRadar (`/qradar/*`)

| Method | Path                                                    | Auth | Purpose                                |
| ------ | ------------------------------------------------------- | ---- | -------------------------------------- |
| GET    | `/api/help` / `/api/help/capabilities`                  | —    | Health                                 |
| GET    | `/api/siem/offenses[?scenarios=all\|batch\|replay\|mix]`| ✅   | Active offences + scenario modes       |
| GET    | `/api/siem/offenses/{id}`                               | ✅   | Single offence (id echoed back)        |
| GET    | `/api/siem/scenarios`                                   | ✅   | All 22 multi-source attack narratives  |
| GET    | `/api/siem/source_addresses`                            | ✅   | IP context (3 synthetic rows)          |
| POST   | `/api/ariel/searches`                                   | ✅   | Submit (returns COMPLETED immediately) |
| GET    | `/api/ariel/searches/{id}`                              | ✅   | Status                                 |
| GET    | `/api/ariel/searches/{id}/results`                      | ✅   | Results `{events: [...]}`              |

## Response shape — quick reference

**LogScale alerts (`/logscale/api/v1/repositories/detections/alerts`)**
return a Humio-style envelope:

```json
{
  "events": [
    {
      "@timestamp": "2026-06-07T17:42:01.234Z",
      "@id": "8a3f4b5c6d7e8f90a1b2c3d4",
      "@rawstring": "2026-06-07T17:42:01.234Z CrowdStrike Falcon Sensor — Detection: Credential Dumping via Mimikatz on WIN-DESKTOP-01.example.local by EXAMPLE\\analyst",
      "#repo": "detections",
      "#type": "kv",
      "metadata.eventType": "DetectionSummaryEvent",
      "event.DetectId": "ldt:5b6c7d8e…",
      "event.DetectName": "Credential Dumping via Mimikatz",
      "event.Severity": 5,
      "event.SeverityName": "Critical",
      "event.Tactic": "Credential Access",
      "event.TacticId": "TA0006",
      "event.Technique": "OS Credential Dumping: LSASS Memory",
      "event.TechniqueId": "T1003.001",
      "event.ComputerName": "WIN-DESKTOP-01.example.local",
      "event.UserName": "EXAMPLE\\analyst",
      "event.CommandLine": "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
      "event.MD5String": "a1b2c3d4…",
      "event.SHA256String": "0f2dd7587…",
      "event.FalconHostLink": "https://falcon.crowdstrike.com/activity/detections/detail/ldt:…",
      "x-mock-source": "siemulator"
    }
  ],
  "metadata": {
    "totalWork": 1,
    "doneWork": 1,
    "workInProgress": 0,
    "extraData": {
      "x-mock-source": "siemulator",
      "x-mock-version": "1.0",
      "x-server-timestamp": 1780839721234
    }
  }
}
```

**QRadar offences (`/qradar/api/siem/offenses`)** return a list (not
an envelope — matches QRadar's actual API):

```json
[
  {
    "id": 95693,
    "offense_id": 95693,
    "description": "Lateral Movement via PsExec — PsExec service binary created on remote host; followed by service start from non-administrative user context.",
    "source_ip": "10.42.83.12",
    "destination_ip": "172.16.55.91",
    "severity": 7,
    "magnitude": 8,
    "credibility": 7,
    "relevance": 8,
    "status": "OPEN",
    "categories": ["Lateral Movement", "Custom Rule Engine"],
    "rules": [{"type": "CRE_RULE", "id": 158472}],
    "start_time": 1780839721000,
    "start_epochtime": 1780839721000,
    "event_count": 247,
    "log_sources": [
      {"type_name": "EventCRE", "id": 63, "name": "Custom Rule Engine-8 :: cre-primary", "type_id": 18},
      {"type_name": "MicrosoftWindows", "id": 168, "name": "WinEventLog @ WIN-DESKTOP-01.example.local", "type_id": 12}
    ],
    "domain_id": 1,
    "domain_name": "EXAMPLE",
    "_detection": {
      "DetectName": "Lateral Movement via PsExec",
      "Tactic": "Lateral Movement",
      "TechniqueId": "T1021.002",
      "MD5String": "75b55bb34dac9d029396fbb98ab8b8ff"
    },
    "x-mock-source": "siemulator"
  }
]
```

**Shape pins worth knowing** (break these and downstream ingestion
crashes — they're in `tests/test_qradar.py`):

- `id` is `int`, not string — consumers do `a['offense_id'] = a['id']`.
- `start_time` is INT MILLISECONDS EPOCH — consumers do
  `datetime.fromtimestamp(a['start_time']/1000)`.
- `severity` is `int 1-10`, not the LogScale `"Critical"`/`"High"` string.

## Scenario modes

`/qradar/api/siem/offenses?scenarios=…`:

- **`all`** — _One-shot_. Returns fresh scenarios only; each offence ID
  served once per process lifetime. Use for cron-style pollers that
  would otherwise create duplicate incidents on every cycle. Reset via
  `POST /qradar/_debug/reset_scenarios` (admin-key gated).
- **`batch`** — Rotate one scenario per call (round-robin through all
  22). Useful for slow-drip ingestion testing.
- **`replay`** — All 22 scenarios in one response, ignoring the one-shot
  dedup set. Useful for one-shot ad-hoc bulk ingestion tests.
- **`mix`** — All scenarios + N synthetic templates (N from the `Range:
  items=0-N` header). Useful for testing how your consumer handles a
  mixed pool.

## What's in the box

### Detection templates (MITRE ATT&CK mapped)

Six templates form the rotating pool that LogScale `/alerts` and QRadar
default-mode `/offenses` draw from. Each carries MITRE tactic + technique
IDs, realistic command lines, MD5/SHA256, and host context. All shipped
in `siemulator/templates.py` — add your own by appending to
`ALERT_TEMPLATES`.

| Tactic                | Technique                                       | DetectName                                          | Severity |
| --------------------- | ----------------------------------------------- | --------------------------------------------------- | -------- |
| TA0006 Credential Access | T1003.001 OS Credential Dumping: LSASS Memory | Credential Dumping via Mimikatz                     | Critical |
| TA0002 Execution      | T1059.001 PowerShell                            | Suspicious PowerShell with Base64 Encoded Command   | High     |
| TA0008 Lateral Movement | T1021.002 SMB/Windows Admin Shares            | Lateral Movement via PsExec                         | High     |
| TA0001 Initial Access | T1566.001 Spearphishing Attachment              | Phishing — Suspicious Outlook Attachment            | Medium   |
| TA0011 Command and Control | T1071.001 Application Layer Protocol: Web | Beaconing C2 Traffic to Known Bad Domain            | Critical |
| TA0003 Persistence    | T1547.001 Registry Run Keys / Startup Folder    | Suspicious File Write to Startup Folder             | Medium   |

### Multi-source attack scenarios

Twenty-two hand-crafted offences spread across two batches, each tagged
with a stable `offense_id` in `90011-90070` and a `_scenario_id` label.
Each offence carries a `_raw_alert` block preserving the original
vendor-specific schema (Proofpoint TAP, Defender for Endpoint,
CrowdStrike Falcon, Zscaler ZIA, Entra ID, Eclypsium, Purview, WAF,
CloudWatch, …) so a downstream agent can analyse the multi-vendor
narrative end-to-end.

#### Batch 1 — narrative chains (S1–S5, 12 offences)

| `_scenario_id` | offence IDs    | Narrative                                                                                     |
| -------------- | -------------- | --------------------------------------------------------------------------------------------- |
| **S1**         | 90011 → 90015 | **Living-off-the-land supply chain (5 alerts, 47 min).** Proofpoint clean email → Defender signed download → CrowdStrike DLL side-load + persistence → Defender LOLBin recon + certutil exfil → Zscaler Notion-API stego exfil. |
| **S2**         | 90021         | **Identity attack chain.** MFA fatigue → PRT theft → OAuth app consent → mailbox forwarding rule → admin role grant. |
| **S3**         | 90031         | **UEFI firmware bootkit** (BlackLotus-class) — pre-boot persistence detected by Eclypsium.    |
| **S4**         | 90041         | **Insider threat + steganographic exfiltration** — ML-model weights hidden in PNG attachments. |
| **S5**         | 90051 → 90054 | **Zero-day chain (4 alerts).** WAF-blocked SSTI probe → WAF-bypassed SSTI success → webshell + XMRig + crontab persist → CloudWatch CPU spike + $847/day cost anomaly. |

#### Batch 2 — advanced TEST scenarios (TEST-A through TEST-J, 10 offences)

Independent single-offence narratives covering attacker tradecraft
where a single sophisticated event tells the whole story.

| `_scenario_id` | offence ID | Narrative                                                                                |
| -------------- | ---------- | ---------------------------------------------------------------------------------------- |
| **TEST-A**     | 90061      | Golden Ticket — Kerberos persistence (T1558.001)                                          |
| **TEST-B**     | 90062      | Exchange ProxyShell — webshell + backdoor user (CVE-2021-34473)                          |
| **TEST-C**     | 90063      | DNS tunneling — dnscat2 exfiltration 12.4 MB (T1048.003)                                  |
| **TEST-D**     | 90064      | SIM swap → MFA bypass → Okta/AWS admin (T1111 + T1098)                                    |
| **TEST-E**     | 90065      | Linux LKM rootkit — syscall hooks + SSH key persistence (T1014)                          |
| **TEST-F**     | 90066      | BEC CEO wire fraud — `.CO` TLD + Gmail reply-to (zero IOCs — tests semantic analysis)    |
| **TEST-G**     | 90067      | CI/CD compromise — GitHub Actions secret exfil + supply chain                            |
| **TEST-H**     | 90068      | Medical infusion pump — drug-limit override 10×↑, patient at risk (CVE-2022-26390)        |
| **TEST-I**     | 90069      | Deepfake vishing — AI-synthesised CEO voice + BEC multi-channel                           |
| **TEST-J**     | 90070      | GPO abuse — domain-wide scheduled-task + persistence (T1484.001)                          |

The full scenario corpus lives in `siemulator/scenarios.py` — JSON-defined
payloads parsed once at import. Add your own by extending the registry
at the bottom of that file.

## Use as a test fixture

The most common consumer pattern: spin up siemulator in a pytest fixture
and point your integration under test at it.

### Pytest in-process (no Docker)

```python
# tests/conftest.py
import os, pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

@pytest.fixture
def siem(monkeypatch):
    monkeypatch.setenv("SIEMULATOR_QRADAR_TOKEN", "ci-token")
    monkeypatch.setenv("SIEMULATOR_LOGSCALE_TOKEN", "ci-token")
    from siemulator.app import create_app
    return TestClient(create_app())


def test_my_qradar_ingest(siem):
    # Your ingestion code under test:
    from myapp.ingest import poll_qradar_offences
    offences = poll_qradar_offences(
        base_url=str(siem.base_url),
        token="ci-token",
    )
    assert len(offences) >= 1
    # Pin the shape contract — siemulator guarantees these on every poll:
    assert isinstance(offences[0]["id"], int)
    assert offences[0]["start_time"] > 1_000_000_000_000  # ms epoch
    assert "x-mock-source" in offences[0]
```

### docker-compose (out-of-process)

```yaml
# docker-compose.test.yml
services:
  siemulator:
    image: ghcr.io/sirp-labs/siemulator:latest
    environment:
      SIEMULATOR_QRADAR_TOKEN: ci-token
      SIEMULATOR_LOGSCALE_TOKEN: ci-token
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/logscale/api/v1/status').read()"]
      interval: 2s
      retries: 5
  my-app-under-test:
    build: .
    environment:
      SIEM_URL: http://siemulator:8080
      SIEM_TOKEN: ci-token
    depends_on:
      siemulator:
        condition: service_healthy
```

### One-off shell test

```bash
docker run -d --name siem --rm -p 8080:8080 ghcr.io/sirp-labs/siemulator:latest
curl -H "SEC: qradar-dev-token" "http://localhost:8080/qradar/api/siem/offenses?scenarios=replay" \
  | jq '.[] | {id, _scenario_id, description}'
docker stop siem
```

## Debug endpoints

Gated on `SIEMULATOR_ADMIN_KEY`. Leave the env var empty to disable
them entirely (every `/_debug/*` then returns 403).

| Method | Path                                | Purpose                                                            |
| ------ | ----------------------------------- | ------------------------------------------------------------------ |
| GET    | `/qradar/_debug/recent`             | Last 100 requests this mock saw (path, headers, auth channel, response preview) |
| POST   | `/qradar/_debug/reset_scenarios`    | Clear served-scenarios set so `?scenarios=all` replays the pool    |
| GET    | `/qradar/_debug/scenarios_state`    | Served vs remaining scenario IDs                                   |

All require `X-Admin-Key: <SIEMULATOR_ADMIN_KEY>`. Use `_debug/recent`
to diagnose "my poller hits siemulator but my SOAR shows zero incidents"
— you can see the exact path, query params, auth channel, and first-row
preview that went over the wire.

## Safety markers

Every response carries `X-Mock-Source: siemulator` (HTTP header) and
`"x-mock-source": "siemulator"` (JSON field). Detection events embed it
per-row too. **This is the contract test every consumer should pin** —
it's how you guarantee in CI that you're not accidentally pointed at a
real SIEM. The `siemulator` string is stable across versions.

## Architecture

```
siemulator/
├── app.py          # FastAPI factory — mounts both routers
├── config.py       # All env var reads (one function per var; no caching)
├── logscale.py     # /logscale/* — Humio REST shape
├── qradar.py       # /qradar/* — QRadar offences + Ariel
├── templates.py    # 6 detection templates + HOSTNAMES + USERS pool
├── scenarios.py    # 22 multi-source attack narratives
└── __main__.py     # `python -m siemulator` entrypoint
```

Both routers are built by a `build_router()` factory that reads the
prefix env var at construction time and returns a fresh `APIRouter`.
Env vars are re-read per-request, not cached at import — so you can
`monkeypatch.setenv()` mid-test and the next request reflects the
change.

State: each surface keeps two in-memory dicts — `_query_jobs` (LogScale
queryjobs, 256-entry FIFO cap) and `_ariel_searches` (QRadar Ariel
searches, 256-entry FIFO cap) — and the QRadar surface additionally
keeps a 100-entry request-capture deque and a set of served scenario
IDs. Everything dies with the process; no persistence.

## What siemulator IS / ISN'T

**IS:**
- A test fixture for SOAR ingestion, detection-engineering pipelines,
  and agent-chain integration tests.
- A way to pin SIEM-response shapes in CI so vendor-shape regressions
  fail fast.
- A reproducible source of multi-source attack narratives for
  end-to-end SOC tooling tests.
- Safe to deploy as a long-running internal service (the debug endpoints
  are admin-key-gated and disabled by default).

**IS NOT:**
- A real SIEM. There's no event ingest, no search engine, no
  correlation rules, no storage. Search queries are accepted and
  ignored; the alert pool is fixed per-process.
- Production-ready as a public endpoint without putting it behind your
  own auth layer. The default tokens are public sentinels —
  **change them**.
- A canonical reference for vendor APIs. Field coverage is "everything
  a typical consumer reads" plus enough adjacent fields to look real;
  if you're building a real LogScale or QRadar client, read the
  upstream vendor docs.
- A red-team training environment. The synthetic data is shape-
  realistic, not behaviour-realistic — running detections against
  siemulator output will not validate that your detections work
  against real attacks.

## Performance & limits

| Resource                    | Cap                                | Behaviour at cap                         |
| --------------------------- | ---------------------------------- | ---------------------------------------- |
| LogScale `?limit=N`         | 1 ≤ N ≤ 50                         | Clamped silently                         |
| QRadar `Range: items=0-N`   | 1 ≤ N ≤ 50                         | Clamped silently                         |
| In-memory LogScale queryjobs | 256                               | Oldest evicted FIFO                      |
| In-memory Ariel searches    | 256                                | Oldest evicted FIFO                      |
| Request capture (`_debug/recent`) | 100 most recent                | Oldest dropped                           |
| Served-scenarios set (`?scenarios=all`) | 22 (the pool size)       | After 22, returns `[]` until reset       |

Single-process throughput is whatever uvicorn + your CPU give you —
typically a few thousand requests/second per worker on a modest host;
each response is generated fresh (template choice + ID + timestamp), so
there's no caching benefit from repeated requests.

Run multiple workers for higher throughput:

```bash
uvicorn siemulator.app:create_app --factory --workers 4 --port 8080
```

Note that the in-memory state (queryjobs, served-scenarios, debug-ring)
is per-worker — multi-worker deployments will see the served-scenarios
one-shot dedup operate independently in each worker. For a true single-
state deployment, run one worker.

## Roadmap

Contributions especially welcome on the highest-leverage gaps:

- **New SIEM vendor shapes.** Splunk REST, Microsoft Sentinel Log
  Analytics, Elastic Security, Google Chronicle. Each lives as a fresh
  module under `siemulator/` reusing the existing template + scenario
  pool. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **More detection templates.** Realistic MITRE-mapped templates,
  especially for under-represented tactics (Defence Evasion, Discovery,
  Collection, Impact).
- **More attack scenarios.** Multi-source narratives covering
  ransomware deployment chains, cloud-native attack paths
  (IMDS abuse → cross-account role assumption → S3 exfil), and Mac /
  Linux endpoint chains. Open-source threat-intel reports are the best
  source.
- **Streaming surface.** A `/logscale/api/v1/repositories/{repo}/stream`
  SSE/WebSocket endpoint that pushes events at a configurable rate, so
  consumers testing push-style ingestion (rather than poll) can exercise
  their code paths.
- **Deterministic mode.** A `SIEMULATOR_SEED` env var that makes
  template choice + IDs + timestamps reproducible across runs, so
  snapshot tests can pin exact responses instead of shape-only contracts.

## Deploy on DigitalOcean App Platform

A ready-to-apply spec ships at [`.do/app.yaml`](.do/app.yaml). It uses
GitHub auto-deploy from `main`, builds via the repo's `Dockerfile`, and
sizes for the stateless mock (1 instance, `basic-xxs` — ~$5/mo).

**First-time create:**

```bash
doctl apps create --spec .do/app.yaml
# → returns an app ID; note it down.
```

**Set the three SECRET env vars** (tokens + admin key) via either
the dashboard (Settings → web → Environment Variables) or by editing a
local copy of `.do/app.yaml` to inline the values and running
`doctl apps update <app-id> --spec <local-copy>`. DO encrypts the values
and stores them as `EV[1:...]` ciphertext — don't commit those.

**Custom domain** (optional): point `siemulator.example.com` at the
default `<app>.ondigitalocean.app` ingress via CNAME, then add a
`domains:` block to the spec and `doctl apps update`. DO provisions a
Let's Encrypt cert automatically.

**Why `instance_count: 1`.** Each instance keeps its own in-memory
served-scenarios set for `?scenarios=all` one-shot dedup. Running
multiple instances would break that contract — a round-robin poller
would see the same scenario re-served on every other hit. If you need
horizontal scale and don't use one-shot dedup, bump the count freely
(every other endpoint is request-local and safe to scale).

**Health checks** poll `/logscale/api/v1/status` (no-auth) every 30 s
with a 10-second initial delay. Failures auto-roll back to the last
healthy deployment.

**Updates flow.** Every push to `main` triggers a fresh build + zero-
downtime deploy. CI must be green; if `pytest` or `ruff` fail, the
build never reaches the platform. Multi-arch Docker images keep getting
published to `ghcr.io/sirp-labs/siemulator:<sha>` in parallel — pin a
specific tag in the spec if you want immutable deploys instead of
"latest-on-main."

## Development

```bash
git clone https://github.com/sirp-labs/siemulator.git
cd siemulator
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                 # 35 contract tests
ruff check .           # lint
```

CI runs ruff + pytest on Python 3.10 / 3.11 / 3.12 plus a multi-arch
GHCR build with a container smoke test. See
[`.github/workflows/`](.github/workflows/) for the exact pipeline.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contribution flow,
including adding new SIEM shapes, templates, and scenarios.

## FAQ

**Q: Can I use this for load testing my SOAR?**
A: It can produce as much traffic as your test harness can consume,
but every response is a fresh roll of dice. If you're load-testing
deduplication or correlation, prefer `?scenarios=batch` or `?scenarios=replay`
so the offence IDs are stable. For shape-only soak testing, the
default mode is fine.

**Q: Does it support Splunk / Sentinel / Elastic?**
A: Not yet. The architecture supports adding them — see the
[Roadmap](#roadmap). Each new vendor shape is a fresh module under
`siemulator/` that reuses the existing template + scenario pool. PRs
welcome.

**Q: Are the scenarios real attacks?**
A: They're realistic narratives modeled on published threat-intel
reports and incident postmortems, but the IOCs, hostnames, usernames,
file hashes, and timestamps are synthetic. Don't match them against
real-world threat-intel feeds.

**Q: How do I add my own templates / scenarios?**
A: For templates, append to `ALERT_TEMPLATES` in
`siemulator/templates.py` — the schema is documented in that file's
module docstring. For scenarios, append a `(offence_id, scenario_label,
raw_alert)` tuple to the registry at the bottom of `siemulator/scenarios.py`
and import a JSON payload via the `_j()` helper. Both surfaces pick up
the additions automatically on next process start.

**Q: Is it safe to expose publicly?**
A: The data is synthetic, so there's no data-leak risk. The default
tokens (`logscale-dev-token`, `qradar-dev-token`) are PUBLIC sentinels —
**change them before exposing publicly** so casual scanners don't get
free use of your service. The debug endpoints are disabled by default
and require `SIEMULATOR_ADMIN_KEY` to be set + sent on every request,
so they're safe to leave wired in.

**Q: Why one combined service instead of two repos for LogScale and
QRadar?**
A: Both surfaces share the same template + scenario pool. Splitting
them would force every new template / scenario to be added in two
places. Keeping them together lets one detection-template addition
serve every vendor surface for free.

**Q: How do I pin a regression test that catches "my consumer breaks
when siemulator changes shape"?**
A: Fork the relevant tests from
[`tests/test_logscale.py`](tests/test_logscale.py) /
[`tests/test_qradar.py`](tests/test_qradar.py) into your own test
suite, pointing them at your consumer's response-handling code instead
of at siemulator. Those tests are the contract — if your consumer
makes them pass, siemulator changes that break the contract will
break your tests too.

## License

[MIT](LICENSE) — © 2026 SIRP Labs.
