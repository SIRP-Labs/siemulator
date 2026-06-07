# siemulator

> Synthetic SIEM endpoints in real-vendor shapes — for SOAR / agent
> integration testing without touching real customer data.

`siemulator` is a tiny FastAPI service that emulates two SIEM REST surfaces
from a single pool of synthetic CrowdStrike-flavoured detections:

| Mount             | Shape                            | Auth                                    |
| ----------------- | -------------------------------- | --------------------------------------- |
| `/logscale/*`     | Falcon LogScale (Humio REST API) | `Authorization: Bearer` or `?token=`    |
| `/qradar/*`       | IBM QRadar (offences + Ariel)    | `SEC` header, `Bearer`, or `?token=`    |

It's the thing you point a SOAR ingestion job at when you want a stable,
reproducible stream of realistic alerts without spinning up real SIEMs or
touching customer telemetry. Originally extracted from
[sara-open](https://github.com/sirp-labs/sara-open) where it powered
end-to-end agent-chain testing.

## Why

Real SIEMs are slow to stand up for tests, real customer data can't be
replayed across environments, and "just hit a record-and-replay fixture"
fails the moment your integration code starts negotiating shape
(`SEC` vs `Bearer`, `start_time` as int-ms vs string, `id` vs `offense_id`,
…). `siemulator` lets you:

- Pin shape regressions in CI — every endpoint has a contract test.
- Replay 22 hand-crafted multi-source attack scenarios (phishing → MFA
  fatigue → token theft → UEFI bootkit → insider exfil → 0-day SSTI),
  each tagged with a stable offence ID so dedup-by-ID works across replays.
- Use either token on either surface — config-paste mistakes are forgiven
  by default; both surfaces serve synthetic data so cross-acceptance is
  safe.
- Pass tokens via `?token=` query param — survives forward proxies that
  strip `Authorization` / `Sec-*` headers.

## Quickstart

```bash
pip install siemulator
python -m siemulator                 # listens on :8080 by default
```

Or with Docker:

```bash
docker run -p 8080:8080 sirplabs/siemulator:latest
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

# Multi-source attack scenarios (22 narrative offences)
curl "http://localhost:8080/qradar/api/siem/scenarios?token=qradar-dev-token"
```

## Configuration

All via env vars. Defaults work for local testing — override in production.

| Variable                       | Default                | Purpose                                                |
| ------------------------------ | ---------------------- | ------------------------------------------------------ |
| `SIEMULATOR_LOGSCALE_TOKEN`    | `logscale-dev-token`   | Bearer token for `/logscale/*`                         |
| `SIEMULATOR_QRADAR_TOKEN`      | `qradar-dev-token`     | SEC / Bearer token for `/qradar/*`                     |
| `SIEMULATOR_ADMIN_KEY`         | _(empty — disabled)_   | Admin key for `/qradar/_debug/*`                       |
| `SIEMULATOR_LOGSCALE_PREFIX`   | `/logscale`            | URL prefix — set to `/omnisense` for legacy compat     |
| `SIEMULATOR_QRADAR_PREFIX`     | `/qradar`              | URL prefix                                             |
| `SIEMULATOR_HOST`              | `0.0.0.0`              | Bind host                                              |
| `SIEMULATOR_PORT`              | `8080`                 | Bind port                                              |

See [`.env.example`](.env.example).

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

### Scenario modes

`/qradar/api/siem/offenses?scenarios=…`:

- **`all`** — _One-shot_. Returns fresh scenarios only; each offence ID
  served once per process lifetime. Use for cron-style pollers that would
  otherwise create duplicate incidents.
- **`batch`** — Rotate one scenario per call (round-robin through all 22).
- **`replay`** — All 22 scenarios, ignoring the one-shot dedup set.
- **`mix`** — All scenarios + N synthetic templates (N from `Range` header).

### Debug endpoints (`SIEMULATOR_ADMIN_KEY` required)

| Method | Path                          | Purpose                                       |
| ------ | ----------------------------- | --------------------------------------------- |
| GET    | `/qradar/_debug/recent`       | Last 100 requests this mock saw (auth, headers, response preview) |
| POST   | `/qradar/_debug/reset_scenarios` | Clear served-scenarios set so `?scenarios=all` replays the pool |
| GET    | `/qradar/_debug/scenarios_state` | Served vs remaining scenario IDs           |

All require `X-Admin-Key: <SIEMULATOR_ADMIN_KEY>`. If the env var is
unset, every `/_debug/*` returns 403.

## Safety markers

Every response carries `X-Mock-Source: siemulator` (header) and
`"x-mock-source": "siemulator"` (in the JSON body). Detection events
additionally embed it per-row. This is the contract test that all
consumers can use to verify they're not accidentally pointed at a
real SIEM — pin it in your integration tests.

## sara-open migration

If you're moving from sara-open's `sara/routes/siem_mock.py`:

```bash
SIEMULATOR_LOGSCALE_PREFIX=/omnisense
SIEMULATOR_QRADAR_PREFIX=/qradar
SIEMULATOR_LOGSCALE_TOKEN=$OMNISENSE_MOCK_LOGSCALE_TOKEN
SIEMULATOR_QRADAR_TOKEN=$OMNISENSE_MOCK_QRADAR_TOKEN
```

URL paths and response shapes are byte-identical. The only behaviour
changes vs sara-open:

- `X-Mock-Source` value is `siemulator` (was `sara-open/sara/routes/siem_mock.py`).
- Debug endpoints use `SIEMULATOR_ADMIN_KEY` (sara-open used `ADMIN_KEY` /
  `EVAL_ADMIN_KEY`).
- Hostnames and usernames in synthetic alerts use `example.local` /
  `EXAMPLE\\…` instead of the sara-open development domain.

## Development

```bash
git clone https://github.com/sirp-labs/siemulator.git
cd siemulator
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding new SIEM shapes,
templates, or scenarios.

## License

[MIT](LICENSE) — © 2026 SIRP Labs.
