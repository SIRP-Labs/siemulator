# Changelog

## [0.1.0] — 2026-06-07

Initial release. Extracted from [sara-open](https://github.com/sirp-labs/sara-open)
`sara/routes/siem_mock.py` + `sara/routes/_siem_scenarios.py`.

### Added
- LogScale (Humio REST) mock at `/logscale/*` — `/status`, `/repositories`,
  `/repositories/{repo}/alerts`, `/repositories/{repo}/query`,
  `/repositories/{repo}/queryjobs` (POST + poll).
- QRadar mock at `/qradar/*` — `/api/help`, `/api/siem/offenses`,
  `/api/siem/offenses/{id}`, `/api/siem/scenarios`, `/api/siem/source_addresses`,
  `/api/ariel/searches` (POST + poll + results).
- 22 sophisticated multi-source attack scenarios (S1–S5 + 10 v2 narratives)
  served via `?scenarios=all` and `/api/siem/scenarios`.
- Admin debug endpoints under `/qradar/_debug/*` — request capture, scenario
  state, replay reset. Gated on `SIEMULATOR_ADMIN_KEY`.
- Three auth channels per surface: `Authorization: Bearer`, `SEC` header
  (QRadar canonical), `?token=` query param (proxy-safe).
- Configurable URL prefixes via `SIEMULATOR_LOGSCALE_PREFIX` /
  `SIEMULATOR_QRADAR_PREFIX` for drop-in replacement of sara-open's
  `/omnisense/*` and `/qradar/*` mounts.
- Docker + docker-compose deployment.
- CI: ruff + pytest on Python 3.10/3.11/3.12 + container smoke test.
