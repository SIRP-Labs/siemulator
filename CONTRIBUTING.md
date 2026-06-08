# Contributing to siemulator

Thanks for your interest. This is a small project — most contributions land
fast.

## Development setup

```bash
git clone https://github.com/sirp-labs/siemulator.git
cd siemulator
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Running locally

```bash
python -m siemulator
# or
uvicorn siemulator.app:create_app --factory --port 8080
```

Then:

```bash
curl http://localhost:8080/logscale/api/v1/status
curl -H "Authorization: Bearer logscale-dev-token" \
  http://localhost:8080/logscale/api/v1/repositories/detections/alerts
```

## What we want

The highest-leverage contributions:

- **New SIEM vendor shapes.** Splunk, Sentinel, Elastic Security, Chronicle.
  Each new shape is a fresh module under `siemulator/` that reuses the
  template pool in `siemulator/templates.py`.
- **More detection templates.** Add to `ALERT_TEMPLATES` in
  `siemulator/templates.py`. Realistic MITRE-mapped CrowdStrike-flavoured
  detections are most useful for end-to-end SOAR testing.
- **More attack scenarios.** Multi-source narrative payloads in
  `siemulator/scenarios.py`. Each scenario gets a stable offence ID range so
  consumers can dedup replays.

## Style

- `ruff check .` must pass.
- `pytest` must pass on Python 3.10+.
- New endpoints get pinned regression tests under `tests/`.
- Every response carries `x-mock-source` so consumers can't confuse the
  output with a real SIEM.

## Reporting bugs

Open an issue with the request that failed (URL, headers minus tokens,
expected vs actual response). For shape regressions (e.g. "my consumer's ingest
script crashes on field X"), include the consumer's read pattern — the
test we add will pin the field name + type.
