# siemulator

**Synthetic SIEM and EDR endpoints in real-vendor shapes — point your SOAR at
realistic alerts without touching customer data.**

siemulator is a small FastAPI service that emulates the REST APIs of IBM
QRadar, Falcon LogScale, Splunk, CrowdStrike Falcon, Microsoft Defender and
RSA NetWitness. You configure it as an ingestion source exactly as you would
the real product, and it serves a stable, reproducible stream of synthetic
alerts — 74 hand-crafted multi-source attack scenarios plus randomised
detection templates.

[Configure it in your tool :material-arrow-right:](ingestion-guide.md){ .md-button .md-button--primary }
[Live demo](https://siemulator-y7uhf.ondigitalocean.app){ .md-button }

---

## What it's for

- **SOAR ingestion testing** — wire up a playbook against alerts you control,
  then replay them identically on every run.
- **Detection-engineering harnesses** — a fixed corpus with stable offence IDs,
  so dedup-by-ID works across replays.
- **Agent / LLM pipeline grading** — every curated scenario carries a
  ground-truth label (category, assessment, severity, expected IOCs) delivered
  out-of-band, so you can score a classifier instead of eyeballing it.
- **Chaos testing** — inject 5xx, latency and malformed JSON to see how your
  consumer handles a SIEM having a bad day.

!!! warning "Synthetic data"
    Every alert is fabricated. Don't feed siemulator output into a production
    detection pipeline or an analyst queue you can't reset. Every response
    carries `x-mock-source: siemulator` — pin it in your consumer as the
    "this is fake" guard.

## Surfaces

| Mount | Emulates | Envelope |
| --- | --- | --- |
| `/qradar/*` | IBM QRadar | offences + Ariel search |
| `/logscale/*` | Falcon LogScale (Humio) | `@timestamp` / `@rawstring` / `#repo` |
| `/splunk/*` | Splunk Enterprise | search jobs + oneshot export |
| `/alerts/entities/alerts/v2` | CrowdStrike Falcon Alerts v2 | `{meta, resources[], errors[]}` |
| `/v1.0/security/alerts` | Microsoft Graph Security v1.0 | `{@odata.context, value[]}` |
| `/rest/api/incidents` | NetWitness Respond | `{items[], totalItems, …}` |

The vendor-native endpoints filter the corpus by source vendor and serve each
vendor's alerts in that vendor's own documented schema — field names taken
from the vendors' published models, not approximated — so a per-vendor parser
sees the shape it expects.

## 60-second check

Two unauthenticated endpoints, so you can prove connectivity before wiring
credentials:

```bash
curl https://siemulator-y7uhf.ondigitalocean.app/logscale/api/v1/status
curl https://siemulator-y7uhf.ondigitalocean.app/qradar/api/help
```

Then pull real offences (demo tokens are public — it's synthetic data):

```bash
curl -H "SEC: qradar-dev-token" \
  "https://siemulator-y7uhf.ondigitalocean.app/qradar/api/siem/offenses?scenarios=batch"
```

## Run your own

```bash
pip install siemulator && python -m siemulator     # listens on :8080
```

```bash
docker run -p 8080:8080 ghcr.io/sirp-labs/siemulator:latest
```

## Next

The [**ingestion guide**](ingestion-guide.md) has copy-paste recipes for IBM
QRadar SOAR / Resilient, Splunk SOAR (Phantom), Cortex XSOAR, Microsoft
Sentinel, Splunk Enterprise, Elastic Stack, Tines / n8n / Zapier and a custom
Python poller — plus authentication patterns, polling and dedup modes, and how
to keep the corpus from leaking its own answers when you're measuring
classification accuracy.
