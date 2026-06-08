# Ingestion guide

How to point your SIEM / SOAR / pipeline at siemulator so it starts
consuming synthetic alerts in real-vendor shapes — for integration
testing, demo environments, training labs, or detection-engineering
soak tests.

There's a live demo at
**https://siemulator-y7uhf.ondigitalocean.app** with default tokens
(`logscale-dev-token`, `qradar-dev-token`) — point your tool at it
before standing up your own instance to validate the integration end-
to-end without operational risk.

> Synthetic data warning. Every alert is fabricated. Don't run
> alerts ingested from siemulator into a production detection pipeline,
> SIEM correlation rule, or analyst queue you can't reset. Pin the
> `X-Mock-Source: siemulator` header / `x-mock-source` field in every
> consumer as your "this is fake" guard — see
> [Verification](#verification).

---

## Table of contents

- [Quickstart](#quickstart)
- [Choosing a surface](#choosing-a-surface)
- [Authentication patterns](#authentication-patterns)
- [Polling patterns + dedup](#polling-patterns--dedup)
- [Platform recipes](#platform-recipes)
  - [IBM QRadar SOAR / Resilient](#ibm-qradar-soar--resilient)
  - [Splunk SOAR (Phantom)](#splunk-soar-phantom)
  - [Cortex XSOAR (Demisto)](#cortex-xsoar-demisto)
  - [Microsoft Sentinel — Logic App + custom logs](#microsoft-sentinel--logic-app--custom-logs)
  - [Splunk Enterprise — REST modular input](#splunk-enterprise--rest-modular-input)
  - [Elastic Stack — Logstash http_poller](#elastic-stack--logstash-http_poller)
  - [Tines / n8n / Zapier](#tines--n8n--zapier)
  - [Custom Python poller](#custom-python-poller)
- [Verification](#verification)
- [Going to production](#going-to-production)

---

## Quickstart

If you just want to see whether your tool can talk to siemulator:

```bash
# These two endpoints are unauthenticated — your tool should hit them
# first to validate connectivity before negotiating credentials.
curl https://siemulator-y7uhf.ondigitalocean.app/logscale/api/v1/status
curl https://siemulator-y7uhf.ondigitalocean.app/qradar/api/help
```

If those work, your tool can reach siemulator. The recipes below
configure each platform to poll the alert / offence endpoints on a
schedule.

## Choosing a surface

| You want to test | Use surface | Why |
|---|---|---|
| QRadar offence ingestion (most SOARs) | `/qradar/*` | Native shape; consumers don't need custom mapping. 22 multi-source scenarios available with stable IDs for dedup. |
| Humio / Falcon LogScale push integrations | `/logscale/*` | Mirrors Humio REST exactly — `@timestamp`, `@id`, `@rawstring`, `#repo` envelope. |
| Detection content (templates) — alert-shape testing | Either | Both surfaces draw from the same 6-template pool; pick the shape your downstream consumer expects. |
| Multi-source attack-narrative testing (5-alert chains across multiple vendors) | `/qradar/*` with `?scenarios=…` | Only the QRadar surface exposes the 22 scenario library. Each scenario tags `_scenario_id` + `_raw_alert` so your SOAR can correlate by chain. |
| Search-API testing (`/queryjobs`, Ariel) | Both | LogScale `queryjobs` POST→poll matches Humio; QRadar Ariel matches the IBM async-search shape. |
| Range-paginated ingestion (`Range: items=N-M`) | `/qradar/*` | QRadar canonical pagination header. LogScale uses `?limit=N` query param instead. |

Most SOAR integrations want `/qradar/*` because (a) QRadar's
offence shape is what most SOAR-vendor connectors are already built
against, and (b) the 22 multi-source scenarios let you test correlation
logic, not just shape parsing.

## Authentication patterns

siemulator accepts **three** auth channels per surface, and the same
token works on either surface (cross-acceptance — convenience for
mixed-vendor environments). Pick whichever your consumer ships
natively:

| Channel | Header / location | Best for |
|---|---|---|
| `Authorization: Bearer <token>` | HTTP header | LogScale-shape consumers, REST clients with stock Bearer support |
| `SEC: <token>` | HTTP header | QRadar canonical — most existing QRadar consumers default to this |
| `?token=<token>` | URL query param | Proxies / SaaS connectors that strip `Authorization` / `Sec-*` headers in egress |

If your environment puts a forward proxy between your consumer and
siemulator, default to the query-param channel — it survives every
header-stripping proxy without code changes.

Cross-token acceptance means if your consumer was configured against
sara-open's old `OMNISENSE_MOCK_LOGSCALE_TOKEN` and you accidentally
paste it as siemulator's `SIEMULATOR_QRADAR_TOKEN`, it still works.
This isn't laziness — it's a deliberate decision because both surfaces
serve synthetic data and forgiving config-paste mistakes removes a
class of friction during integration setup.

## Polling patterns + dedup

The hardest part of any "poll a mock SIEM for alerts" integration
isn't the HTTP call — it's making sure your consumer doesn't create
12 incidents from one scenario when your cron runs every 60 seconds.
siemulator provides four modes via `?scenarios=…` on
`/qradar/api/siem/offenses` to make this safe.

| Mode | Behaviour | When to use |
|---|---|---|
| _(default — no `?scenarios=`)_ | Returns N synthetic offences from the 6-template pool. Random IDs, random content per call. | Shape-only soak testing; load-style polling where you want a constant trickle. |
| `?scenarios=all` | **One-shot dedup.** Returns scenarios with offence IDs your process hasn't served yet. Each ID emitted once per process lifetime. Subsequent polls return `[]` until reset. | **Default for SOAR ingestion testing.** A cron poll every 60s drains the 22 scenarios over ~22 polls, then quiesces. Your SOAR sees 22 distinct incidents, not the same one re-ingested 22 times. |
| `?scenarios=batch` | Round-robin — one scenario per call, rotating through the pool. | Slow-drip ingestion where you want a steady stream of fresh content. |
| `?scenarios=replay` | All 22 scenarios in one response, every call. | Bulk-load tests; one-shot end-to-end runs. |
| `?scenarios=mix` | All scenarios + N synthetic templates from `Range: items=0-N`. | Mixed-pool stress testing. |

If you choose `?scenarios=all` and want to replay the pool (e.g. after
adding new scenario variants, or as part of a CI reset), call:

```bash
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" \
  https://your-siemulator/qradar/_debug/reset_scenarios
```

The admin key is set via `SIEMULATOR_ADMIN_KEY`; the endpoint is 403
when unset.

**Cron cadence recommendation**: every 60 seconds is plenty.
siemulator handles thousands of req/s on `basic-xxs`, but your SOAR's
ingestion-cost ceiling typically matters more than siemulator's.

## Platform recipes

### IBM QRadar SOAR / Resilient

Resilient (and the standalone QRadar SIEM ingestion add-on) consumes
the QRadar offence shape natively. Point it at siemulator like a real
QRadar console:

| Setting | Value |
|---|---|
| Host | `siemulator-y7uhf.ondigitalocean.app` (or your instance) |
| Port | `443` |
| Auth | `SEC` header — set the `SEC` header to your `SIEMULATOR_QRADAR_TOKEN` |
| Verify TLS | Yes (DO App Platform serves a valid Let's Encrypt cert) |
| Polling endpoint | `/qradar/api/siem/offenses?scenarios=all` |
| Polling interval | 60 seconds |

What lands: every poll, your SOAR ingests fresh scenario offences as
they're drained from the pool. Each offence carries a `_scenario_id`
field — group incidents by that label to reconstruct multi-alert
narratives (S1 = 5 alerts, S5 = 4 alerts).

### Splunk SOAR (Phantom)

Use the **HTTP/REST** asset type (built-in, no app install needed).

**Asset configuration:**

| Field | Value |
|---|---|
| Asset name | `siemulator` |
| Asset type | `REST` |
| Base URL | `https://siemulator-y7uhf.ondigitalocean.app` |
| Verify server certificate | true |
| Default headers | `SEC: <your token>` |

**Playbook block** (paste into a `code` block in a playbook):

```python
import phantom.rules as phantom
import json, urllib.request

def poll_siemulator(action=None, success=None, container=None,
                    results=None, handle=None, filtered_artifacts=None,
                    filtered_results=None, custom_function=None, **kwargs):

    url = "https://siemulator-y7uhf.ondigitalocean.app/qradar/api/siem/offenses?scenarios=all"
    req = urllib.request.Request(url, headers={"SEC": "qradar-dev-token"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        offences = json.loads(resp.read())

    for o in offences:
        # Pin the mock-source marker so you can never confuse this for
        # production data downstream:
        assert o.get("x-mock-source") == "siemulator", "real-SIEM source detected!"

        cid = phantom.create_container(
            label="events",
            name=f"[{o['_scenario_id']}] {o['description'][:80]}",
            description=o["description"],
            severity={9: "high", 7: "medium", 5: "low"}.get(o["severity"], "low"),
            artifacts=[{
                "name": "offence",
                "cef": {
                    "deviceCustomString1": o["_scenario_id"],
                    "deviceCustomString2": o["_detection"]["TechniqueId"],
                    "sourceAddress": o["source_ip"],
                    "destinationAddress": o["destination_ip"],
                    "severity": o["severity"],
                    "externalId": str(o["id"]),
                },
                "raw": o,
            }],
        )

    return phantom.set_status(container=container, status="closed")
```

Schedule the playbook on a 1-minute cron.

### Cortex XSOAR (Demisto)

Use the **Generic Webhook / Generic REST** integration (built-in).

**Integration instance:**

| Field | Value |
|---|---|
| Name | `siemulator-incidents` |
| Server URL | `https://siemulator-y7uhf.ondigitalocean.app` |
| Fetches incidents | true |
| Incident type | `Alert` |
| Mapper (incoming) | _(see below)_ |
| First fetch | `1 minute ago` |
| Fetch incidents (interval) | `1 minute` |

**Pre-process script** (paste into the integration's script field):

```python
import demistomock as demisto
import json
import requests

URL = "https://siemulator-y7uhf.ondigitalocean.app/qradar/api/siem/offenses"
HEADERS = {"SEC": demisto.params().get("apikey")}

def fetch_incidents():
    last_run = demisto.getLastRun() or {}
    resp = requests.get(f"{URL}?scenarios=all", headers=HEADERS, timeout=10)
    resp.raise_for_status()
    offences = resp.json()

    incidents = []
    for o in offences:
        assert o["x-mock-source"] == "siemulator"
        incidents.append({
            "name": f"[{o['_scenario_id']}] {o['description'][:80]}",
            "occurred": demisto.toIso8601(o["start_time"] / 1000),
            "rawJSON": json.dumps(o),
            "severity": {9: 3, 7: 2, 5: 1}.get(o["severity"], 1),
            "type": "Alert",
            "details": o["description"],
            "labels": [
                {"type": "scenario_id", "value": o["_scenario_id"]},
                {"type": "technique_id", "value": o["_detection"]["TechniqueId"]},
            ],
        })
    demisto.incidents(incidents)
    demisto.setLastRun({"last_id": offences[-1]["id"] if offences else last_run.get("last_id")})

fetch_incidents()
```

The one-shot `?scenarios=all` mode means after 22 polls the pool
drains and `fetch_incidents` stops creating incidents until you reset
the served-set via `/qradar/_debug/reset_scenarios`. Useful — your CI
test sees exactly 22 incidents, then quiesces.

### Microsoft Sentinel — Logic App + custom logs

Use a **scheduled Logic App** to poll siemulator and forward to a
Sentinel custom log table.

**Logic App workflow** (Designer or JSON):

1. Trigger: **Recurrence** every 1 minute.
2. Action: **HTTP** —
   - Method: `GET`
   - URI: `https://siemulator-y7uhf.ondigitalocean.app/qradar/api/siem/offenses?scenarios=all`
   - Headers: `SEC` = `qradar-dev-token`
3. Action: **Parse JSON** — schema from the QRadar response (the
   easiest way is to run once, copy the body from the run history,
   and let the designer generate the schema).
4. Action: **For each** on `body('Parse_JSON')` →
   **Send Data (Azure Log Analytics Data Collector)** —
   - Workspace ID + key from your Sentinel workspace
   - Custom log name: `siemulator_offence_CL`
   - JSON request body: `items('For_each')`

Sentinel then exposes the data as `siemulator_offence_CL` in KQL:

```kusto
siemulator_offence_CL
| where xmocksource_s == "siemulator"
| summarize count() by _scenario_id_s
```

If `xmocksource_s` ever returns anything other than `"siemulator"`
in production, alert-on-it — that's the leak indicator.

### Splunk Enterprise — REST modular input

Use the **Splunk Add-on Builder** or the built-in **REST API Modular
Input** add-on (Splunkbase, free) to poll siemulator.

**Input configuration:**

| Field | Value |
|---|---|
| Endpoint URL | `https://siemulator-y7uhf.ondigitalocean.app/qradar/api/siem/offenses?scenarios=all` |
| HTTP method | `GET` |
| Authentication | `none` (we use a custom header instead) |
| Custom headers | `SEC=qradar-dev-token` |
| Interval | `60` (seconds) |
| Response handler | `default` (JSON array) |
| Source type | `siemulator:offence` |
| Index | `mock_security` (separate from your prod indexes) |

In Splunk search:

```spl
index=mock_security sourcetype=siemulator:offence
| stats count by _scenario_id, _detection.TechniqueId
| sort -count
```

### Elastic Stack — Logstash http_poller

```ruby
# /etc/logstash/conf.d/siemulator.conf
input {
  http_poller {
    urls => {
      siemulator => {
        method => get
        url => "https://siemulator-y7uhf.ondigitalocean.app/qradar/api/siem/offenses?scenarios=all"
        headers => {
          SEC => "qradar-dev-token"
        }
      }
    }
    request_timeout => 10
    schedule => { every => "60s" }
    codec => "json"
    tags => ["siemulator", "synthetic"]
  }
}

filter {
  # Hard fail if anything reaches here without the mock-source marker.
  if ![x-mock-source] or [x-mock-source] != "siemulator" {
    drop {}
  }
  mutate {
    rename => { "[_detection][TechniqueId]" => "mitre_technique_id" }
    rename => { "[_scenario_id]" => "scenario_id" }
  }
}

output {
  elasticsearch {
    hosts => ["https://your-es:9200"]
    index => "mock-siemulator-%{+YYYY.MM.dd}"
    user => "logstash_writer"
    password => "${ES_LOGSTASH_PWD}"
  }
}
```

Kibana Discover query: `tags:siemulator AND scenario_id:S*`.

### Tines / n8n / Zapier

Visual workflow tools — pattern is identical across all three:

1. **Trigger**: Schedule every 60 seconds.
2. **Action — HTTP Request**:
   - URL: `https://siemulator-y7uhf.ondigitalocean.app/qradar/api/siem/offenses?scenarios=all`
   - Method: `GET`
   - Headers: `SEC: qradar-dev-token`
3. **Action — Loop over items** (array body).
4. **Action — Branch by `_scenario_id`** or push each offence to your
   downstream tool (Slack alert, ticket-create, webhook to another
   workflow).

In Tines specifically, the `?scenarios=all` one-shot dedup means your
storyboard runs end-to-end with exactly 22 incidents, then quiesces —
useful for iterating on a workflow without re-creating 22 Jira
tickets every minute.

### Custom Python poller

Minimal reference — drop into any container, runs forever, prints
one line per ingested offence:

```python
"""Minimal siemulator → stdout poller. ~40 LOC, stdlib only.

Run with:
    python siemulator_poll.py https://siemulator-y7uhf.ondigitalocean.app qradar-dev-token
"""

from __future__ import annotations
import json, sys, time
import urllib.request, urllib.error


def poll(base_url: str, token: str, interval_s: int = 60) -> None:
    url = f"{base_url.rstrip('/')}/qradar/api/siem/offenses?scenarios=all"
    req = urllib.request.Request(url, headers={"SEC": token})
    seen: set[int] = set()
    while True:
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                offences = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            print(f"[{time.strftime('%H:%M:%S')}] poll failed: HTTP {e.code}", flush=True)
            time.sleep(interval_s)
            continue

        for o in offences:
            assert o.get("x-mock-source") == "siemulator", "non-mock data!"
            if o["id"] in seen:
                continue
            seen.add(o["id"])
            print(
                f"[{time.strftime('%H:%M:%S')}] "
                f"id={o['id']} scenario={o['_scenario_id']} "
                f"sev={o['severity']} desc={o['description'][:80]}",
                flush=True,
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    poll(sys.argv[1], sys.argv[2])
```

After 22 polls (~22 minutes), the pool drains; call
`/qradar/_debug/reset_scenarios` with the admin key if you want to
replay the whole library.

## Verification

After wiring up any of the recipes above, verify ingestion from both
sides:

**Siemulator side** — confirm your consumer is hitting the mock:

```bash
curl -H "X-Admin-Key: $ADMIN_KEY" \
  https://your-siemulator/qradar/_debug/recent \
  | jq '.requests[:5] | .[] | {ts, path, mode, response_count, client}'
```

This returns the last 100 requests siemulator saw — path, query
params, auth channel, response row count. If your consumer's user
agent / client IP doesn't show up here, the request isn't reaching
siemulator (firewall? wrong URL?).

**Consumer side** — confirm your tool can read the mock-source marker:

| Tool | Query |
|---|---|
| Splunk | `sourcetype=siemulator:offence "x-mock-source"="siemulator" \| stats count` |
| Sentinel | `siemulator_offence_CL \| where xmocksource_s == "siemulator" \| count` |
| Elastic | `tags:siemulator AND x-mock-source:siemulator` |
| XSOAR | filter incident by `labels.scenario_id:S*` |

If `x-mock-source` is missing or != `siemulator`, **stop the
ingestion** — something has either pointed your consumer at a real
SIEM by mistake, or rewritten the response in transit.

The pinning recommendation is to fail-closed: if a single ingested
record arrives without the marker, page the ingestion owner.

## Going to production

When you graduate from "exploring with the live demo" to "depending
on siemulator in CI / staging / a long-running test environment":

1. **Stand up your own instance.** Don't depend on the public demo URL
   for anything load-bearing. Deploy options are in the README §
   [Deploy on DigitalOcean App Platform](../README.md#deploy-on-digitalocean-app-platform);
   the Docker image is at `ghcr.io/sirp-labs/siemulator:latest`.

2. **Rotate the tokens.** The public demo uses `logscale-dev-token` /
   `qradar-dev-token` — public sentinels. Set `SIEMULATOR_LOGSCALE_TOKEN`
   and `SIEMULATOR_QRADAR_TOKEN` to fresh values
   (`openssl rand -hex 24`) on your own deploy.

3. **Set `SIEMULATOR_ADMIN_KEY`.** Without it, the `/qradar/_debug/*`
   endpoints return 403 (safe default). Set it if you want
   request-capture for ingestion debugging or scenario-set reset
   capability.

4. **Front it with HTTPS.** DO Apps does this automatically; on
   your own infra, terminate TLS upstream.

5. **Pin the `x-mock-source` marker** in every consumer's parser, with
   a fail-closed branch if the field is missing or != `siemulator`.
   This is your "the mock isn't accidentally proxying real data"
   guard.

6. **Don't multi-instance unless you don't use `?scenarios=all`.** The
   one-shot dedup state is per-process; running 2 instances behind a
   load balancer means each instance serves each scenario independently
   (your consumer sees the same offence twice). Stick to
   `instance_count: 1` for the one-shot mode; bump for shape-only soak
   testing where every poll returning random offences is fine.

7. **Snapshot-pin in CI.** Once your integration parses siemulator
   responses correctly, lock the parse shape with a contract test that
   fetches `/qradar/api/siem/offenses?scenarios=replay` and asserts
   on the field shape — that way if siemulator ever changes its output
   in a way that breaks your consumer, you find out in your test suite
   (not in production).

## Real-world deployments

- **sara-open** (the AI security assistant siemulator was extracted
  from) uses siemulator to drive its end-to-end agent-chain tests
  across the LogScale + QRadar surfaces. See
  [sara-open's cutover runbook](https://github.com/SIRP-Labs/sara-open/blob/main/docs/runbooks/siemulator-cutover.md)
  for the operational pattern of "shim a SIEM-mock dependency through
  a redirect, then cut over to the standalone service."

- Add yours via a PR — open an issue or PR at
  https://github.com/SIRP-Labs/siemulator with `INTEGRATION:`
  in the title and a one-paragraph description of how you're using it.
