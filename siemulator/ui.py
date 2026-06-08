"""Single-page web UI for siemulator.

A small landing page + interactive playground for the live API surface.
All HTML/CSS/JS is inlined here so the package stays "one repo, one
import, one image" — no static-files mount, no path concerns, no extra
files to ship in the Dockerfile.

Disable via ``SIEMULATOR_UI_ENABLED=false`` for production deployments
that want pure-API behaviour. When disabled, ``/`` falls back to the
JSON metadata response from ``siemulator.app.create_app``.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from siemulator import __version__
from siemulator.config import MOCK_SOURCE, logscale_prefix, qradar_prefix


def build_router() -> APIRouter:
    """Build a router that serves the UI at ``/`` and nothing else.

    The route factory captures the configured prefixes at construction
    time so the rendered HTML's hardcoded curl examples line up with
    whatever ``SIEMULATOR_LOGSCALE_PREFIX`` / ``SIEMULATOR_QRADAR_PREFIX``
    are set to.
    """
    router = APIRouter(tags=["ui"], include_in_schema=False)
    html = _render(
        version=__version__,
        mock_source=MOCK_SOURCE,
        logscale_prefix=logscale_prefix(),
        qradar_prefix=qradar_prefix(),
    )

    @router.get("/", response_class=HTMLResponse)
    async def landing() -> HTMLResponse:
        return HTMLResponse(content=html)

    return router


def _render(*, version: str, mock_source: str, logscale_prefix: str, qradar_prefix: str) -> str:
    """Render the single-page HTML with the configured prefixes baked in."""
    return _HTML_TEMPLATE.format(
        version=version,
        mock_source=mock_source,
        ls=logscale_prefix,
        qr=qradar_prefix,
    )


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>siemulator v{version} — synthetic SIEM endpoints</title>
<meta name="description" content="Synthetic SIEM endpoints in real-vendor shapes for SOAR / agent integration testing.">
<style>
  :root {{
    --bg: #0d1117;
    --bg-elev: #161b22;
    --bg-input: #0d1117;
    --border: #30363d;
    --border-soft: #21262d;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --text-soft: #7d8590;
    --accent: #58a6ff;
    --accent-hover: #79b8ff;
    --green: #3fb950;
    --orange: #d29922;
    --red: #f85149;
    --purple: #a371f7;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0;
    background: var(--bg); color: var(--text);
    font-family: var(--sans); font-size: 14px; line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ color: var(--accent-hover); text-decoration: underline; }}
  code, pre {{ font-family: var(--mono); font-size: 13px; }}
  .container {{ max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }}
  header {{ border-bottom: 1px solid var(--border-soft); padding-bottom: 24px; margin-bottom: 32px; }}
  .hero {{ display: flex; flex-wrap: wrap; align-items: baseline; gap: 12px; }}
  .hero h1 {{
    margin: 0; font-size: 28px; font-weight: 600; letter-spacing: -0.02em;
    color: var(--text);
  }}
  .hero .badge {{
    font-family: var(--mono); font-size: 12px;
    color: var(--text-dim); background: var(--bg-elev);
    padding: 2px 8px; border-radius: 4px;
    border: 1px solid var(--border-soft);
  }}
  .tagline {{
    color: var(--text-dim); font-size: 16px;
    margin: 12px 0 16px; max-width: 720px;
  }}
  .links {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
  .links a {{
    display: inline-block; padding: 4px 10px;
    border: 1px solid var(--border); border-radius: 6px;
    font-size: 13px; color: var(--text-dim);
  }}
  .links a:hover {{ border-color: var(--accent); color: var(--accent); text-decoration: none; }}
  .links a.primary {{ color: var(--accent); border-color: var(--accent); }}

  section {{
    background: var(--bg-elev); border: 1px solid var(--border-soft);
    border-radius: 8px; padding: 20px 24px; margin-bottom: 20px;
  }}
  section h2 {{
    margin: 0 0 12px; font-size: 15px; font-weight: 600;
    color: var(--text); text-transform: uppercase; letter-spacing: 0.05em;
  }}
  section h2 .count {{
    font-size: 12px; color: var(--text-dim);
    text-transform: none; letter-spacing: 0; font-weight: 400;
    margin-left: 6px;
  }}
  section p {{ color: var(--text-dim); margin: 6px 0 12px; }}
  .row {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }}
  .row > * {{ flex-shrink: 0; }}
  label {{
    display: block; font-size: 12px; color: var(--text-dim);
    margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em;
  }}
  input[type=text], input[type=password], select {{
    background: var(--bg-input); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 10px; font: 13px var(--mono);
    min-width: 200px;
  }}
  input:focus, select:focus {{ outline: none; border-color: var(--accent); }}
  button {{
    background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 14px; font: 13px var(--sans); font-weight: 500;
    cursor: pointer;
  }}
  button:hover {{ background: var(--border-soft); border-color: var(--text-dim); }}
  button.primary {{ background: var(--accent); color: #0d1117; border-color: var(--accent); }}
  button.primary:hover {{ background: var(--accent-hover); border-color: var(--accent-hover); }}
  button.small {{ padding: 2px 8px; font-size: 12px; }}
  button[disabled] {{ opacity: 0.5; cursor: not-allowed; }}

  pre.code {{
    background: var(--bg); color: var(--text);
    border: 1px solid var(--border-soft); border-radius: 6px;
    padding: 12px 14px; overflow-x: auto;
    margin: 8px 0; position: relative;
    white-space: pre; word-wrap: normal;
  }}
  pre.code .copy {{
    position: absolute; top: 6px; right: 6px;
    background: var(--bg-elev); color: var(--text-dim);
    border: 1px solid var(--border); border-radius: 4px;
    padding: 2px 8px; font-size: 11px; cursor: pointer;
    opacity: 0; transition: opacity 0.15s;
  }}
  pre.code:hover .copy {{ opacity: 1; }}
  pre.code .copy:hover {{ color: var(--accent); border-color: var(--accent); }}
  pre.code .copy.copied {{ color: var(--green); border-color: var(--green); }}

  .chip-row {{
    display: flex; flex-wrap: wrap; gap: 6px;
    margin: 10px 0;
  }}
  .chip {{
    display: inline-flex; align-items: center;
    padding: 4px 10px; border-radius: 14px;
    background: var(--bg); border: 1px solid var(--border);
    font: 12px var(--mono); color: var(--text-dim);
    cursor: pointer; user-select: none;
  }}
  .chip:hover {{ border-color: var(--accent); color: var(--accent); }}
  .chip.active {{ background: var(--accent); color: #0d1117; border-color: var(--accent); }}
  .chip .id {{ font-weight: 600; margin-right: 6px; }}

  table {{
    width: 100%; border-collapse: collapse; margin: 8px 0;
    font-size: 13px;
  }}
  th, td {{
    text-align: left; padding: 8px 10px;
    border-bottom: 1px solid var(--border-soft);
  }}
  th {{
    color: var(--text-dim); font-weight: 500;
    text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em;
  }}
  td code {{ color: var(--accent); }}
  td .sev {{ font-size: 11px; padding: 1px 8px; border-radius: 10px; display: inline-block; }}
  td .sev.critical {{ color: var(--red); background: rgba(248,81,73,0.1); }}
  td .sev.high {{ color: var(--orange); background: rgba(210,153,34,0.1); }}
  td .sev.medium {{ color: var(--accent); background: rgba(88,166,255,0.1); }}

  .endpoint-list {{ font-family: var(--mono); font-size: 13px; }}
  .endpoint-list li {{
    list-style: none; padding: 4px 0;
    display: flex; gap: 10px; align-items: baseline;
  }}
  .endpoint-list .method {{
    display: inline-block; min-width: 44px;
    font-weight: 600; font-size: 11px;
    padding: 1px 6px; border-radius: 3px;
    text-align: center;
  }}
  .endpoint-list .method.get {{ color: var(--accent); background: rgba(88,166,255,0.1); }}
  .endpoint-list .method.post {{ color: var(--green); background: rgba(63,185,80,0.1); }}
  .endpoint-list .path {{ color: var(--text); }}
  .endpoint-list .note {{ color: var(--text-dim); font-size: 12px; }}

  .scenario-detail {{ margin-top: 12px; }}
  .scenario-detail .header {{
    color: var(--text); font-weight: 600; font-size: 14px;
    margin-bottom: 4px;
  }}
  .scenario-detail .sub {{ color: var(--text-dim); font-size: 12px; margin-bottom: 8px; }}
  .scenario-row {{
    border-left: 2px solid var(--border); padding: 6px 0 6px 12px;
    margin: 4px 0; font-size: 13px;
  }}
  .scenario-row .row-id {{
    font-family: var(--mono); color: var(--text-dim);
    margin-right: 8px;
  }}
  .scenario-row .row-source {{
    color: var(--purple); font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.05em;
    margin-right: 8px;
  }}

  details summary {{
    cursor: pointer; user-select: none;
    color: var(--text-dim); font-size: 12px;
    padding: 4px 0;
  }}
  details summary:hover {{ color: var(--text); }}
  details[open] summary {{ color: var(--text); }}

  .response-area {{
    background: var(--bg); border: 1px solid var(--border-soft);
    border-radius: 6px; padding: 12px 14px;
    font: 12px var(--mono); color: var(--text);
    max-height: 480px; overflow: auto;
    margin-top: 12px;
  }}
  .response-area.empty {{ color: var(--text-dim); font-style: italic; }}
  .response-meta {{
    display: flex; gap: 16px; align-items: center;
    color: var(--text-dim); font-size: 12px;
    margin-bottom: 8px;
  }}
  .response-meta .status.ok {{ color: var(--green); }}
  .response-meta .status.fail {{ color: var(--red); }}

  footer {{
    margin-top: 48px; padding-top: 24px;
    border-top: 1px solid var(--border-soft);
    color: var(--text-dim); font-size: 12px;
    text-align: center;
  }}
  footer a {{ color: var(--text-dim); border-bottom: 1px dotted var(--border); }}
  footer a:hover {{ color: var(--accent); border-color: var(--accent); }}

  @media (max-width: 600px) {{
    .container {{ padding: 16px; }}
    .hero h1 {{ font-size: 22px; }}
    input[type=text], input[type=password], select {{ min-width: 0; width: 100%; }}
    .row {{ flex-direction: column; align-items: stretch; }}
  }}
</style>
</head>
<body>
<div class="container">

<header>
  <div class="hero">
    <h1>siemulator</h1>
    <span class="badge">v{version}</span>
    <span class="badge" style="color:var(--green)">● live</span>
  </div>
  <p class="tagline">
    Synthetic SIEM endpoints in real-vendor shapes — for SOAR / agent
    integration testing without touching real customer data.
  </p>
  <div class="links">
    <a class="primary" href="https://github.com/SIRP-Labs/siemulator" target="_blank" rel="noopener">GitHub ↗</a>
    <a href="https://github.com/SIRP-Labs/siemulator/blob/main/docs/ingestion-guide.md" target="_blank" rel="noopener">Ingestion guide ↗</a>
    <a href="/docs" target="_blank">OpenAPI docs</a>
    <a href="{ls}/api/v1/status">{ls}/api/v1/status</a>
    <a href="{qr}/api/help">{qr}/api/help</a>
  </div>
</header>

<section>
  <h2>Quickstart</h2>
  <p>
    Paste a token to populate every curl example with your value, then
    run them in-browser via the <strong>Try it</strong> panel below.
    Defaults assume the local-dev token <code>logscale-dev-token</code> /
    <code>qradar-dev-token</code>.
  </p>
  <div class="row">
    <div style="flex:1; min-width:260px;">
      <label for="tok-ls">LogScale token</label>
      <input id="tok-ls" type="text" value="logscale-dev-token" oninput="renderCurls()" style="width:100%;">
    </div>
    <div style="flex:1; min-width:260px;">
      <label for="tok-qr">QRadar token</label>
      <input id="tok-qr" type="text" value="qradar-dev-token" oninput="renderCurls()" style="width:100%;">
    </div>
  </div>

  <p style="margin-top:16px;">Health (no auth required):</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-health"></span></pre>

  <p>LogScale alerts:</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-ls"></span></pre>

  <p>QRadar offences (5 synthetic):</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-qr"></span></pre>

  <p>All 22 multi-source attack scenarios at once:</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-sc"></span></pre>
</section>

<section>
  <h2>Try it <span class="count">live against this host</span></h2>
  <p>Runs same-origin against the API you're already looking at. No CORS, no relay.</p>
  <div class="row">
    <div>
      <label for="try-endpoint">Endpoint</label>
      <select id="try-endpoint" onchange="renderTryDefaults()">
        <option value="ls-status">GET {ls}/api/v1/status (no auth)</option>
        <option value="ls-alerts">GET {ls}/api/v1/repositories/detections/alerts (Bearer)</option>
        <option value="ls-query">GET {ls}/api/v1/repositories/detections/query (Bearer)</option>
        <option value="qr-help">GET {qr}/api/help (no auth)</option>
        <option value="qr-offenses">GET {qr}/api/siem/offenses (SEC)</option>
        <option value="qr-scenarios-all">GET {qr}/api/siem/offenses?scenarios=all (SEC)</option>
        <option value="qr-scenarios">GET {qr}/api/siem/scenarios (SEC)</option>
      </select>
    </div>
    <div>
      <label for="try-limit">Limit / range</label>
      <input id="try-limit" type="text" value="3" style="min-width:80px;">
    </div>
    <div style="align-self:flex-end;">
      <button class="primary" onclick="runTry()">Run ▶</button>
    </div>
  </div>
  <div id="try-meta" class="response-meta" style="display:none;"></div>
  <div id="try-response" class="response-area empty">Response will appear here.</div>
</section>

<section>
  <h2>Multi-source attack scenarios <span class="count" id="sc-count">loading…</span></h2>
  <p>
    Twenty-two hand-crafted offences across two batches.
    <strong>S1–S5</strong> are multi-alert narrative chains (e.g. S1 spans 5 alerts
    across Proofpoint → Defender → CrowdStrike → Zscaler);
    <strong>TEST-A&nbsp;through TEST-J</strong> are single-offence
    advanced-tradecraft scenarios. Click a chip to expand.
  </p>
  <div id="sc-chips" class="chip-row">
    <span class="chip" style="cursor:default;">loading…</span>
  </div>
  <div id="sc-detail" class="scenario-detail"></div>
</section>

<section>
  <h2>Detection templates <span class="count">6 · MITRE ATT&amp;CK mapped</span></h2>
  <p>
    Rotating pool drawn from by LogScale <code>/alerts</code> and QRadar
    default-mode <code>/offenses</code>. Every alert response picks a
    random template; multi-response polls show variety across the pool.
  </p>
  <table>
    <thead>
      <tr><th>Tactic</th><th>Technique</th><th>DetectName</th><th>Severity</th></tr>
    </thead>
    <tbody>
      <tr><td><code>TA0006</code> Credential Access</td><td><code>T1003.001</code> LSASS Memory</td><td>Credential Dumping via Mimikatz</td><td><span class="sev critical">Critical</span></td></tr>
      <tr><td><code>TA0002</code> Execution</td><td><code>T1059.001</code> PowerShell</td><td>Suspicious PowerShell with Base64 Encoded Command</td><td><span class="sev high">High</span></td></tr>
      <tr><td><code>TA0008</code> Lateral Movement</td><td><code>T1021.002</code> SMB Admin Shares</td><td>Lateral Movement via PsExec</td><td><span class="sev high">High</span></td></tr>
      <tr><td><code>TA0001</code> Initial Access</td><td><code>T1566.001</code> Spearphishing Attachment</td><td>Phishing — Suspicious Outlook Attachment</td><td><span class="sev medium">Medium</span></td></tr>
      <tr><td><code>TA0011</code> Command and Control</td><td><code>T1071.001</code> Web Protocols</td><td>Beaconing C2 Traffic to Known Bad Domain</td><td><span class="sev critical">Critical</span></td></tr>
      <tr><td><code>TA0003</code> Persistence</td><td><code>T1547.001</code> Registry Run Keys</td><td>Suspicious File Write to Startup Folder</td><td><span class="sev medium">Medium</span></td></tr>
    </tbody>
  </table>
</section>

<section>
  <h2>Endpoint inventory</h2>
  <ul class="endpoint-list">
    <li><span class="method get">GET</span><span class="path">{ls}/api/v1/status</span><span class="note">health (no auth)</span></li>
    <li><span class="method get">GET</span><span class="path">{ls}/api/v1/repositories</span><span class="note">list repos (no auth)</span></li>
    <li><span class="method get">GET</span><span class="path">{ls}/api/v1/repositories/{{repo}}/alerts?limit=N</span></li>
    <li><span class="method get">GET</span><span class="path">{ls}/api/v1/repositories/{{repo}}/query?q=&amp;limit=N</span></li>
    <li><span class="method post">POST</span><span class="path">{ls}/api/v1/repositories/{{repo}}/queryjobs</span></li>
    <li><span class="method get">GET</span><span class="path">{ls}/api/v1/repositories/{{repo}}/queryjobs/{{id}}</span></li>
    <li>&nbsp;</li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/help</span><span class="note">health (no auth)</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/offenses</span><span class="note">?scenarios=all|batch|replay|mix</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/offenses/{{id}}</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/scenarios</span><span class="note">all 22 narratives</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/source_addresses</span></li>
    <li><span class="method post">POST</span><span class="path">{qr}/api/ariel/searches</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/ariel/searches/{{id}}</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/ariel/searches/{{id}}/results</span></li>
  </ul>
  <details>
    <summary>Admin debug endpoints (require <code>X-Admin-Key</code>)</summary>
    <ul class="endpoint-list" style="margin-top:8px;">
      <li><span class="method get">GET</span><span class="path">{qr}/_debug/recent</span><span class="note">last 100 requests</span></li>
      <li><span class="method post">POST</span><span class="path">{qr}/_debug/reset_scenarios</span><span class="note">clear served-set so ?scenarios=all replays</span></li>
      <li><span class="method get">GET</span><span class="path">{qr}/_debug/scenarios_state</span><span class="note">served vs remaining</span></li>
    </ul>
    <p style="margin-top:8px;">Set <code>X-Admin-Key</code> here to probe:</p>
    <div class="row">
      <input id="admin-key" type="password" placeholder="X-Admin-Key" style="flex:1; min-width:240px;">
      <button onclick="runAdmin('recent')">/_debug/recent</button>
      <button onclick="runAdmin('scenarios_state')">/_debug/scenarios_state</button>
    </div>
    <div id="admin-meta" class="response-meta" style="display:none;"></div>
    <div id="admin-response" class="response-area empty">Admin response will appear here.</div>
  </details>
</section>

<footer>
  <p>
    <code>x-mock-source: {mock_source}</code> ·
    <a href="https://github.com/SIRP-Labs/siemulator" target="_blank" rel="noopener">SIRP-Labs/siemulator</a> ·
    <a href="https://github.com/SIRP-Labs/siemulator/blob/main/LICENSE" target="_blank" rel="noopener">MIT</a>
  </p>
  <p style="margin-top:8px; color:var(--text-soft);">
    This is a mock. Every response is synthetic. Never feed it into a real detection pipeline.
  </p>
</footer>

</div>

<script>
const LS = "{ls}";
const QR = "{qr}";

function getTok(kind) {{
  return document.getElementById("tok-" + kind).value || (kind === "ls" ? "logscale-dev-token" : "qradar-dev-token");
}}

function escapeHtml(s) {{
  return String(s).replace(/[&<>"']/g, c => ({{
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }})[c]);
}}

function renderCurls() {{
  const lsTok = getTok("ls");
  const qrTok = getTok("qr");
  const origin = window.location.origin;
  document.getElementById("curl-health").textContent =
    `curl ${{origin}}${{LS}}/api/v1/status`;
  document.getElementById("curl-ls").textContent =
    `curl -H "Authorization: Bearer ${{lsTok}}" \\\\\\n  "${{origin}}${{LS}}/api/v1/repositories/detections/alerts?limit=3"`;
  document.getElementById("curl-qr").textContent =
    `curl -H "SEC: ${{qrTok}}" "${{origin}}${{QR}}/api/siem/offenses"`;
  document.getElementById("curl-sc").textContent =
    `curl "${{origin}}${{QR}}/api/siem/scenarios?token=${{qrTok}}"`;
}}

function copyCode(btn) {{
  const text = btn.parentElement.querySelector("span").textContent;
  navigator.clipboard.writeText(text).then(() => {{
    btn.textContent = "copied";
    btn.classList.add("copied");
    setTimeout(() => {{ btn.textContent = "copy"; btn.classList.remove("copied"); }}, 1200);
  }});
}}

function renderTryDefaults() {{
  const ep = document.getElementById("try-endpoint").value;
  const limitField = document.getElementById("try-limit");
  if (ep.startsWith("ls-status") || ep.startsWith("qr-help") || ep === "qr-scenarios") {{
    limitField.value = "";
    limitField.disabled = true;
  }} else if (ep === "qr-scenarios-all" || ep === "qr-offenses") {{
    limitField.disabled = false;
    limitField.value = limitField.value || "5";
  }} else {{
    limitField.disabled = false;
    limitField.value = limitField.value || "3";
  }}
}}

async function runTry() {{
  const ep = document.getElementById("try-endpoint").value;
  const limit = document.getElementById("try-limit").value.trim();
  const lsTok = getTok("ls");
  const qrTok = getTok("qr");
  let url = "", opts = {{}};

  if (ep === "ls-status") {{ url = LS + "/api/v1/status"; }}
  else if (ep === "ls-alerts") {{
    url = LS + "/api/v1/repositories/detections/alerts" + (limit ? `?limit=${{limit}}` : "");
    opts.headers = {{ "Authorization": "Bearer " + lsTok }};
  }} else if (ep === "ls-query") {{
    url = LS + "/api/v1/repositories/detections/query?q=*" + (limit ? `&limit=${{limit}}` : "");
    opts.headers = {{ "Authorization": "Bearer " + lsTok }};
  }} else if (ep === "qr-help") {{ url = QR + "/api/help"; }}
  else if (ep === "qr-offenses") {{
    url = QR + "/api/siem/offenses";
    opts.headers = {{ "SEC": qrTok }};
    if (limit) opts.headers["Range"] = `items=0-${{Math.max(0, parseInt(limit, 10) - 1)}}`;
  }} else if (ep === "qr-scenarios-all") {{
    url = QR + "/api/siem/offenses?scenarios=all";
    opts.headers = {{ "SEC": qrTok }};
  }} else if (ep === "qr-scenarios") {{
    url = QR + "/api/siem/scenarios";
    opts.headers = {{ "SEC": qrTok }};
  }}

  const respArea = document.getElementById("try-response");
  const metaArea = document.getElementById("try-meta");
  respArea.classList.remove("empty");
  respArea.textContent = "Loading…";
  metaArea.style.display = "none";

  const t0 = performance.now();
  try {{
    const resp = await fetch(url, opts);
    const ms = Math.round(performance.now() - t0);
    const body = await resp.text();
    let formatted = body;
    try {{ formatted = JSON.stringify(JSON.parse(body), null, 2); }} catch (e) {{}}
    metaArea.style.display = "flex";
    metaArea.innerHTML = `
      <span class="status ${{resp.ok ? "ok" : "fail"}}">${{resp.status}} ${{resp.statusText}}</span>
      <span>${{ms}} ms</span>
      <span>${{(body.length / 1024).toFixed(1)}} KB</span>
      <span style="color:var(--text-soft); margin-left:auto;">${{url}}</span>
    `;
    respArea.textContent = formatted;
  }} catch (e) {{
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status fail">network error</span><span>${{escapeHtml(e.message)}}</span>`;
    respArea.textContent = "";
  }}
}}

async function runAdmin(which) {{
  const key = document.getElementById("admin-key").value;
  const respArea = document.getElementById("admin-response");
  const metaArea = document.getElementById("admin-meta");
  respArea.classList.remove("empty");
  respArea.textContent = "Loading…";
  const url = QR + "/_debug/" + which;
  try {{
    const resp = await fetch(url, {{ headers: {{ "X-Admin-Key": key }} }});
    const body = await resp.text();
    let formatted = body;
    try {{ formatted = JSON.stringify(JSON.parse(body), null, 2); }} catch (e) {{}}
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status ${{resp.ok ? "ok" : "fail"}}">${{resp.status}} ${{resp.statusText}}</span><span style="margin-left:auto; color:var(--text-soft);">${{url}}</span>`;
    respArea.textContent = formatted;
  }} catch (e) {{
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status fail">network error</span><span>${{escapeHtml(e.message)}}</span>`;
    respArea.textContent = "";
  }}
}}

let scenariosCache = null;
async function loadScenarios() {{
  const qrTok = getTok("qr");
  try {{
    const resp = await fetch(QR + "/api/siem/scenarios", {{ headers: {{ "SEC": qrTok }} }});
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    scenariosCache = await resp.json();
    renderScenarioChips();
  }} catch (e) {{
    document.getElementById("sc-chips").innerHTML =
      `<span style="color:var(--red); font-size:12px;">Couldn't load scenarios: ${{escapeHtml(e.message)}}. Check QRadar token.</span>`;
  }}
}}

function renderScenarioChips() {{
  if (!scenariosCache) return;
  const groups = {{}};
  for (const s of scenariosCache) {{
    const id = s._scenario_id || "?";
    (groups[id] = groups[id] || []).push(s);
  }}
  const order = ["S1", "S2", "S3", "S4", "S5", "TEST-A", "TEST-B", "TEST-C", "TEST-D", "TEST-E", "TEST-F", "TEST-G", "TEST-H", "TEST-I", "TEST-J"];
  const chips = order.filter(id => groups[id]).map(id => {{
    const count = groups[id].length;
    return `<span class="chip" onclick="selectScenario('${{id}}')"><span class="id">${{id}}</span>${{count > 1 ? count + " alerts" : "1 offence"}}</span>`;
  }}).join("");
  document.getElementById("sc-chips").innerHTML = chips;
  document.getElementById("sc-count").textContent = `${{scenariosCache.length}} offences in ${{Object.keys(groups).length}} scenarios`;
  // Auto-select S1
  selectScenario("S1");
}}

function selectScenario(id) {{
  document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
  for (const c of document.querySelectorAll(".chip")) {{
    if (c.querySelector(".id") && c.querySelector(".id").textContent === id) c.classList.add("active");
  }}
  const matching = scenariosCache.filter(s => s._scenario_id === id);
  if (!matching.length) return;
  const detail = document.getElementById("sc-detail");
  const firstDesc = matching[0].description || "";
  const headerText = matching.length > 1
    ? `${{id}} — ${{matching.length}} correlated alerts`
    : `${{id}} — ${{firstDesc.split("—")[0].trim()}}`;
  detail.innerHTML = `
    <div class="header">${{escapeHtml(headerText)}}</div>
    <div class="sub">Offence IDs ${{matching[0].id}}${{matching.length > 1 ? "–" + matching[matching.length - 1].id : ""}} · stable across replays for dedup-by-ID</div>
    ${{matching.map(s => {{
      const src = s._raw_alert && s._raw_alert.source ? s._raw_alert.source : "(raw alert)";
      return `<div class="scenario-row">
        <span class="row-id">${{s.id}}</span>
        <span class="row-source">${{escapeHtml(src)}}</span>
        ${{escapeHtml(s.description.length > 220 ? s.description.slice(0, 220) + "…" : s.description)}}
        <details><summary>raw alert JSON</summary><pre style="margin:6px 0 0; font-size:11px; color:var(--text-dim); white-space:pre-wrap;">${{escapeHtml(JSON.stringify(s._raw_alert, null, 2))}}</pre></details>
      </div>`;
    }}).join("")}}
  `;
}}

renderCurls();
renderTryDefaults();
loadScenarios();
</script>
</body>
</html>
"""
