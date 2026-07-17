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
from siemulator.config import MOCK_SOURCE, logscale_prefix, qradar_prefix, splunk_prefix


def build_router() -> APIRouter:
    """Build a router that serves the UI at ``/`` and nothing else.

    The route factory captures the configured prefixes at construction
    time so the rendered HTML's hardcoded curl examples line up with
    whatever ``SIEMULATOR_LOGSCALE_PREFIX`` / ``SIEMULATOR_QRADAR_PREFIX``
    are set to.
    """
    router = APIRouter(tags=["ui"], include_in_schema=False)

    # Compute counts at render time — bake into the hero/stats.
    # No runtime fetch needed; numbers are facts about the deploy.
    from siemulator.scenarios import all_scenarios_as_qradar
    from siemulator.templates import ALERT_TEMPLATES

    scenarios = all_scenarios_as_qradar()
    scenario_count = len(scenarios)
    template_count = len(ALERT_TEMPLATES)
    scenario_group_count = len({s.get("_scenario_id") for s in scenarios if s.get("_scenario_id")})

    html = _render(
        version=__version__,
        mock_source=MOCK_SOURCE,
        logscale_prefix=logscale_prefix(),
        qradar_prefix=qradar_prefix(),
        splunk_prefix=splunk_prefix(),
        scenario_count=scenario_count,
        scenario_count_minus_one=scenario_count - 1,
        scenario_group_count=scenario_group_count,
        template_count=template_count,
    )

    @router.get("/", response_class=HTMLResponse)
    async def landing() -> HTMLResponse:
        return HTMLResponse(content=html)

    return router


def _render(
    *,
    version: str,
    mock_source: str,
    logscale_prefix: str,
    qradar_prefix: str,
    splunk_prefix: str,
    scenario_count: int,
    scenario_count_minus_one: int,
    scenario_group_count: int,
    template_count: int,
) -> str:
    """Render the single-page HTML with the configured prefixes baked in."""
    return _HTML_TEMPLATE.format(
        version=version,
        mock_source=mock_source,
        ls=logscale_prefix,
        qr=qradar_prefix,
        sp=splunk_prefix,
        scenario_count=scenario_count,
        scenario_count_minus_one=scenario_count_minus_one,
        scenario_group_count=scenario_group_count,
        template_count=template_count,
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

  /* ── Redesigned hero ─────────────────────────────────────── */
  header.hero-v2 {{
    border-bottom: none;
    padding: 56px 0 32px;
    margin-bottom: 24px;
    position: relative;
  }}
  header.hero-v2::before {{
    content: "";
    position: absolute; inset: 0;
    background:
      radial-gradient(circle at 20% 0%, rgba(88,166,255,0.08), transparent 50%),
      radial-gradient(circle at 80% 30%, rgba(163,113,247,0.06), transparent 50%);
    pointer-events: none;
    z-index: -1;
  }}
  .hero-title {{
    display: flex; align-items: baseline; gap: 14px;
    flex-wrap: wrap; margin-bottom: 8px;
  }}
  .hero-title h1 {{
    margin: 0; font-size: 48px; font-weight: 700;
    letter-spacing: -0.04em; line-height: 1;
    background: linear-gradient(135deg, var(--text) 0%, var(--accent) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }}
  .hero-title .badge {{ font-size: 12px; }}
  .hero-tagline {{
    font-size: 24px; font-weight: 500;
    color: var(--text); line-height: 1.3;
    margin: 12px 0 16px; max-width: 720px;
    letter-spacing: -0.015em;
  }}
  .hero-sub {{
    color: var(--text-dim); font-size: 16px;
    margin: 0 0 24px; max-width: 720px;
    line-height: 1.55;
  }}
  .hero-sub strong {{ color: var(--text); font-weight: 500; }}
  .hero-actions {{
    display: flex; flex-wrap: wrap; gap: 10px;
    margin-bottom: 32px;
  }}
  .hero-actions a {{
    display: inline-flex; align-items: center;
    padding: 8px 16px;
    border: 1px solid var(--border); border-radius: 8px;
    font-size: 14px; font-weight: 500;
    color: var(--text);
    transition: transform 0.1s, border-color 0.15s, background 0.15s;
  }}
  .hero-actions a:hover {{
    text-decoration: none;
    border-color: var(--text-dim);
    transform: translateY(-1px);
    background: var(--bg-elev);
  }}
  .hero-actions a.primary {{
    background: var(--accent); color: #0d1117;
    border-color: var(--accent);
  }}
  .hero-actions a.primary:hover {{
    background: var(--accent-hover);
    border-color: var(--accent-hover);
  }}

  /* ── Stats grid ─────────────────────────────────────────── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1px;
    background: var(--border-soft);
    border: 1px solid var(--border-soft);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 32px;
  }}
  .stat {{
    background: var(--bg-elev);
    padding: 22px 20px;
    text-align: center;
  }}
  .stat .value {{
    display: block;
    font-size: 32px; font-weight: 700;
    color: var(--text);
    letter-spacing: -0.02em;
    line-height: 1;
  }}
  .stat .label {{
    display: block;
    font-size: 11px; color: var(--text-dim);
    text-transform: uppercase; letter-spacing: 0.08em;
    margin-top: 6px;
  }}
  .stat.accent .value {{ color: var(--accent); }}
  .stat.green .value {{ color: var(--green); }}
  .stat.purple .value {{ color: var(--purple); }}
  .stat.orange .value {{ color: var(--orange); }}

  /* ── Features grid ──────────────────────────────────────── */
  .features-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 14px;
    margin: 12px 0 0;
  }}
  .feature {{
    background: var(--bg-elev);
    border: 1px solid var(--border-soft);
    border-radius: 10px;
    padding: 20px 22px;
    transition: border-color 0.15s, transform 0.1s;
  }}
  .feature:hover {{
    border-color: var(--border);
    transform: translateY(-2px);
  }}
  .feature .icon {{
    display: inline-flex;
    width: 32px; height: 32px;
    align-items: center; justify-content: center;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 16px; font-weight: 700;
    color: var(--accent);
    margin-bottom: 12px;
  }}
  .feature h3 {{
    margin: 0 0 6px; font-size: 14px; font-weight: 600;
    color: var(--text);
  }}
  .feature p {{
    margin: 0; font-size: 13px; line-height: 1.55;
    color: var(--text-dim);
  }}
  .feature code {{
    color: var(--accent); font-size: 12px;
    background: var(--bg);
    padding: 1px 6px; border-radius: 3px;
    border: 1px solid var(--border-soft);
  }}

  /* ── How it works diagram ───────────────────────────────── */
  .how-diagram {{
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: 8px;
    padding: 24px;
    margin: 16px 0;
    overflow-x: auto;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text);
    line-height: 1.5;
    white-space: pre;
  }}
  .how-diagram .label {{ color: var(--text-dim); }}
  .how-diagram .arrow {{ color: var(--accent); }}
  .how-diagram .box {{ color: var(--purple); }}
  .how-diagram .surface {{ color: var(--green); }}

  /* ── Use cases ──────────────────────────────────────────── */
  .usecase-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 14px;
    margin: 12px 0 0;
  }}
  .usecase {{
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: 8px;
    padding: 18px 20px;
  }}
  .usecase .who {{
    font-size: 11px; color: var(--accent);
    text-transform: uppercase; letter-spacing: 0.08em;
    font-weight: 600;
    margin-bottom: 6px;
  }}
  .usecase h3 {{
    margin: 0 0 8px; font-size: 15px; font-weight: 600;
    color: var(--text);
  }}
  .usecase p {{
    margin: 0; font-size: 13px; line-height: 1.55;
    color: var(--text-dim);
  }}
  .usecase .impl {{
    margin-top: 10px; padding-top: 10px;
    border-top: 1px dashed var(--border-soft);
    font-size: 12px; color: var(--text-soft);
  }}
  .usecase .impl code {{
    background: transparent; color: var(--accent);
    font-size: 11px;
  }}

  /* ── Improved footer ────────────────────────────────────── */
  footer.footer-v2 {{
    margin-top: 64px;
    padding: 32px 0 24px;
    border-top: 1px solid var(--border-soft);
    text-align: left;
  }}
  .footer-cols {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 24px;
    margin-bottom: 24px;
  }}
  .footer-col h4 {{
    margin: 0 0 10px; font-size: 11px;
    color: var(--text-dim);
    text-transform: uppercase; letter-spacing: 0.1em;
    font-weight: 600;
  }}
  .footer-col a {{
    display: block; color: var(--text-dim);
    font-size: 13px; margin-bottom: 5px;
    border-bottom: none;
  }}
  .footer-col a:hover {{ color: var(--accent); }}
  .footer-bottom {{
    padding-top: 20px;
    border-top: 1px solid var(--border-soft);
    color: var(--text-soft); font-size: 12px;
    display: flex; flex-wrap: wrap;
    justify-content: space-between; gap: 12px;
    align-items: center;
  }}
  .footer-bottom code {{
    background: var(--bg-elev);
    padding: 2px 8px; border-radius: 4px;
    border: 1px solid var(--border-soft);
    color: var(--text-dim); font-size: 11px;
  }}

  @media (max-width: 600px) {{
    .hero-title h1 {{ font-size: 36px; }}
    .hero-tagline {{ font-size: 18px; }}
    .stat .value {{ font-size: 24px; }}
  }}

  /* ── Hero split (text left, JSON preview right) ────────── */
  .hero-split {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 40px;
    align-items: start;
    margin-bottom: 32px;
  }}
  @media (max-width: 900px) {{
    .hero-split {{ grid-template-columns: 1fr; gap: 28px; }}
  }}

  /* ── Shields.io badges row ─────────────────────────────── */
  .hero-shields {{
    display: flex; flex-wrap: wrap; gap: 8px;
    margin: 16px 0 0;
    align-items: center;
  }}
  .hero-shields img {{
    display: block; height: 22px; border-radius: 4px;
    opacity: 0.95;
    transition: opacity 0.15s, transform 0.1s;
  }}
  .hero-shields a:hover img {{ opacity: 1; transform: translateY(-1px); }}

  /* ── Hero JSON preview card ────────────────────────────── */
  .hero-preview {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    box-shadow:
      0 8px 32px rgba(0,0,0,0.45),
      0 0 0 1px rgba(88,166,255,0.06);
  }}
  .preview-header {{
    background: var(--bg-elev);
    padding: 10px 16px;
    display: flex; align-items: center; gap: 12px;
    border-bottom: 1px solid var(--border);
    font: 12px var(--mono);
  }}
  .preview-dots {{ display: inline-flex; gap: 6px; }}
  .preview-dots span {{
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--border);
  }}
  .preview-dots span:nth-child(1) {{ background: #f85149; }}
  .preview-dots span:nth-child(2) {{ background: #d29922; }}
  .preview-dots span:nth-child(3) {{ background: #3fb950; }}
  .preview-header .method {{ color: var(--accent); font-weight: 600; }}
  .preview-header .url {{
    color: var(--text-dim);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    flex: 1;
  }}
  .preview-header .status {{
    background: rgba(63,185,80,0.15);
    color: var(--green);
    padding: 2px 9px; border-radius: 4px;
    font-size: 11px; font-weight: 600;
  }}
  .preview-body {{
    margin: 0; padding: 18px 20px;
    font: 12.5px/1.6 var(--mono);
    color: var(--text);
    overflow-x: auto;
    max-height: 380px;
  }}
  .preview-body .k {{ color: var(--accent); }}
  .preview-body .s {{ color: var(--green); }}
  .preview-body .n {{ color: var(--orange); }}
  .preview-body .b {{ color: var(--purple); }}
  .preview-body .m {{ color: var(--text-soft); font-style: italic; }}

  /* ── How-it-works SVG diagram ──────────────────────────── */
  .how-svg {{
    display: block;
    width: 100%;
    max-width: 900px;
    height: auto;
    margin: 8px auto 16px;
  }}
  .how-svg .arrow-stroke {{ stroke: #58a6ff; stroke-width: 1.5; fill: none; }}
  .how-svg .consumer-rect {{ fill: #161b22; stroke: #58a6ff; stroke-width: 1.5; }}
  .how-svg .surface-rect {{ fill: #161b22; stroke: #30363d; stroke-width: 1; }}
  .how-svg .lib-rect {{ fill: #161b22; stroke: #a371f7; stroke-width: 1.5; }}
  .how-svg .label-primary {{ fill: #e6edf3; font-weight: 600; }}
  .how-svg .label-accent {{ fill: #3fb950; font-family: ui-monospace, monospace; font-weight: 600; }}
  .how-svg .label-purple {{ fill: #a371f7; font-weight: 700; }}
  .how-svg .label-sub {{ fill: #8b949e; }}
  .knobs-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    margin-top: 20px;
  }}
  .knob-group {{
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: 8px;
    padding: 14px 18px;
  }}
  .knob-group h4 {{
    margin: 0 0 10px;
    font-size: 11px; color: var(--text-dim);
    text-transform: uppercase; letter-spacing: 0.08em;
    font-weight: 600;
  }}
  .knob-group ul {{ margin: 0; padding: 0; list-style: none; }}
  .knob-group li {{
    padding: 4px 0;
    font: 12px var(--mono); color: var(--text-dim);
  }}
  .knob-group li strong {{ color: var(--accent); font-weight: 600; }}
</style>
</head>
<body>
<div class="container">

<header class="hero-v2">
  <div class="hero-split">
    <div class="hero-content">
      <div class="hero-title">
        <h1>siemulator</h1>
        <span class="badge">v{version}</span>
        <span class="badge" style="color:var(--green)">● live demo</span>
      </div>
      <p class="hero-tagline">
        Stop spinning up real SIEMs for integration tests.
      </p>
      <p class="hero-sub">
        Synthetic SIEM data in real-vendor shapes — SIEM aggregators
        (<strong>Falcon LogScale</strong>, <strong>IBM QRadar</strong>,
        <strong>Splunk Enterprise</strong>) plus vendor-native EDR/XDR
        envelopes (<strong>CrowdStrike Falcon</strong>,
        <strong>Microsoft Defender</strong>, <strong>RSA NetWitness</strong>).
        Chaos-engineering and regression-testing primitives baked in.
        <strong>{scenario_count} multi-source attack scenarios</strong>,
        record/replay/diff, real-time SSE push. Zero customer data —
        every response carries <code>x-mock-source: siemulator</code>.
      </p>
      <div class="hero-actions">
        <a class="primary" href="#try-it">▶ Try the live demo</a>
        <a href="https://github.com/SIRP-Labs/siemulator" target="_blank" rel="noopener">GitHub ↗</a>
        <a href="https://github.com/SIRP-Labs/siemulator/blob/main/docs/ingestion-guide.md" target="_blank" rel="noopener">Ingestion guide ↗</a>
        <a href="/docs" target="_blank">OpenAPI</a>
      </div>
      <div class="hero-shields">
        <a href="https://github.com/SIRP-Labs/siemulator/actions" target="_blank" rel="noopener">
          <img src="https://img.shields.io/github/actions/workflow/status/SIRP-Labs/siemulator/ci.yml?branch=main&amp;label=tests&amp;style=flat-square&amp;logo=githubactions&amp;logoColor=white" alt="CI build status">
        </a>
        <a href="https://github.com/SIRP-Labs/siemulator/blob/main/LICENSE" target="_blank" rel="noopener">
          <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License">
        </a>
        <a href="https://github.com/SIRP-Labs/siemulator/stargazers" target="_blank" rel="noopener">
          <img src="https://img.shields.io/github/stars/SIRP-Labs/siemulator?style=flat-square&amp;logo=github&amp;label=stars" alt="GitHub stars">
        </a>
        <a href="https://github.com/SIRP-Labs/siemulator/pkgs/container/siemulator" target="_blank" rel="noopener">
          <img src="https://img.shields.io/badge/ghcr.io-sirp--labs%2Fsiemulator-blue?style=flat-square&amp;logo=docker&amp;logoColor=white" alt="GHCR image">
        </a>
      </div>
    </div>
    <div class="hero-preview" aria-label="Sample API response">
      <div class="preview-header">
        <span class="preview-dots"><span></span><span></span><span></span></span>
        <span class="method">GET</span>
        <span class="url">{qr}/api/siem/offenses?scenarios=replay</span>
        <span class="status">200 OK</span>
      </div>
<pre class="preview-body"><span class="m">// One of {scenario_count} scenarios — stable IDs survive replays</span>
[
  {{
    <span class="k">"id"</span>: <span class="n">90011</span>,
    <span class="k">"offense_id"</span>: <span class="n">90011</span>,
    <span class="k">"_scenario_id"</span>: <span class="s">"S1"</span>,
    <span class="k">"description"</span>: <span class="s">"Living-off-the-Land Supply Chain — Proofpoint"</span>,
    <span class="k">"severity"</span>: <span class="n">5</span>,
    <span class="k">"start_time"</span>: <span class="n">1780839721000</span>,
    <span class="k">"categories"</span>: [<span class="s">"S1"</span>, <span class="s">"Sophisticated-Test"</span>],
    <span class="k">"_raw_alert"</span>: {{
      <span class="k">"source"</span>: <span class="s">"Proofpoint TAP"</span>,
      <span class="k">"event_type"</span>: <span class="s">"MessagesDelivered"</span>,
      <span class="k">"timestamp"</span>: <span class="s">"2026-05-22T08:14:22Z"</span>
    }},
    <span class="k">"x-mock-source"</span>: <span class="s">"siemulator"</span>
  }},
  <span class="m">// + {scenario_count_minus_one} more</span>
]</pre>
    </div>
  </div>
  <div class="stats-grid">
    <div class="stat accent">
      <span class="value">{scenario_count}</span>
      <span class="label">Scenarios</span>
    </div>
    <div class="stat purple">
      <span class="value">{scenario_group_count}</span>
      <span class="label">Narrative chains</span>
    </div>
    <div class="stat green">
      <span class="value">3</span>
      <span class="label">Vendor shapes</span>
    </div>
    <div class="stat orange">
      <span class="value">{template_count}</span>
      <span class="label">Templates</span>
    </div>
    <div class="stat">
      <span class="value">156</span>
      <span class="label">Contract tests</span>
    </div>
    <div class="stat">
      <span class="value">3</span>
      <span class="label">Auth channels</span>
    </div>
  </div>
</header>

<section>
  <h2>Features</h2>
  <p>Everything you need to pin SOAR / agent integration behavior, without standing up real SIEMs.</p>
  <div class="features-grid">
    <div class="feature">
      <span class="icon">⚡</span>
      <h3>Six real-vendor REST shapes</h3>
      <p>SIEM aggregators — Falcon LogScale (Humio REST), IBM QRadar (offences + Ariel), Splunk Enterprise (search jobs + oneshot). Vendor-native EDR/XDR — CrowdStrike Falcon Streaming, Microsoft Defender Graph Security, RSA NetWitness SA. Consumers drop in unchanged — same fields, same envelopes.</p>
    </div>
    <div class="feature">
      <span class="icon">🎯</span>
      <h3>{scenario_count} stable scenarios</h3>
      <p>Multi-source attack narratives (S1–S5), advanced tradecraft (TEST), synthetic-IOC fixtures (DEMO), pentest chains (SCAN), TI-confirmed (ENRICH). Each carries a stable <code>_scenario_id</code> + offence ID for dedup.</p>
    </div>
    <div class="feature">
      <span class="icon">🌊</span>
      <h3>SSE push surface</h3>
      <p>Real-time alert streaming via <code>EventSource</code>. Configurable rate, method-preserving, with monotonic event IDs. Test push-style ingestion in your SOAR without polling.</p>
    </div>
    <div class="feature">
      <span class="icon">🧨</span>
      <h3>Chaos engineering</h3>
      <p>Inject configurable faults — <code>?inject_status=503</code>, latency, malformed JSON. Three layers: per-request, env-default, live admin dials. Validate your consumer's failure handling.</p>
    </div>
    <div class="feature">
      <span class="icon">📼</span>
      <h3>Record / replay / diff</h3>
      <p>Capture every (request, response) pair. Diff two consumer-version runs to detect behavior regressions. Replay captured responses verbatim to snapshot-pin siemulator's own output.</p>
    </div>
    <div class="feature">
      <span class="icon">🔒</span>
      <h3>Token-redacting access log</h3>
      <p>Per-request capture (timestamp, path, status, latency, IP, UA) with auth channels logged as names only — Bearer / SEC / query token values are <em>never</em> stored. Pinned by regression test.</p>
    </div>
  </div>
</section>

<section>
  <h2>How it works</h2>
  <p>One process, three surface mounts, one shared scenario library. No external dependencies. <code>pip install</code> or <code>docker run</code> and you're done.</p>
  <svg class="how-svg" viewBox="0 0 880 280" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Architecture diagram">
    <defs>
      <marker id="arrowhead" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
        <path d="M 0 0 L 8 3 L 0 6 z" fill="#58a6ff"/>
      </marker>
    </defs>

    <!-- Consumer box -->
    <rect class="consumer-rect" x="20" y="100" width="180" height="80" rx="10"/>
    <text class="label-primary" x="110" y="135" text-anchor="middle" font-size="14">Your consumer</text>
    <text class="label-sub" x="110" y="156" text-anchor="middle" font-size="11">SOAR · agent · CI</text>

    <!-- Arrows consumer → 3 surfaces -->
    <path class="arrow-stroke" d="M 200 130 Q 240 60 290 60" marker-end="url(#arrowhead)"/>
    <path class="arrow-stroke" d="M 200 140 L 290 140" marker-end="url(#arrowhead)"/>
    <path class="arrow-stroke" d="M 200 150 Q 240 220 290 220" marker-end="url(#arrowhead)"/>

    <!-- 3 surface boxes -->
    <rect class="surface-rect" x="295" y="30" width="220" height="60" rx="8"/>
    <text class="label-accent" x="405" y="55" text-anchor="middle" font-size="14">/logscale/*</text>
    <text class="label-sub" x="405" y="74" text-anchor="middle" font-size="11">Falcon LogScale · Humio REST</text>

    <rect class="surface-rect" x="295" y="110" width="220" height="60" rx="8"/>
    <text class="label-accent" x="405" y="135" text-anchor="middle" font-size="14">/qradar/*</text>
    <text class="label-sub" x="405" y="154" text-anchor="middle" font-size="11">IBM QRadar · offences + Ariel</text>

    <rect class="surface-rect" x="295" y="190" width="220" height="60" rx="8"/>
    <text class="label-accent" x="405" y="215" text-anchor="middle" font-size="14">/splunk/*</text>
    <text class="label-sub" x="405" y="234" text-anchor="middle" font-size="11">Splunk Enterprise · REST search</text>

    <!-- Arrows surfaces → library -->
    <path class="arrow-stroke" d="M 515 60 Q 580 100 625 130" marker-end="url(#arrowhead)"/>
    <path class="arrow-stroke" d="M 515 140 L 625 140" marker-end="url(#arrowhead)"/>
    <path class="arrow-stroke" d="M 515 220 Q 580 180 625 150" marker-end="url(#arrowhead)"/>

    <!-- Library box -->
    <rect class="lib-rect" x="630" y="80" width="230" height="120" rx="12"/>
    <text class="label-purple" x="745" y="115" text-anchor="middle" font-size="14">Scenario library</text>
    <text class="label-primary" x="745" y="142" text-anchor="middle" font-size="15" font-weight="700">{scenario_count} scenarios</text>
    <text class="label-primary" x="745" y="162" text-anchor="middle" font-size="13">{template_count} detection templates</text>
    <text class="label-sub" x="745" y="184" text-anchor="middle" font-size="11">MITRE ATT&amp;CK mapped</text>
  </svg>

  <div class="knobs-grid">
    <div class="knob-group">
      <h4>Three knobs at every layer</h4>
      <ul>
        <li><strong>Auth</strong>  Bearer · SEC · ?token=</li>
        <li><strong>Mode</strong>  ?scenarios=all|batch|replay|mix</li>
        <li><strong>Faults</strong>  ?inject_status / ?inject_latency / ?inject_malformed</li>
      </ul>
    </div>
    <div class="knob-group">
      <h4>Per-request meta-channels</h4>
      <ul>
        <li><strong>Replay</strong>  ?replay_from=&lt;session&gt;</li>
        <li><strong>Capture</strong>  POST /api/sessions/&lt;name&gt;/start</li>
        <li><strong>Observe</strong>  GET /api/access-log/stats</li>
      </ul>
    </div>
  </div>
</section>

<section>
  <h2>Use cases</h2>
  <div class="usecase-grid">
    <div class="usecase">
      <div class="who">For SOAR vendors</div>
      <h3>Validate ingestion across SIEM shapes</h3>
      <p>Point your XSOAR / Splunk SOAR / Resilient connector at siemulator and exercise three vendor shapes from one fixture. Snapshot-pin the response shape in CI.</p>
      <div class="impl">→ <code>?scenarios=all</code> + <code>/api/sessions/&lt;run&gt;/start</code></div>
    </div>
    <div class="usecase">
      <div class="who">For detection engineers</div>
      <h3>Drive playbooks deterministically</h3>
      <p>{scenario_count} scenarios with stable offence IDs let you reproduce the same incident stream every CI run. Diff two consumer versions to catch regressions before prod.</p>
      <div class="impl">→ <code>GET /api/sessions/diff?a=v1&amp;b=v2</code></div>
    </div>
    <div class="usecase">
      <div class="who">For AI security teams</div>
      <h3>Test agent chains end-to-end</h3>
      <p>Multi-source narratives (S1: Proofpoint→Defender→CrowdStrike→Zscaler) let agents practice correlation across vendors. Real-TI fixtures (ENRICH) test the enrichment path.</p>
      <div class="impl">→ <code>?scenarios=batch</code> for slow-drip / <code>?scenarios=replay</code> for bulk</div>
    </div>
    <div class="usecase">
      <div class="who">For training labs</div>
      <h3>Reproducible analyst exercises</h3>
      <p>Reset the served-scenarios set, replay the same chain every cohort. EICAR + WannaCry + Tor egress + Shodan scanner cover the full disposition spectrum.</p>
      <div class="impl">→ <code>POST /qradar/_debug/reset_scenarios</code></div>
    </div>
  </div>
</section>

<section id="quickstart">
  <h2>Quickstart</h2>
  <p>
    Paste a token to populate every curl example with your value, then
    run them in-browser via the <strong>Try it</strong> panel below.
    Defaults assume the local-dev token <code>logscale-dev-token</code> /
    <code>qradar-dev-token</code>.
  </p>
  <div class="row">
    <div style="flex:1; min-width:200px;">
      <label for="tok-ls">LogScale token</label>
      <input id="tok-ls" type="text" value="logscale-dev-token" oninput="renderCurls()" style="width:100%;">
    </div>
    <div style="flex:1; min-width:200px;">
      <label for="tok-qr">QRadar token</label>
      <input id="tok-qr" type="text" value="qradar-dev-token" oninput="renderCurls()" style="width:100%;">
    </div>
    <div style="flex:1; min-width:200px;">
      <label for="tok-sp">Splunk token</label>
      <input id="tok-sp" type="text" value="splunk-dev-token" oninput="renderCurls()" style="width:100%;">
    </div>
  </div>

  <p style="margin-top:16px;">Health (no auth required):</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-health"></span></pre>

  <p>LogScale alerts:</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-ls"></span></pre>

  <p>QRadar offences (5 synthetic):</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-qr"></span></pre>

  <p>All 38 multi-source attack scenarios at once:</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-sc"></span></pre>

  <p>Splunk oneshot search:</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span id="curl-sp"></span></pre>
</section>

<section id="try-it">
  <h2>Try it <span class="count">live against this host</span></h2>
  <p>Runs same-origin against the API you're already looking at. No CORS, no relay.</p>
  <div class="row">
    <div>
      <label for="try-endpoint">Endpoint</label>
      <select id="try-endpoint" onchange="renderTryDefaults()">
        <optgroup label="LogScale">
          <option value="ls-status">GET {ls}/api/v1/status (no auth)</option>
          <option value="ls-alerts">GET {ls}/api/v1/repositories/detections/alerts (Bearer)</option>
          <option value="ls-query">GET {ls}/api/v1/repositories/detections/query (Bearer)</option>
        </optgroup>
        <optgroup label="QRadar">
          <option value="qr-help">GET {qr}/api/help (no auth)</option>
          <option value="qr-offenses">GET {qr}/api/siem/offenses (SEC)</option>
          <option value="qr-scenarios-all">GET {qr}/api/siem/offenses?scenarios=all (SEC)</option>
          <option value="qr-scenarios">GET {qr}/api/siem/scenarios (SEC)</option>
        </optgroup>
        <optgroup label="Splunk">
          <option value="sp-info">GET {sp}/services/server/info (no auth)</option>
          <option value="sp-export">GET {sp}/services/search/jobs/export (Bearer)</option>
        </optgroup>
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
  <h2>Live alert ticker <span class="count">Server-Sent Events · same-origin</span></h2>
  <p>
    Streams synthetic alerts from <code>{ls}/api/v1/repositories/detections/stream</code>
    via the browser's <code>EventSource</code> API. One alert per
    <em>rate</em> seconds. Disconnects cleanly when you click Stop or
    leave the page.
  </p>
  <div class="row">
    <div>
      <label for="ticker-rate">Rate (alerts/sec)</label>
      <input id="ticker-rate" type="text" value="1" style="min-width:80px;">
    </div>
    <div style="align-self:flex-end;">
      <button class="primary" id="ticker-toggle" onclick="toggleTicker()">▶ Start</button>
    </div>
    <div style="align-self:flex-end; color:var(--text-dim); font-size:12px;">
      <span id="ticker-count">0 alerts received</span>
    </div>
  </div>
  <div id="ticker-feed" class="response-area empty" style="max-height:240px;">
    Click <strong>Start</strong> to begin the live stream.
  </div>
</section>

<section>
  <h2>Failure injection <span class="count">chaos engineering · admin-gated</span></h2>
  <p>
    Inject configurable faults to test how your consumer handles
    5xx, rate-limits, slow responses, and corrupt JSON. Per-request
    overrides (anyone can use) attach a <code>?inject_…</code> param to any
    request. Live-tunable env-default % via the admin endpoints below.
  </p>
  <p style="margin-top:8px;">Try a one-shot fault on any endpoint:</p>
  <pre class="code"><button class="copy" onclick="copyCode(this)">copy</button><span>curl -i "{qr}/api/help?inject_status=503"
curl -i "{qr}/api/help?inject_latency=2000"
curl -i "{qr}/api/siem/offenses?inject_malformed=1" -H "SEC: qradar-dev-token"</span></pre>

  <p style="margin-top:16px;">Live-tune env-default fault rates (admin-key required):</p>
  <div class="row">
    <input id="faults-key" type="password" placeholder="X-Admin-Key" style="flex:1; min-width:200px;">
    <button onclick="getFaults()">Current config</button>
    <button onclick="resetFaults()">Reset to env</button>
  </div>
  <div class="row" style="margin-top:8px;">
    <div><label for="faults-5xx">5xx %</label><input id="faults-5xx" type="text" value="0" style="min-width:60px;"></div>
    <div><label for="faults-429">429 %</label><input id="faults-429" type="text" value="0" style="min-width:60px;"></div>
    <div><label for="faults-latency">Latency ms</label><input id="faults-latency" type="text" value="0" style="min-width:80px;"></div>
    <div><label for="faults-malformed">Malformed %</label><input id="faults-malformed" type="text" value="0" style="min-width:60px;"></div>
    <div style="align-self:flex-end;"><button class="primary" onclick="applyFaults()">Apply</button></div>
  </div>
  <div id="faults-meta" class="response-meta" style="display:none;"></div>
  <div id="faults-response" class="response-area empty">Faults config will appear here.</div>
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
    <li><span class="method get">GET</span><span class="path">{ls}/api/v1/repositories/{{repo}}/stream</span><span class="note">SSE push, ?rate=N&amp;max_count=N</span></li>
    <li>&nbsp;</li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/help</span><span class="note">health (no auth)</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/offenses</span><span class="note">?scenarios=all|batch|replay|mix</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/offenses/{{id}}</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/scenarios</span><span class="note">all 57 narratives</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/siem/source_addresses</span></li>
    <li><span class="method post">POST</span><span class="path">{qr}/api/ariel/searches</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/ariel/searches/{{id}}</span></li>
    <li><span class="method get">GET</span><span class="path">{qr}/api/ariel/searches/{{id}}/results</span></li>
    <li>&nbsp;</li>
    <li><span class="method get">GET</span><span class="path">/crowdstrike/api/v1/detects</span><span class="note">Falcon Streaming envelope (?scenarios=all|batch|replay)</span></li>
    <li><span class="method get">GET</span><span class="path">/defender/api/security/v1.0/alerts</span><span class="note">Microsoft Graph Security envelope</span></li>
    <li><span class="method get">GET</span><span class="path">/netwitness/api/v1/incidents</span><span class="note">RSA NetWitness SA envelope</span></li>
    <li><span class="method post">POST</span><span class="path">/_debug/reset_vendor?vendor=&lt;v&gt;|all</span><span class="note">clear per-vendor rotation/dedup</span></li>
    <li>&nbsp;</li>
    <li><span class="method get">GET</span><span class="path">{sp}/services/server/info</span><span class="note">health (no auth)</span></li>
    <li><span class="method post">POST</span><span class="path">{sp}/services/search/jobs</span><span class="note">async submit → {{sid}}</span></li>
    <li><span class="method get">GET</span><span class="path">{sp}/services/search/jobs/export</span><span class="note">oneshot synchronous</span></li>
    <li><span class="method get">GET</span><span class="path">{sp}/services/search/jobs/{{sid}}</span></li>
    <li><span class="method get">GET</span><span class="path">{sp}/services/search/jobs/{{sid}}/results</span></li>
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

<section>
  <h2>Record / replay / diff <span class="count">regression testing · admin-gated</span></h2>
  <p>
    Capture every (request, response) pair into a named session, then
    diff two sessions to detect consumer-behaviour regressions.
    Snapshot-pin siemulator's own output by replaying captured responses
    via <code>?replay_from=&lt;session&gt;</code> on any bound endpoint.
  </p>
  <div class="row">
    <input id="sess-key" type="password" placeholder="X-Admin-Key" style="flex:1; min-width:200px;">
    <input id="sess-name" type="text" placeholder="session name (e.g. xsoar-v1)" style="flex:1; min-width:200px;">
    <button class="primary" onclick="sessAction('start')">▶ Start</button>
    <button onclick="sessAction('stop')">■ Stop</button>
    <button onclick="sessList()">List</button>
  </div>
  <p style="margin-top:8px;">Diff two sessions (request-stream regression):</p>
  <div class="row">
    <input id="sess-diff-a" type="text" placeholder="a (e.g. xsoar-v1)" style="flex:1; min-width:160px;">
    <input id="sess-diff-b" type="text" placeholder="b (e.g. xsoar-v2)" style="flex:1; min-width:160px;">
    <button onclick="sessDiff()">Diff</button>
  </div>
  <div id="sess-meta" class="response-meta" style="display:none;"></div>
  <div id="sess-response" class="response-area empty">Session response will appear here.</div>
</section>

<section>
  <h2>Access log <span class="count">who consumed what · admin-gated</span></h2>
  <p>
    Every request to <code>{ls}/*</code> and <code>{qr}/*</code> is captured
    with timestamp, method, path, redacted query, auth channel, client IP,
    user-agent, status, duration, and response size. Token values are
    <strong>never</strong> recorded — only the channel name
    (<code>bearer</code> / <code>sec</code> / <code>query</code> / <code>none</code>).
    Set <code>X-Admin-Key</code> below to probe.
  </p>
  <div class="row">
    <input id="al-key" type="password" placeholder="X-Admin-Key" style="flex:1; min-width:240px;">
    <button onclick="runAccessLog('recent')">Recent (20)</button>
    <button onclick="runAccessLog('stats')">Aggregations</button>
    <button onclick="runAccessLog('qradar-only')">QRadar only</button>
    <button onclick="runAccessLog('errors-only')">Errors only</button>
  </div>
  <div id="al-meta" class="response-meta" style="display:none;"></div>
  <div id="al-response" class="response-area empty">Access-log response will appear here.</div>
</section>

<footer class="footer-v2">
  <div class="footer-cols">
    <div class="footer-col">
      <h4>Project</h4>
      <a href="https://github.com/SIRP-Labs/siemulator" target="_blank" rel="noopener">GitHub</a>
      <a href="https://github.com/SIRP-Labs/siemulator/blob/main/README.md" target="_blank" rel="noopener">README</a>
      <a href="https://github.com/SIRP-Labs/siemulator/blob/main/CHANGELOG.md" target="_blank" rel="noopener">Changelog</a>
      <a href="https://github.com/SIRP-Labs/siemulator/blob/main/LICENSE" target="_blank" rel="noopener">MIT License</a>
    </div>
    <div class="footer-col">
      <h4>Docs</h4>
      <a href="/docs" target="_blank">OpenAPI / Swagger</a>
      <a href="https://github.com/SIRP-Labs/siemulator/blob/main/docs/ingestion-guide.md" target="_blank" rel="noopener">Ingestion guide</a>
      <a href="https://github.com/SIRP-Labs/siemulator/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener">Contributing</a>
      <a href="https://github.com/SIRP-Labs/siemulator/issues" target="_blank" rel="noopener">Issue tracker</a>
    </div>
    <div class="footer-col">
      <h4>Surfaces</h4>
      <a href="{ls}/api/v1/status">{ls}/api/v1/status</a>
      <a href="{qr}/api/help">{qr}/api/help</a>
      <a href="{sp}/services/server/info">{sp}/services/server/info</a>
      <a href="/api/info">/api/info (metadata)</a>
    </div>
    <div class="footer-col">
      <h4>Install</h4>
      <a href="https://pypi.org/project/siemulator/" target="_blank" rel="noopener">pip install siemulator</a>
      <a href="https://github.com/SIRP-Labs/siemulator/pkgs/container/siemulator" target="_blank" rel="noopener">ghcr.io/sirp-labs/siemulator</a>
      <a href="https://github.com/SIRP-Labs/siemulator/blob/main/.do/app.yaml" target="_blank" rel="noopener">DigitalOcean spec</a>
    </div>
  </div>
  <div class="footer-bottom">
    <span>
      <strong>siemulator v{version}</strong> — a SIRP Labs OSS project. <code>x-mock-source: {mock_source}</code>
    </span>
    <span style="color:var(--text-soft);">
      Every response is synthetic. Never feed it into a real detection pipeline.
    </span>
  </div>
</footer>

</div>

<script>
const LS = "{ls}";
const QR = "{qr}";
const SP = "{sp}";

function getTok(kind) {{
  const el = document.getElementById("tok-" + kind);
  if (el && el.value) return el.value;
  if (kind === "ls") return "logscale-dev-token";
  if (kind === "qr") return "qradar-dev-token";
  if (kind === "sp") return "splunk-dev-token";
  return "";
}}

function escapeHtml(s) {{
  return String(s).replace(/[&<>"']/g, c => ({{
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }})[c]);
}}

function renderCurls() {{
  const lsTok = getTok("ls");
  const qrTok = getTok("qr");
  const spTok = getTok("sp");
  const origin = window.location.origin;
  document.getElementById("curl-health").textContent =
    `curl ${{origin}}${{LS}}/api/v1/status`;
  document.getElementById("curl-ls").textContent =
    `curl -H "Authorization: Bearer ${{lsTok}}" \\\\\\n  "${{origin}}${{LS}}/api/v1/repositories/detections/alerts?limit=3"`;
  document.getElementById("curl-qr").textContent =
    `curl -H "SEC: ${{qrTok}}" "${{origin}}${{QR}}/api/siem/offenses"`;
  document.getElementById("curl-sc").textContent =
    `curl "${{origin}}${{QR}}/api/siem/scenarios?token=${{qrTok}}"`;
  const spEl = document.getElementById("curl-sp");
  if (spEl) spEl.textContent =
    `curl -H "Authorization: Bearer ${{spTok}}" \\\\\\n  "${{origin}}${{SP}}/services/search/jobs/export?search=*&count=3"`;
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
  if (ep === "ls-status" || ep === "qr-help" || ep === "qr-scenarios" || ep === "sp-info") {{
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
  }} else if (ep === "sp-info") {{ url = SP + "/services/server/info"; }}
  else if (ep === "sp-export") {{
    url = SP + "/services/search/jobs/export?search=*" + (limit ? `&count=${{limit}}` : "");
    opts.headers = {{ "Authorization": "Bearer " + getTok("sp") }};
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

async function runAccessLog(which) {{
  const key = document.getElementById("al-key").value;
  const respArea = document.getElementById("al-response");
  const metaArea = document.getElementById("al-meta");
  respArea.classList.remove("empty");
  respArea.textContent = "Loading…";
  let url;
  if (which === "stats") url = "/api/access-log/stats";
  else if (which === "qradar-only") url = "/api/access-log?path_prefix=" + encodeURIComponent(QR) + "&limit=20";
  else if (which === "errors-only") url = "/api/access-log?status=401&limit=20";
  else url = "/api/access-log?limit=20";
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
  const order = ["S1", "S2", "S3", "S4", "S5", "TEST-A", "TEST-B", "TEST-C", "TEST-D", "TEST-E", "TEST-F", "TEST-G", "TEST-H", "TEST-I", "TEST-J", "DEMO-A", "DEMO-B", "DEMO-C", "DEMO-D", "DEMO-E", "DEMO-F", "DEMO-G", "DEMO-H", "SCAN-A", "SCAN-B", "SCAN-C", "ENRICH-A", "ENRICH-B", "ENRICH-C", "ENRICH-D", "ENRICH-E", "TRELLIX-A", "WIN-4672", "PA-SMB-A", "PA-SMB-B", "RANSOM-A", "RANSOM-B", "RANSOM-C", "PSH-A", "PSH-B", "PSH-C", "PA-DNS-A", "RANSOM-D", "BENIGN-C2-A", "DNS-C2-A"];
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

// ── Live alert ticker (SSE) ────────────────────────────────────
let _ticker = null;
let _tickerCount = 0;

function toggleTicker() {{
  if (_ticker) {{
    _ticker.close();
    _ticker = null;
    document.getElementById("ticker-toggle").textContent = "▶ Start";
    return;
  }}
  const rate = document.getElementById("ticker-rate").value || "1";
  const lsTok = getTok("ls");
  const url = LS + "/api/v1/repositories/detections/stream?rate=" + encodeURIComponent(rate) + "&token=" + encodeURIComponent(lsTok);
  const feed = document.getElementById("ticker-feed");
  feed.classList.remove("empty");
  feed.textContent = "";
  _tickerCount = 0;
  document.getElementById("ticker-count").textContent = "0 alerts received";
  document.getElementById("ticker-toggle").textContent = "■ Stop";
  _ticker = new EventSource(url);
  _ticker.addEventListener("alert", (ev) => {{
    try {{
      const e = JSON.parse(ev.data);
      const ts = (e["@timestamp"] || "").slice(11, 19);
      const line = `[${{ts}}] ${{e["event.SeverityName"] || "?"}} · ${{e["event.DetectName"] || "?"}} · ${{e["event.ComputerName"] || "?"}}\\n`;
      feed.textContent = line + feed.textContent;
      // Cap the feed at ~50 lines visually
      const lines = feed.textContent.split("\\n");
      if (lines.length > 60) feed.textContent = lines.slice(0, 60).join("\\n");
      _tickerCount++;
      document.getElementById("ticker-count").textContent = `${{_tickerCount}} alerts received`;
    }} catch (e) {{}}
  }});
  _ticker.addEventListener("end", () => {{
    _ticker.close();
    _ticker = null;
    document.getElementById("ticker-toggle").textContent = "▶ Start";
  }});
  _ticker.onerror = (e) => {{
    feed.textContent = "Stream error (auth? check the LogScale token).\\n" + feed.textContent;
    _ticker.close();
    _ticker = null;
    document.getElementById("ticker-toggle").textContent = "▶ Start";
  }};
}}

// Clean up on page unload
window.addEventListener("beforeunload", () => {{ if (_ticker) _ticker.close(); }});

// ── Sessions (record / replay / diff) ──────────────────────────
async function sessAction(action) {{
  const key = document.getElementById("sess-key").value;
  const name = document.getElementById("sess-name").value.trim();
  if (!name) {{ alert("Session name required"); return; }}
  const url = `/api/sessions/${{encodeURIComponent(name)}}/${{action}}`;
  await sessFetch(url, "POST", null, key);
}}

async function sessList() {{
  const key = document.getElementById("sess-key").value;
  await sessFetch("/api/sessions", "GET", null, key);
}}

async function sessDiff() {{
  const key = document.getElementById("sess-key").value;
  const a = document.getElementById("sess-diff-a").value.trim();
  const b = document.getElementById("sess-diff-b").value.trim();
  if (!a || !b) {{ alert("Both A and B session names required"); return; }}
  await sessFetch(`/api/sessions/diff?a=${{encodeURIComponent(a)}}&b=${{encodeURIComponent(b)}}`, "GET", null, key);
}}

async function sessFetch(url, method, body, key) {{
  const respArea = document.getElementById("sess-response");
  const metaArea = document.getElementById("sess-meta");
  respArea.classList.remove("empty");
  respArea.textContent = "Loading…";
  try {{
    const opts = {{ method, headers: {{ "X-Admin-Key": key }} }};
    if (body) {{
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }}
    const resp = await fetch(url, opts);
    const text = await resp.text();
    let formatted = text;
    try {{ formatted = JSON.stringify(JSON.parse(text), null, 2); }} catch (e) {{}}
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status ${{resp.ok ? "ok" : "fail"}}">${{resp.status}} ${{resp.statusText}}</span><span style="margin-left:auto; color:var(--text-soft);">${{method}} ${{url}}</span>`;
    respArea.textContent = formatted;
  }} catch (e) {{
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status fail">network error</span><span>${{escapeHtml(e.message)}}</span>`;
    respArea.textContent = "";
  }}
}}

// ── Faults dials ───────────────────────────────────────────────
async function getFaults() {{
  const key = document.getElementById("faults-key").value;
  const respArea = document.getElementById("faults-response");
  const metaArea = document.getElementById("faults-meta");
  respArea.classList.remove("empty");
  respArea.textContent = "Loading…";
  try {{
    const resp = await fetch("/api/faults", {{ headers: {{ "X-Admin-Key": key }} }});
    const body = await resp.text();
    let formatted = body;
    try {{
      const parsed = JSON.parse(body);
      formatted = JSON.stringify(parsed, null, 2);
      if (resp.ok) {{
        // Populate the dial inputs from the response so Apply round-trips cleanly
        document.getElementById("faults-5xx").value = parsed.inject_5xx_pct ?? 0;
        document.getElementById("faults-429").value = parsed.inject_429_pct ?? 0;
        document.getElementById("faults-latency").value = parsed.inject_latency_ms ?? 0;
        document.getElementById("faults-malformed").value = parsed.inject_malformed_pct ?? 0;
      }}
    }} catch (e) {{}}
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status ${{resp.ok ? "ok" : "fail"}}">${{resp.status}} ${{resp.statusText}}</span><span style="margin-left:auto; color:var(--text-soft);">GET /api/faults</span>`;
    respArea.textContent = formatted;
  }} catch (e) {{
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status fail">network error</span><span>${{escapeHtml(e.message)}}</span>`;
    respArea.textContent = "";
  }}
}}

async function applyFaults() {{
  const key = document.getElementById("faults-key").value;
  const body = {{
    enabled: true,
    inject_5xx_pct: parseFloat(document.getElementById("faults-5xx").value) || 0,
    inject_429_pct: parseFloat(document.getElementById("faults-429").value) || 0,
    inject_latency_ms: parseInt(document.getElementById("faults-latency").value) || 0,
    inject_malformed_pct: parseFloat(document.getElementById("faults-malformed").value) || 0,
  }};
  const respArea = document.getElementById("faults-response");
  const metaArea = document.getElementById("faults-meta");
  respArea.classList.remove("empty");
  respArea.textContent = "Updating…";
  try {{
    const resp = await fetch("/api/faults", {{
      method: "PUT",
      headers: {{ "X-Admin-Key": key, "Content-Type": "application/json" }},
      body: JSON.stringify(body),
    }});
    const text = await resp.text();
    let formatted = text;
    try {{ formatted = JSON.stringify(JSON.parse(text), null, 2); }} catch (e) {{}}
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status ${{resp.ok ? "ok" : "fail"}}">${{resp.status}} ${{resp.statusText}}</span><span style="margin-left:auto; color:var(--text-soft);">PUT /api/faults</span>`;
    respArea.textContent = formatted;
  }} catch (e) {{
    metaArea.style.display = "flex";
    metaArea.innerHTML = `<span class="status fail">network error</span><span>${{escapeHtml(e.message)}}</span>`;
    respArea.textContent = "";
  }}
}}

async function resetFaults() {{
  const key = document.getElementById("faults-key").value;
  try {{
    const resp = await fetch("/api/faults/reset", {{ method: "POST", headers: {{ "X-Admin-Key": key }} }});
    if (resp.ok) await getFaults();
  }} catch (e) {{}}
}}

renderCurls();
renderTryDefaults();
loadScenarios();
</script>
</body>
</html>
"""
