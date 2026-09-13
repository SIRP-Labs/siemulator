"""Serve the ingestion guide as a page on the live host.

Why this exists: the 8 platform recipes (QRadar SOAR, Phantom, XSOAR,
Sentinel, Elastic, Tines, custom poller) lived only on github.com, so a
user who landed on the deployed demo had to notice one link and leave
the site to learn how to wire siemulator into their tool. Worse, ``/docs``
— the URL people instinctively try — serves FastAPI's Swagger UI, so the
guess that *should* land on "how do I configure this" landed on an HTTP
operation list instead.

Design constraints inherited from ``siemulator.ui``: one repo, one
import, one image — no static-files mount and no filesystem path
assumptions. So the markdown ships INSIDE the package
(``siemulator/ingestion_guide.md``, declared as package-data) and is read
through ``importlib.resources``. That works identically from a source
checkout, the Docker image, and ``pip install siemulator``.

``docs/ingestion-guide.md`` remains the canonical, externally-linked
copy; ``tests/test_guide.py`` pins the two byte-identical so they cannot
drift.

The renderer is deliberately small and hand-rolled rather than pulling in
a markdown dependency — the project ships with three runtime deps and the
guide only uses a known, closed set of constructs (headings, tables,
fenced code, lists, blockquotes, rules, inline code/bold/links). Every
value is HTML-escaped before any markup is emitted.
"""

from __future__ import annotations

import html
import re

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

GUIDE_FILENAME = "ingestion_guide.md"

# URLs a user plausibly guesses when hunting for setup docs. All of them
# 404'd before this module existed.
GUIDE_ALIASES = ("/ingestion", "/ingestion-guide", "/setup", "/help", "/integrations")

_CANONICAL_URL = (
    "https://github.com/SIRP-Labs/siemulator/blob/main/docs/ingestion-guide.md"
)


def load_guide_markdown() -> str:
    """Read the packaged guide. Falls back to the repo copy so the route
    still works when running from a source tree whose package-data has
    not been installed (editable installs, ``python -m siemulator`` from
    a fresh clone)."""
    try:
        from importlib.resources import files

        return (files("siemulator") / GUIDE_FILENAME).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, TypeError):
        from pathlib import Path

        repo_copy = Path(__file__).resolve().parent.parent / "docs" / "ingestion-guide.md"
        if repo_copy.is_file():
            return repo_copy.read_text(encoding="utf-8")
        raise


# ── Markdown → HTML ─────────────────────────────────────────────────
# Closed subset, matching what the guide actually uses. Inline handling
# runs AFTER escaping, and code spans are extracted first so their
# contents are never re-interpreted as markup.

_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_FENCE = re.compile(r"^```(\w*)\s*$")
_TABLE_SEP = re.compile(r"^\|[\s:|-]+\|$")
_BULLET = re.compile(r"^(\s*)[-*]\s+(.*)$")
_NUMBERED = re.compile(r"^(\s*)\d+\.\s+(.*)$")


def _slug(text: str) -> str:
    """GitHub-compatible heading anchor, so the guide's own table of
    contents links keep working once rendered.

    GitHub's algorithm: lowercase, drop everything that isn't
    alphanumeric / underscore / space / hyphen, then map EACH remaining
    space to one hyphen. The last step matters — dropping punctuation
    leaves the spaces that surrounded it, so "SOAR / Resilient" ends up
    with two spaces and therefore ``soar--resilient``. Collapsing
    whitespace runs here (``\\s+``) silently breaks every heading
    containing ``/``, ``+`` or an em-dash — which is 6 of the guide's 8
    platform recipes.
    """
    s = _INLINE_CODE.sub(r"\1", text)
    s = _BOLD.sub(r"\1", s)
    s = _LINK.sub(r"\1", s)
    s = s.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)          # drop punctuation (— / + ( ) etc.)
    return re.sub(r"\s", "-", s)            # per-space, NOT per-run


def _inline(text: str) -> str:
    """Escape, then apply inline markup. Code spans are pulled out first
    and restored last so markup inside them stays literal."""
    spans: list[str] = []

    def _stash(m: re.Match[str]) -> str:
        spans.append(html.escape(m.group(1)))
        return f"\x00{len(spans) - 1}\x00"

    text = _INLINE_CODE.sub(_stash, text)
    text = html.escape(text)
    text = _BOLD.sub(r"<strong>\1</strong>", text)

    def _link(m: re.Match[str]) -> str:
        label, href = m.group(1), m.group(2)
        # Only http(s) and in-page anchors; anything else renders as text
        # so a malformed or javascript: target can't become a live link.
        if not re.match(r"^(https?://|#|/)", href):
            return label
        ext = ' target="_blank" rel="noopener"' if href.startswith("http") else ""
        return f'<a href="{href}"{ext}>{label}</a>'

    text = _LINK.sub(_link, text)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{spans[int(m.group(1))]}</code>", text)


def render_markdown(md: str) -> str:
    """Render the guide's markdown subset to HTML."""
    out: list[str] = []
    lines = md.splitlines()
    i = 0
    list_stack: list[str] = []          # open <ul>/<ol> tags

    def close_lists() -> None:
        while list_stack:
            out.append(f"</{list_stack.pop()}>")

    while i < len(lines):
        line = lines[i]

        # fenced code
        fence = _FENCE.match(line)
        if fence:
            close_lists()
            lang = fence.group(1)
            body: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1  # closing fence
            cls = f' class="lang-{lang}"' if lang else ""
            out.append(
                f"<pre{cls}><code>{html.escape(chr(10).join(body))}</code></pre>"
            )
            continue

        # table: a header row followed by a |---|---| separator
        if line.startswith("|") and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            close_lists()

            def cells(row: str) -> list[str]:
                return [c.strip() for c in row.strip().strip("|").split("|")]

            head = cells(line)
            i += 2
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(cells(lines[i]))
                i += 1
            out.append('<div class="table-wrap"><table>')
            out.append(
                "<thead><tr>"
                + "".join(f"<th>{_inline(c)}</th>" for c in head)
                + "</tr></thead><tbody>"
            )
            for r in rows:
                out.append(
                    "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>"
                )
            out.append("</tbody></table></div>")
            continue

        # heading
        head_m = _HEADING.match(line)
        if head_m:
            close_lists()
            level = len(head_m.group(1))
            text = head_m.group(2)
            out.append(f'<h{level} id="{_slug(text)}">{_inline(text)}</h{level}>')
            i += 1
            continue

        # horizontal rule
        if line.strip() in ("---", "***", "___"):
            close_lists()
            out.append("<hr>")
            i += 1
            continue

        # blockquote (consume the whole run)
        if line.startswith(">"):
            close_lists()
            quote = []
            while i < len(lines) and lines[i].startswith(">"):
                quote.append(lines[i].lstrip(">").strip())
                i += 1
            out.append(f"<blockquote>{_inline(' '.join(quote))}</blockquote>")
            continue

        # lists (one nesting level, which is all the guide uses)
        bullet = _BULLET.match(line)
        number = _NUMBERED.match(line)
        if bullet or number:
            m = bullet or number
            tag = "ul" if bullet else "ol"
            depth = len(m.group(1)) // 2
            while len(list_stack) > depth + 1:
                out.append(f"</{list_stack.pop()}>")
            if len(list_stack) == depth:
                out.append(f"<{tag}>")
                list_stack.append(tag)
            out.append(f"<li>{_inline(m.group(2))}</li>")
            i += 1
            continue

        # blank line ends any open list
        if not line.strip():
            close_lists()
            i += 1
            continue

        # paragraph (join until blank/structural line)
        para = []
        while i < len(lines) and lines[i].strip() and not (
            lines[i].startswith(("|", ">", "```", "#"))
            or _BULLET.match(lines[i])
            or _NUMBERED.match(lines[i])
            or lines[i].strip() in ("---", "***", "___")
        ):
            para.append(lines[i].strip())
            i += 1
        if para:
            close_lists()
            out.append(f"<p>{_inline(' '.join(para))}</p>")

    close_lists()
    return "\n".join(out)


_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ingestion guide · siemulator</title>
<meta name="description" content="How to configure siemulator as an ingestion
source in QRadar SOAR, Splunk SOAR, Cortex XSOAR, Microsoft Sentinel, Elastic,
Tines and custom pollers.">
<style>
  :root {{
    --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3;
    --muted:#8b949e; --accent:#58a6ff; --code-bg:#1c2128;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; background:var(--bg); color:var(--fg);
    font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  }}
  .topbar {{
    position:sticky; top:0; z-index:10; background:rgba(13,17,23,.92);
    backdrop-filter:blur(8px); border-bottom:1px solid var(--border);
    padding:12px 24px; display:flex; gap:18px; align-items:center; flex-wrap:wrap;
  }}
  .topbar a {{ color:var(--muted); text-decoration:none; font-size:14px; }}
  .topbar a:hover {{ color:var(--accent); }}
  .topbar .brand {{ color:var(--fg); font-weight:600; margin-right:auto; }}
  .wrap {{ max-width:900px; margin:0 auto; padding:40px 24px 96px; }}
  h1,h2,h3,h4 {{ line-height:1.3; margin:1.8em 0 .6em; scroll-margin-top:70px; }}
  h1 {{ font-size:2em; margin-top:0; }}
  h2 {{ font-size:1.5em; border-bottom:1px solid var(--border); padding-bottom:.3em; }}
  h3 {{ font-size:1.2em; }}
  a {{ color:var(--accent); }}
  code {{
    background:var(--code-bg); border:1px solid var(--border); border-radius:5px;
    padding:.12em .38em; font-size:.88em;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  }}
  pre {{
    background:var(--code-bg); border:1px solid var(--border); border-radius:8px;
    padding:14px 16px; overflow-x:auto;
  }}
  pre code {{ background:none; border:0; padding:0; font-size:.86em; }}
  .table-wrap {{ overflow-x:auto; margin:1em 0; }}
  table {{ border-collapse:collapse; width:100%; font-size:.92em; }}
  th,td {{ border:1px solid var(--border); padding:8px 11px; text-align:left;
           vertical-align:top; }}
  th {{ background:var(--panel); font-weight:600; }}
  blockquote {{
    margin:1em 0; padding:.6em 1em; border-left:3px solid var(--accent);
    background:var(--panel); color:var(--muted); border-radius:0 6px 6px 0;
  }}
  hr {{ border:0; border-top:1px solid var(--border); margin:2em 0; }}
  li {{ margin:.3em 0; }}
  .src {{
    margin-top:56px; padding-top:18px; border-top:1px solid var(--border);
    color:var(--muted); font-size:13px;
  }}
</style>
</head><body>
<nav class="topbar">
  <a class="brand" href="/">siemulator</a>
  <a href="/">Home</a>
  <a href="/guide">Ingestion guide</a>
  <a href="/docs">OpenAPI</a>
  <a href="https://github.com/SIRP-Labs/siemulator" target="_blank" rel="noopener">GitHub</a>
</nav>
<main class="wrap">
{body}
<p class="src">Rendered from
<a href="{canonical}" target="_blank" rel="noopener">docs/ingestion-guide.md</a>
in the siemulator repo.</p>
</main>
</body></html>"""


def build_router() -> APIRouter:
    """Serve the guide at ``/guide``, with the commonly-guessed URLs
    redirecting to it."""
    router = APIRouter(tags=["ui"], include_in_schema=False)

    # Rendered once at startup — the guide is static for a given build.
    page = _PAGE.format(
        body=render_markdown(load_guide_markdown()),
        canonical=_CANONICAL_URL,
    )

    @router.get("/guide", response_class=HTMLResponse)
    async def guide() -> HTMLResponse:
        return HTMLResponse(content=page)

    for alias in GUIDE_ALIASES:
        @router.get(alias, include_in_schema=False)
        async def _alias() -> RedirectResponse:
            return RedirectResponse(url="/guide", status_code=308)

    return router
