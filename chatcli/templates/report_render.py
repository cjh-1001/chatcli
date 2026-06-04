"""
Unified HTML report renderer.

AI produces a lightweight JSON payload following the report schema.
This script converts it into a self-contained, styled HTML page.

Usage:
    python report_render.py input.json [output.html]
    # or from code:
    from chatcli.templates.report_render import render_json, render_file
    html = render_file("report.json")
    html = render_json(data_dict)

Schema (informal — any field is optional unless marked required):

{
  "title": "Report Title",                   # required
  "meta": {
    "date": "2026-06-04",
    "author": "chatcli",
    "tags": ["tag1", "tag2"],
    "target": {"name": "...", "sha256": "...", "size": "..."}
  },
  "summary": "Executive summary (markdown)",
  "sections": [
    {
      "title": "Section title",              # required
      "type": "text",                        # text|findings|code|table|timeline|comparison
      "intro": "Optional intro (markdown)",
      "content": "...",                      # depends on type (see below)
      "collapsed": false
    }
  ],
  "appendix": "Optional appendix (markdown)"
}

Section types & their `content` format:

text:
    "content": "Markdown text..."

findings:
    "content": [
      {
        "severity": "critical|high|medium|low|info",
        "title": "Finding title",
        "location": "file:line",        # optional
        "description": "markdown",
        "code": "code snippet",         # optional
        "remediation": "markdown"       # optional
      }
    ]

code:
    "content": {
      "language": "python|javascript|c|asm|...",
      "code": "source code..."
    }

table:
    "content": {
      "headers": ["Col1", "Col2"],
      "rows": [["a", "b"], ["c", "d"]],
      "caption": "Optional caption"
    }

timeline:
    "content": [
      {"time": "T+0ms", "event": "Description"},
      ...
    ]

comparison:
    "content": {
      "left": {"title": "Before", "body": "markdown or code"},
      "right": {"title": "After", "body": "markdown or code"}
    }
"""

import json
import sys
import html as _html
from pathlib import Path
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# CSS — self-contained, no external dependencies
# ---------------------------------------------------------------------------

CSS = r"""
:root {
  --bg: #f6f7f9;
  --card: #ffffff;
  --text: #1a1d29;
  --text-secondary: #4a4f5e;
  --muted: #7a7f8f;
  --border: #e2e4ea;
  --border-light: #edf0f5;
  --accent: #3451e2;
  --accent-soft: #eef1fd;
  --accent-glow: rgba(52,81,226,0.08);
  --critical: #d92d3b;
  --critical-bg: #fef0f1;
  --high: #e8640c;
  --high-bg: #fef6ee;
  --medium: #b78b08;
  --medium-bg: #fdfaec;
  --low: #1f9254;
  --low-bg: #edf7f1;
  --info: #5a6175;
  --info-bg: #f3f4f7;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
  --shadow-md: 0 2px 8px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
  --radius: 10px;
  --radius-sm: 6px;
  --font: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  --font-display: "Inter Display", system-ui, -apple-system, sans-serif;
  --mono: "Cascadia Code", "Fira Code", "JetBrains Mono", "SF Mono", Consolas, monospace;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0d14;
    --card: #141722;
    --text: #e6e7ec;
    --text-secondary: #b0b4c2;
    --muted: #6f748a;
    --border: #232738;
    --border-light: #1c1f2e;
    --accent: #678af5;
    --accent-soft: #1a1f35;
    --accent-glow: rgba(103,138,245,0.1);
    --critical: #f0656e;
    --critical-bg: #2a1518;
    --high: #f08c4a;
    --high-bg: #2a1d14;
    --medium: #d9b72b;
    --medium-bg: #252214;
    --low: #3db871;
    --low-bg: #141f18;
    --info: #7a8099;
    --info-bg: #1a1c25;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
    --shadow-md: 0 2px 12px rgba(0,0,0,0.25);
  }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.72;
  padding: 2.5rem 1.5rem;
  -webkit-font-smoothing: antialiased;
}

.container { max-width: 920px; margin: 0 auto; }

/* ── Header ── */
header {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 2.25rem 2.5rem;
  margin-bottom: 1.75rem;
  box-shadow: var(--shadow-sm);
}

header h1 {
  font-family: var(--font-display);
  font-size: 1.85rem;
  font-weight: 800;
  letter-spacing: -0.025em;
  line-height: 1.2;
  margin-bottom: 0.6rem;
  color: var(--text);
}

header .meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.6rem;
  font-size: 0.84rem;
  color: var(--muted);
}

header .meta .sep { color: var(--border); }

header .meta .tag {
  display: inline-flex;
  align-items: center;
  background: var(--accent-soft);
  color: var(--accent);
  padding: 0.2rem 0.7rem;
  border-radius: 99px;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.01em;
}

header .target-info {
  margin-top: 1rem;
  padding: 0.65rem 1rem;
  background: var(--bg);
  border-radius: var(--radius-sm);
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--muted);
  word-break: break-all;
  border: 1px solid var(--border-light);
}

/* ── Summary ── */
.summary {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.75rem 2.5rem;
  margin-bottom: 1.75rem;
  box-shadow: var(--shadow-sm);
}

.summary h2 {
  font-size: 1rem;
  font-weight: 700;
  margin-bottom: 0.6rem;
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-size: 0.78rem;
}

.summary p { color: var(--text-secondary); }

/* ── Sections ── */
.section {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 1.25rem;
  overflow: hidden;
  box-shadow: var(--shadow-sm);
  transition: box-shadow 0.15s;
}

.section:hover { box-shadow: var(--shadow-md); }

.section-header {
  display: flex;
  align-items: center;
  padding: 1.1rem 1.75rem;
  cursor: pointer;
  user-select: none;
  border-bottom: 1px solid transparent;
  transition: background 0.12s;
}

.section-header:hover { background: var(--bg); }

.section-body:not(.collapsed) + .section-header,
.section:has(.section-body:not(.collapsed)) .section-header {
  border-bottom-color: var(--border-light);
}

.section-header .toggle {
  margin-right: 0.5rem;
  font-size: 0.65rem;
  color: var(--muted);
  transition: transform 0.2s;
  width: 1.2rem;
  text-align: center;
  flex-shrink: 0;
}

.section-header h3 {
  font-size: 1rem;
  font-weight: 650;
  color: var(--text);
}

.section-body {
  padding: 1.5rem 1.75rem;
}

.section-body.collapsed { display: none; }

.section-body .intro {
  color: var(--muted);
  margin-bottom: 1rem;
  font-size: 0.9rem;
}

/* ── Findings ── */
.finding {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1.1rem 1.25rem;
  margin-bottom: 0.75rem;
  border-left: 3px solid var(--border);
  transition: border-color 0.15s;
}

.finding:last-child { margin-bottom: 0; }

.finding-header {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  margin-bottom: 0.5rem;
  flex-wrap: wrap;
}

.severity {
  font-size: 0.68rem;
  font-weight: 700;
  text-transform: uppercase;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  letter-spacing: 0.05em;
  flex-shrink: 0;
}

.sev-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
.sev-high     { background: var(--high-bg);     color: var(--high);     border: 1px solid var(--high); }
.sev-medium   { background: var(--medium-bg);   color: var(--medium);   border: 1px solid var(--medium); }
.sev-low      { background: var(--low-bg);      color: var(--low);      border: 1px solid var(--low); }
.sev-info     { background: var(--info-bg);     color: var(--info);     border: 1px solid var(--info); }

/* severity left border on finding card */
.finding:has(.sev-critical) { border-left-color: var(--critical); }
.finding:has(.sev-high)     { border-left-color: var(--high); }
.finding:has(.sev-medium)   { border-left-color: var(--medium); }
.finding:has(.sev-low)      { border-left-color: var(--low); }

.finding-location {
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--muted);
  background: var(--bg);
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
}

.finding-desc { margin-bottom: 0.4rem; color: var(--text-secondary); }
.finding-desc p { margin-bottom: 0.35rem; }

.finding-code { margin: 0.5rem 0; }

.finding-remediation {
  margin-top: 0.5rem;
  padding: 0.7rem 0.9rem;
  background: var(--low-bg);
  border-radius: var(--radius-sm);
  font-size: 0.88rem;
  border: 1px solid color-mix(in srgb, var(--low) 20%, transparent);
}

.finding-remediation strong { color: var(--low); }

/* ── Code blocks ── */
.code-block {
  margin: 0.75rem 0;
  border-radius: var(--radius-sm);
  overflow: hidden;
  border: 1px solid var(--border);
  background: var(--bg);
}

.code-block .code-lang {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  padding: 0.45rem 1rem;
  background: var(--card);
  border-bottom: 1px solid var(--border);
}
.code-block .code-lang::before {
  content: "";
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--border);
  box-shadow: 10px 0 0 var(--border), 20px 0 0 var(--border);
}

.code-block pre {
  padding: 1.1rem;
  overflow-x: auto;
  font-family: var(--mono);
  font-size: 0.82rem;
  line-height: 1.6;
  tab-size: 4;
  background: var(--bg);
}

/* ── Tables ── */
.table-wrap {
  overflow-x: auto;
  margin: 0.75rem 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
}

.table-wrap table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.88rem;
}

.table-wrap caption {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--muted);
  padding: 0.6rem 1rem;
  text-align: left;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
}

.table-wrap th {
  text-align: left;
  font-weight: 650;
  font-size: 0.76rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  padding: 0.55rem 0.9rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
}

.table-wrap td {
  padding: 0.5rem 0.9rem;
  border-bottom: 1px solid var(--border-light);
  color: var(--text-secondary);
}

.table-wrap tbody tr:last-child td { border-bottom: none; }
.table-wrap tbody tr:nth-child(even) td { background: rgba(0,0,0,0.015); }
.table-wrap tbody tr:hover td { background: var(--accent-soft); }

/* ── Timeline ── */
.timeline { margin: 0.5rem 0; }

.timeline-item {
  display: flex;
  gap: 1rem;
  padding: 0.55rem 0;
  border-bottom: 1px solid var(--border-light);
  align-items: baseline;
}

.timeline-item:last-child { border-bottom: none; }

.timeline-time {
  font-family: var(--mono);
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--accent);
  min-width: 90px;
  flex-shrink: 0;
  background: var(--accent-soft);
  padding: 0.15rem 0.6rem;
  border-radius: 4px;
  text-align: center;
}

/* ── Comparison ── */
.comparison {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.comparison .comp-panel {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.comp-panel .comp-title {
  font-size: 0.82rem;
  font-weight: 650;
  padding: 0.5rem 0.9rem;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.comp-panel .comp-body {
  padding: 0.9rem;
  font-size: 0.88rem;
  color: var(--text-secondary);
}

.comp-panel .comp-body pre {
  font-family: var(--mono);
  font-size: 0.8rem;
  overflow-x: auto;
  background: var(--bg);
  padding: 0.6rem;
  border-radius: 4px;
}

/* ── Appendix ── */
.appendix {
  margin-top: 2rem;
  padding: 1.75rem 2.5rem;
  background: var(--card);
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  font-size: 0.88rem;
  color: var(--muted);
}

.appendix h2 {
  font-size: 0.95rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
  color: var(--text);
}

/* ── Footer ── */
footer {
  text-align: center;
  font-size: 0.75rem;
  color: var(--muted);
  margin-top: 2.5rem;
  opacity: 0.7;
}

/* ── Typography ── */
h1, h2, h3, h4 { color: var(--text); }
h1 { font-size: 1.5rem; font-weight: 750; letter-spacing: -0.02em; margin-bottom: 0.5rem; }
h2 { font-size: 1.2rem; font-weight: 700; margin: 1.25rem 0 0.5rem; }
h3 { font-size: 1.05rem; font-weight: 650; margin: 1rem 0 0.4rem; }
h4 { font-size: 0.95rem; font-weight: 650; margin: 0.75rem 0 0.3rem; }

p { margin-bottom: 0.6rem; color: var(--text-secondary); }

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

code {
  font-family: var(--mono);
  font-size: 0.85em;
  background: var(--bg);
  padding: 0.12em 0.4em;
  border-radius: 3px;
  border: 1px solid var(--border-light);
  color: var(--critical);
}

pre code {
  border: none;
  padding: 0;
  color: inherit;
  background: transparent;
}

blockquote {
  border-left: 3px solid var(--accent);
  margin: 0.6rem 0;
  padding: 0.4rem 1rem;
  background: var(--accent-soft);
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  color: var(--text-secondary);
}

ul, ol { padding-left: 1.5rem; margin-bottom: 0.6rem; color: var(--text-secondary); }
li { margin-bottom: 0.2rem; }

hr {
  border: none;
  border-top: 1px solid var(--border-light);
  margin: 1rem 0;
}

/* ── Responsive ── */
@media (max-width: 640px) {
  body { padding: 1.25rem 0.75rem; }
  .comparison { grid-template-columns: 1fr; }
  header { padding: 1.5rem; }
  .section-header { padding: 0.85rem 1.25rem; }
  .section-body { padding: 1rem 1.25rem; }
  .summary { padding: 1.25rem 1.5rem; }
}

@media print {
  body { padding: 0; font-size: 10.5pt; background: #fff; }
  .section-body.collapsed { display: block; }
  .section-header { cursor: default; }
  .section { box-shadow: none; break-inside: avoid; }
  .code-block .code-lang::before { display: none; }
}
"""

# ---------------------------------------------------------------------------
# Simple markdown → HTML (handles the common subset used in reports)
# ---------------------------------------------------------------------------

def _md(text: str) -> str:
    """Convert a small subset of markdown to HTML."""
    if not text:
        return ""
    lines = text.splitlines()
    out: list[str] = []
    in_code = False
    in_list = False
    in_quote = False

    for line in lines:
        # Code fence
        if line.strip().startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
                continue
            lang = line.strip()[3:].strip()
            out.append(f'<pre class="code-block"><code class="lang-{_html.escape(lang)}">' if lang else '<pre><code>')
            in_code = True
            continue

        if in_code:
            out.append(_html.escape(line))
            continue

        # Blank line closes lists and blockquotes
        if not line.strip():
            if in_list:
                out.append("</ul>")
                in_list = False
            if in_quote:
                out.append("</blockquote>")
                in_quote = False
            out.append("")
            continue

        # Inline code
        while "`" in line:
            bt = line.index("`")
            end = line.find("`", bt + 1)
            if end == -1:
                break
            code = _html.escape(line[bt + 1:end])
            line = line[:bt] + f"<code>{code}</code>" + line[end + 1:]

        # Bold and italic
        import re
        line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
        line = re.sub(r'\*(.+?)\*', r'<em>\1</em>', line)

        # Blockquote
        if line.startswith("> "):
            if not in_quote:
                out.append("<blockquote>")
                in_quote = True
            out.append(f"<p>{line[2:]}</p>")
            continue
        elif in_quote:
            out.append("</blockquote>")
            in_quote = False

        # Unordered list
        if line.strip().startswith("- ") or line.strip().startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            content = line.strip()[2:]
            out.append(f"<li>{content}</li>")
            continue
        elif in_list:
            out.append("</ul>")
            in_list = False

        # Headings
        if line.startswith("#### "):
            out.append(f"<h4>{line[5:]}</h4>")
        elif line.startswith("### "):
            out.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{line[2:]}</h1>")
        else:
            out.append(f"<p>{line}</p>")

    if in_list:
        out.append("</ul>")
    if in_quote:
        out.append("</blockquote>")
    if in_code:
        out.append("</code></pre>")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_text(content: Any) -> str:
    return _md(str(content) if isinstance(content, str) else json.dumps(content, ensure_ascii=False, indent=2))


def _render_findings(items: list) -> str:
    if not items:
        return '<p class="intro">No findings.</p>'
    parts = []
    for f in items:
        sev = f.get("severity", "info").lower()
        parts.append('<div class="finding">')
        parts.append('<div class="finding-header">')
        parts.append(f'<span class="severity sev-{sev}">{_html.escape(sev)}</span>')
        parts.append(f'<strong>{_html.escape(f.get("title", ""))}</strong>')
        if f.get("location"):
            parts.append(f'<span class="finding-location">{_html.escape(f["location"])}</span>')
        parts.append('</div>')
        if f.get("description"):
            parts.append(f'<div class="finding-desc">{_md(f["description"])}</div>')
        if f.get("code"):
            parts.append(f'<div class="finding-code"><pre><code>{_html.escape(str(f["code"]))}</code></pre></div>')
        if f.get("remediation"):
            parts.append(f'<div class="finding-remediation"><strong>🔧 Remediation:</strong> {_md(f["remediation"])}</div>')
        parts.append('</div>')
    return "\n".join(parts)


def _render_code(content: Any) -> str:
    if isinstance(content, str):
        code = content
        lang = ""
    else:
        code = content.get("code", "")
        lang = content.get("language", "")
    parts = ['<div class="code-block">']
    if lang:
        parts.append(f'<div class="code-lang">{_html.escape(lang)}</div>')
    parts.append(f"<pre><code>{_html.escape(code)}</code></pre>")
    parts.append("</div>")
    return "\n".join(parts)


def _render_table(content: Any) -> str:
    headers = content.get("headers", [])
    rows = content.get("rows", [])
    caption = content.get("caption", "")
    parts = ['<div class="table-wrap"><table>']
    if caption:
        parts.append(f"<caption>{_html.escape(caption)}</caption>")
    if headers:
        parts.append("<thead><tr>")
        for h in headers:
            parts.append(f"<th>{_html.escape(str(h))}</th>")
        parts.append("</tr></thead>")
    parts.append("<tbody>")
    for row in rows:
        parts.append("<tr>")
        for cell in row:
            parts.append(f"<td>{_html.escape(str(cell))}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table></div>")
    return "\n".join(parts)


def _render_timeline(items: list) -> str:
    parts = ['<div class="timeline">']
    for item in items:
        parts.append('<div class="timeline-item">')
        parts.append(f'<span class="timeline-time">{_html.escape(str(item.get("time", "")))}</span>')
        parts.append(f'<span>{_md(str(item.get("event", "")))}</span>')
        parts.append('</div>')
    parts.append('</div>')
    return "\n".join(parts)


def _render_comparison(content: Any) -> str:
    left = content.get("left", {})
    right = content.get("right", {})
    parts = ['<div class="comparison">']
    for side in (left, right):
        parts.append('<div class="comp-panel">')
        parts.append(f'<div class="comp-title">{_html.escape(str(side.get("title", "")))}</div>')
        parts.append(f'<div class="comp-body">{_md(str(side.get("body", "")))}</div>')
        parts.append('</div>')
    parts.append('</div>')
    return "\n".join(parts)


_SECTION_RENDERERS = {
    "text": _render_text,
    "findings": _render_findings,
    "code": _render_code,
    "table": _render_table,
    "timeline": _render_timeline,
    "comparison": _render_comparison,
}


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------

def _section_id(title: str, idx: int) -> str:
    """Stable ID from title or index."""
    import re
    slug = re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')
    return slug or f"section-{idx}"


def render_html(report: dict) -> str:
    """Convert a report dict into a complete self-contained HTML page."""
    title = _html.escape(str(report.get("title", "Report")))
    meta = report.get("meta", {}) or {}
    summary = report.get("summary", "")
    sections = report.get("sections", [])
    appendix = report.get("appendix", "")

    tags_html = ""
    if meta.get("tags"):
        tags_html = "".join(
            f'<span class="tag">{_html.escape(t)}</span>' for t in meta["tags"]
        )

    target_html = ""
    target = meta.get("target")
    if target and isinstance(target, dict):
        pairs = " &nbsp;|&nbsp; ".join(
            f"{_html.escape(k)}: {_html.escape(str(v))}" for k, v in target.items()
        )
        target_html = f'<div class="target-info">{pairs}</div>'

    # Build page
    html_parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{title}</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        '<div class="container">',
        # Header
        "<header>",
        f"<h1>{title}</h1>",
        '<div class="meta">',
        f'<span>{_html.escape(str(meta.get("date", datetime.now().strftime("%Y-%m-%d"))))}</span>',
    ]
    if meta.get("author"):
        html_parts.append(f'<span>by {_html.escape(str(meta["author"]))}</span>')
    html_parts.append("</div>")
    if tags_html:
        html_parts.append(f'<div class="meta">{tags_html}</div>')
    if target_html:
        html_parts.append(target_html)
    html_parts.append("</header>")

    # Summary
    if summary:
        html_parts.append('<div class="summary">')
        html_parts.append("<h2>Summary</h2>")
        html_parts.append(_md(summary))
        html_parts.append("</div>")

    # Sections
    for idx, sec in enumerate(sections):
        sec_title = _html.escape(str(sec.get("title", "")))
        sec_type = sec.get("type", "text")
        sec_intro = sec.get("intro", "")
        sec_content = sec.get("content", "")
        collapsed = sec.get("collapsed", False)

        sid = _section_id(sec_title, idx)

        html_parts.append('<div class="section">')
        html_parts.append(f'<div class="section-header" onclick="toggleSection(\'{sid}\')">')
        html_parts.append(f'<span class="toggle" id="toggle-{sid}">{"▶" if collapsed else "▼"}</span>')
        html_parts.append(f"<h3>{sec_title}</h3>")
        html_parts.append("</div>")

        collapse_class = "collapsed" if collapsed else ""
        html_parts.append(f'<div class="section-body {collapse_class}" id="{sid}">')
        if sec_intro:
            html_parts.append(f'<div class="intro">{_md(sec_intro)}</div>')

        renderer = _SECTION_RENDERERS.get(sec_type, _render_text)
        html_parts.append(renderer(sec_content))

        html_parts.append("</div>")  # section-body
        html_parts.append("</div>")  # section

    # Appendix
    if appendix:
        html_parts.append('<div class="appendix">')
        html_parts.append("<h2>Appendix</h2>")
        html_parts.append(_md(appendix))
        html_parts.append("</div>")

    # Footer
    html_parts.append("<footer>")
    html_parts.append(f"Generated by chatcli &middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    html_parts.append("</footer>")

    html_parts.append("</div>")  # container

    # Minimal JS for section collapsing
    html_parts.append("""<script>
function toggleSection(id) {
  var body = document.getElementById(id);
  var toggle = document.getElementById('toggle-' + id);
  if (body.classList.contains('collapsed')) {
    body.classList.remove('collapsed');
    toggle.textContent = '▼';
  } else {
    body.classList.add('collapsed');
    toggle.textContent = '▶';
  }
}
</script>""")

    html_parts.append("</body></html>")
    return "\n".join(html_parts)


# ---------------------------------------------------------------------------
# Convenience entry points
# ---------------------------------------------------------------------------

def render_json(data: dict) -> str:
    """Render a report dict to HTML string."""
    return render_html(data)


def render_file(path: str | Path) -> str:
    """Read a JSON report file and return rendered HTML."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return render_html(data)


def render_to(data: dict, output_path: str | Path) -> Path:
    """Render and write HTML file, returning the output path."""
    html = render_html(data)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} input.json [output.html]", file=sys.stderr)
        print("  If output is omitted, writes to input_stem.html", file=sys.stderr)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))

    if len(sys.argv) >= 3:
        output_path = Path(sys.argv[2])
    else:
        output_path = input_path.with_suffix(".html")

    result = render_to(data, output_path)
    print(f"Report written: {result} ({result.stat().st_size} bytes)")
