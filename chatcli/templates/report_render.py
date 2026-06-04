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
  --bg: #f8f9fa;
  --card: #ffffff;
  --text: #212529;
  --muted: #6c757d;
  --border: #dee2e6;
  --accent: #2563eb;
  --critical: #dc2626;
  --high: #ea580c;
  --medium: #ca8a04;
  --low: #16a34a;
  --info: #6b7280;
  --radius: 8px;
  --font: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: "Cascadia Code", "Fira Code", "JetBrains Mono", Consolas, monospace;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1117;
    --card: #1a1d27;
    --text: #e4e5e7;
    --muted: #8b8fa3;
    --border: #2a2d3a;
    --accent: #5b8def;
    --critical: #f87171;
    --high: #fb923c;
    --medium: #facc15;
    --low: #4ade80;
    --info: #9ca3af;
  }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.7;
  padding: 2rem 1rem;
}

.container {
  max-width: 960px;
  margin: 0 auto;
}

/* ── Header ── */
header {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 2rem;
  margin-bottom: 1.5rem;
}

header h1 {
  font-size: 1.75rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  margin-bottom: 0.5rem;
}

header .meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  font-size: 0.85rem;
  color: var(--muted);
}

header .meta .tag {
  background: var(--accent);
  color: #fff;
  padding: 0.15rem 0.6rem;
  border-radius: 99px;
  font-size: 0.78rem;
}

header .target-info {
  margin-top: 0.75rem;
  padding: 0.6rem 0.8rem;
  background: var(--bg);
  border-radius: 6px;
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--muted);
  word-break: break-all;
}

/* ── Summary ── */
.summary {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem 2rem;
  margin-bottom: 1.5rem;
}

.summary h2 {
  font-size: 1.1rem;
  margin-bottom: 0.5rem;
  color: var(--accent);
}

/* ── Sections ── */
.section {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 1rem;
  overflow: hidden;
}

.section-header {
  display: flex;
  align-items: center;
  padding: 1rem 1.5rem;
  cursor: pointer;
  user-select: none;
}

.section-header:hover { background: var(--bg); }

.section-header .toggle {
  margin-right: 0.6rem;
  font-size: 0.7rem;
  color: var(--muted);
  transition: transform 0.2s;
}

.section-header h3 {
  font-size: 1.05rem;
  font-weight: 600;
}

.section-body {
  padding: 0 1.5rem 1.5rem;
}

.section-body.collapsed { display: none; }

.section-body .intro {
  color: var(--muted);
  margin-bottom: 0.75rem;
}

/* ── Findings ── */
.finding {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  margin-bottom: 0.75rem;
}

.finding:last-child { margin-bottom: 0; }

.finding-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.4rem;
}

.severity {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  padding: 0.2rem 0.55rem;
  border-radius: 4px;
  letter-spacing: 0.04em;
}

.sev-critical { background: var(--critical); color: #fff; }
.sev-high     { background: var(--high);     color: #fff; }
.sev-medium   { background: var(--medium);   color: #000; }
.sev-low      { background: var(--low);      color: #fff; }
.sev-info     { background: var(--info);     color: #fff; }

.finding-location {
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--muted);
}

.finding-desc { margin-bottom: 0.4rem; }
.finding-desc p { margin-bottom: 0.3rem; }

.finding-code {
  margin: 0.5rem 0;
}

.finding-remediation {
  margin-top: 0.4rem;
  padding: 0.6rem 0.8rem;
  background: var(--bg);
  border-radius: 4px;
  font-size: 0.9rem;
}

.finding-remediation strong { color: var(--low); }

/* ── Code blocks ── */
.code-block {
  margin: 0.5rem 0;
  border-radius: 6px;
  overflow: hidden;
}

.code-block .code-lang {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  padding: 0.3rem 0.8rem;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
}

.code-block pre {
  padding: 1rem;
  overflow-x: auto;
  font-family: var(--mono);
  font-size: 0.84rem;
  line-height: 1.55;
  tab-size: 4;
}

/* ── Tables ── */
.table-wrap {
  overflow-x: auto;
  margin: 0.5rem 0;
}

.table-wrap table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}

.table-wrap caption {
  font-size: 0.85rem;
  color: var(--muted);
  margin-bottom: 0.4rem;
  text-align: left;
}

.table-wrap th {
  text-align: left;
  font-weight: 600;
  padding: 0.5rem 0.75rem;
  border-bottom: 2px solid var(--border);
  background: var(--bg);
}

.table-wrap td {
  padding: 0.4rem 0.75rem;
  border-bottom: 1px solid var(--border);
}

.table-wrap tr:hover td { background: var(--bg); }

/* ── Timeline ── */
.timeline { margin: 0.5rem 0; }

.timeline-item {
  display: flex;
  gap: 1rem;
  padding: 0.4rem 0;
  border-bottom: 1px solid var(--border);
}

.timeline-item:last-child { border-bottom: none; }

.timeline-time {
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--accent);
  min-width: 90px;
  flex-shrink: 0;
}

/* ── Comparison ── */
.comparison {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.comparison .comp-panel {
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}

.comp-panel .comp-title {
  font-size: 0.85rem;
  font-weight: 600;
  padding: 0.4rem 0.8rem;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
}

.comp-panel .comp-body {
  padding: 0.8rem;
  font-size: 0.9rem;
}

.comp-panel .comp-body pre {
  font-family: var(--mono);
  font-size: 0.82rem;
  overflow-x: auto;
}

/* ── Appendix ── */
.appendix {
  margin-top: 1.5rem;
  padding: 1.5rem 2rem;
  background: var(--card);
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  font-size: 0.9rem;
  color: var(--muted);
}

.appendix h2 {
  font-size: 1rem;
  margin-bottom: 0.5rem;
  color: var(--text);
}

/* ── Footer ── */
footer {
  text-align: center;
  font-size: 0.78rem;
  color: var(--muted);
  margin-top: 2rem;
}

/* ── Responsive ── */
@media (max-width: 640px) {
  .comparison { grid-template-columns: 1fr; }
  header { padding: 1.25rem; }
  .section-header { padding: 0.75rem 1rem; }
  .section-body { padding: 0 1rem 1rem; }
}

@media print {
  body { padding: 0; font-size: 11pt; }
  .section-body.collapsed { display: block; }
  .section-header { cursor: default; }
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
