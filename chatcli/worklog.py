"""Autonomous work sessions — progress tracking + task management.

/work <desc>      Start an autonomous work session
/work status      Show current progress
/work continue    Resume an interrupted session
/work done        Mark the task as complete

Progress is tracked in .chatcli/task.md (structured task + subtask
checkboxes) and auto-logged as the model works. Sessions auto-save
each turn, so interrupting with Ctrl+C preserves all state.
"""

from pathlib import Path
from datetime import datetime
import html
import re
import uuid
from typing import Optional

from .work_prompts import (
    MALWARE_TRIAGE_PROMPT,
    SECURITY_AUDIT_PROMPT,
    WORK_CONTINUE_PROMPT,
    WORK_IMPLEMENT_PROMPT,
    WORK_PLAN_PROMPT,
    WORK_PROMPT,
)

try:
    from .templates._malware_css import MALWARE_CSS
except ImportError:
    try:
        from chatcli.templates._malware_css import MALWARE_CSS
    except ImportError:
        MALWARE_CSS = ""


def _task_file(workspace: str) -> Path:
    return Path(workspace) / ".chatcli" / "task.md"


def _log_file(workspace: str) -> Path:
    return Path(workspace) / ".chatcli" / "worklog.md"


def _read_text_compat(path: Path) -> str:
    """Read chatcli state files without crashing on legacy local encodings."""
    for encoding in ("utf-8", "utf-8-sig", "gb18030"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="utf-8", errors="replace")


# ── Task state ────────────────────────────────────────────────────


def start_task(workspace: str, description: str) -> str:
    """Create a new task file and initialize the work log."""
    tf = _task_file(workspace)
    tf.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    task_id = datetime.now().strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
    tf.write_text(
        f"# Task: {description}\n\n"
        f"**Task ID:** {task_id}\n"
        f"**Status:** in_progress\n"
        f"**Started:** {now}\n"
        f"**Last activity:** {now}\n\n"
        f"## Subtasks\n\n"
        f"<!-- The model will add [x] checkboxes as it works -->\n"
        f"<!-- Use /work status to view, /work done to complete, "
        f"/work continue to resume -->\n",
        encoding="utf-8",
    )

    lf = _log_file(workspace)
    lf.parent.mkdir(parents=True, exist_ok=True)
    lf.write_text(
        f"# Work Log\n\n"
        f"## {description}\n"
        f"**Started:** {now}\n\n",
        encoding="utf-8",
    )
    return task_id


def get_task_status(workspace: str) -> Optional[dict]:
    """Read current task status. Returns None if no active task."""
    tf = _task_file(workspace)
    if not tf.exists():
        return None

    content = _read_text_compat(tf)
    status = "unknown"
    task_id = ""
    for line in content.split("\n"):
        if "**Task ID:**" in line:
            task_id = line.split("**Task ID:**")[-1].strip()
            continue
        if "**Status:**" in line:
            status = line.split("**Status:**")[-1].strip()

    # Count completed vs total subtasks
    subtasks = []
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("- [") and "] " in stripped:
            done = stripped.startswith("- [x]") or stripped.startswith("- [X]")
            subtasks.append({
                "text": stripped[5:].strip(),
                "done": done,
            })

    done_count = sum(1 for s in subtasks if s["done"])
    total = len(subtasks)

    return {
        "task_id": task_id,
        "status": status,
        "subtasks": subtasks,
        "done": done_count,
        "total": total,
        "content": content,
    }


def mark_task_done(workspace: str) -> None:
    """Mark the current task as completed."""
    tf = _task_file(workspace)
    if not tf.exists():
        return
    content = _read_text_compat(tf)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    content = content.replace("**Status:** in_progress", f"**Status:** done")
    content = content.replace("**Last activity:**", f"**Completed:** {now}\n**Last activity:**")
    tf.write_text(content, encoding="utf-8")


def touch_task(workspace: str) -> None:
    """Update last-activity timestamp on the task."""
    tf = _task_file(workspace)
    if not tf.exists():
        return
    content = _read_text_compat(tf)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    # Replace any existing **Last activity:** line
    content = re.sub(r"\*\*Last activity:\*\*.*", f"**Last activity:** {now}", content)
    tf.write_text(content, encoding="utf-8")


def _inline_markdown(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", escaped)
    return escaped


def _is_table_separator(line: str) -> bool:
    """Detect markdown table separator rows like |---|---|"""
    return bool(re.match(r"^\s*\|?\s*:?---+:?\s*(\|\s*:?---+:?\s*)+\|?\s*$", line))


def _parse_table_row(line: str) -> list[str]:
    """Parse a markdown table row into cells."""
    # Strip leading/trailing | and split
    stripped = line.strip().strip("|")
    return [cell.strip() for cell in stripped.split("|")]


def _render_table(lines: list[str], start_idx: int) -> tuple[str, int]:
    """Render a markdown table from lines starting at start_idx.

    Returns (html_string, next_line_index).
    Expected format: header line, separator line, body lines.
    """
    if start_idx >= len(lines):
        return "", start_idx

    header_cells = _parse_table_row(lines[start_idx])
    if not header_cells:
        return "", start_idx

    idx = start_idx + 1
    # Skip separator line if present
    if idx < len(lines) and _is_table_separator(lines[idx]):
        idx += 1

    body_rows: list[list[str]] = []
    while idx < len(lines):
        line = lines[idx].strip()
        if not line or not re.match(r"^\s*\|", line):
            break
        cells = _parse_table_row(line)
        if cells:
            body_rows.append(cells)
        idx += 1

    # Build HTML
    parts = ['<div class="table-wrap"><table>']
    parts.append('<thead><tr>' + ''.join(f'<th>{_inline_markdown(c)}</th>' for c in header_cells) + '</tr></thead>')
    if body_rows:
        parts.append('<tbody>')
        for row in body_rows:
            # Pad row to match header column count
            padded = row + [''] * (len(header_cells) - len(row))
            parts.append('<tr>' + ''.join(f'<td>{_inline_markdown(c)}</td>' for c in padded[:len(header_cells)]) + '</tr>')
        parts.append('</tbody>')
    parts.append('</table></div>')

    return '\n'.join(parts), idx


def _markdownish_to_html(text: str) -> str:
    """Convert the CLI's markdown-like reports into a self-contained HTML body."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    out: list[str] = []
    paragraph: list[str] = []
    in_list = False
    in_code = False
    in_blockquote = False
    code_lines: list[str] = []
    list_type = ""  # "ul" or "ol"

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            out.append("<p>" + "<br>".join(_inline_markdown(x) for x in paragraph) + "</p>")
            paragraph = []

    def close_list() -> None:
        nonlocal in_list, list_type
        if in_list:
            out.append(f"</{list_type}>")
            in_list = False
            list_type = ""

    def close_blockquote() -> None:
        nonlocal in_blockquote
        if in_blockquote:
            out.append("</blockquote>")
            in_blockquote = False

    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        stripped = line.strip()

        # Code fence
        if stripped.startswith("```"):
            if in_code:
                out.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                flush_paragraph()
                close_list()
                close_blockquote()
                in_code = True
            i += 1
            continue

        if in_code:
            code_lines.append(line)
            i += 1
            continue

        # Blank line
        if not stripped:
            flush_paragraph()
            close_list()
            close_blockquote()
            i += 1
            continue

        # Table detection (line starts with |)
        if re.match(r"^\s*\|", stripped):
            flush_paragraph()
            close_list()
            close_blockquote()
            table_html, next_i = _render_table(lines, i)
            if table_html:
                out.append(table_html)
                i = next_i
                continue

        # Horizontal rule
        if re.match(r"^[-*_]{3,}\s*$", stripped):
            flush_paragraph()
            close_list()
            close_blockquote()
            out.append("<hr>")
            i += 1
            continue

        # Heading
        heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            close_list()
            close_blockquote()
            level = min(6, len(heading.group(1)) + 1)
            out.append(f"<h{level}>{_inline_markdown(heading.group(2))}</h{level}>")
            i += 1
            continue

        # Blockquote
        if stripped.startswith("> "):
            flush_paragraph()
            close_list()
            if not in_blockquote:
                out.append("<blockquote>")
                in_blockquote = True
            out.append("<p>" + _inline_markdown(stripped[2:]) + "</p>")
            i += 1
            continue
        elif in_blockquote and not stripped.startswith(">"):
            close_blockquote()

        # Unordered list
        bullet = re.match(r"^[-*]\s+(.+)$", stripped)
        if bullet:
            flush_paragraph()
            close_blockquote()
            if not in_list:
                out.append("<ul>")
                in_list = True
                list_type = "ul"
            elif list_type != "ul":
                close_list()
                out.append("<ul>")
                in_list = True
                list_type = "ul"
            out.append("<li>" + _inline_markdown(bullet.group(1)) + "</li>")
            i += 1
            continue

        # Numbered list
        num_list = re.match(r"^(\d+)\.\s+(.+)$", stripped)
        if num_list:
            flush_paragraph()
            close_blockquote()
            if not in_list:
                out.append("<ol>")
                in_list = True
                list_type = "ol"
            elif list_type != "ol":
                close_list()
                out.append("<ol>")
                in_list = True
                list_type = "ol"
            out.append("<li>" + _inline_markdown(num_list.group(2)) + "</li>")
            i += 1
            continue

        # Regular paragraph text
        close_list()
        close_blockquote()
        paragraph.append(stripped)
        i += 1

    if in_code:
        out.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
    flush_paragraph()
    close_list()
    close_blockquote()
    return "\n".join(out)


def _fallback_report_css() -> str:
    """Minimal CSS fallback when MALWARE_CSS cannot be imported."""
    return """\
:root {
  --bg: #f5f6f8; --card: #ffffff; --text: #151820; --text-secondary: #444a58;
  --muted: #72788a; --border: #e1e4eb; --border-light: #eef0f5;
  --accent: #c42b2b; --accent-soft: #fdf3f3; --ok: #1f7a3b; --ok-bg: #edf7f1;
  --warn: #d97706; --warn-bg: #fef8ee; --info: #2756b5; --info-bg: #eef3fc;
  --critical: #c42b2b; --high: #d95a1a; --medium: #b08808; --low: #1f7a3b;
  --chip-bg: #f0f2f6; --table-stripe: #fafbfc; --radius: 10px; --radius-sm: 6px;
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.05); --shadow-md: 0 2px 10px rgba(0,0,0,0.07);
  --font: "Inter", system-ui, -apple-system, "Segoe UI", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", Roboto, sans-serif;
  --mono: "Cascadia Code", "Fira Code", "JetBrains Mono", "SF Mono", Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.75; padding: 2.5rem 1.5rem; -webkit-font-smoothing: antialiased; }
.container { max-width: 1000px; margin: 0 auto; }
.report-header { background: var(--card); border: 1px solid var(--border); border-top: 3px solid var(--accent); border-radius: var(--radius); padding: 2.25rem 2.5rem; margin-bottom: 1.5rem; box-shadow: var(--shadow-sm); }
.report-header h1 { font-size: 1.7rem; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 0.75rem; }
.report-header .meta-line { display: flex; flex-wrap: wrap; gap: 1.25rem; font-size: 0.84rem; color: var(--muted); }
.tag { display: inline-flex; align-items: center; font-size: 0.73rem; font-weight: 600; padding: 0.2rem 0.7rem; border-radius: 99px; background: var(--chip-bg); border: 1px solid var(--border); color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
.tag.classification { background: var(--accent); color: #fff; border-color: var(--accent); }
.section { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 1.25rem; overflow: hidden; box-shadow: var(--shadow-sm); }
.section-body { padding: 1.3rem 1.75rem; }
h2 { font-size: 1.2rem; font-weight: 700; margin: 1.5rem 0 0.6rem; padding-bottom: 0.4rem; border-bottom: 2px solid var(--border); color: var(--text); }
h3 { font-size: 1.05rem; font-weight: 650; margin: 1.2rem 0 0.5rem; color: var(--text); }
h4 { font-size: 0.92rem; font-weight: 650; margin: 0.8rem 0 0.3rem; color: var(--text-secondary); }
p { margin: 0.5rem 0; color: var(--text-secondary); }
ul, ol { margin: 0.5rem 0 0.8rem 1.5rem; color: var(--text-secondary); }
li { margin: 0.25rem 0; }
code { font-family: var(--mono); font-size: 0.85em; background: var(--chip-bg); padding: 0.12em 0.4em; border-radius: 3px; border: 1px solid var(--border-light); color: var(--critical); }
pre { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 0.9rem; overflow-x: auto; font-family: var(--mono); font-size: 0.79rem; line-height: 1.55; white-space: pre-wrap; color: var(--text-secondary); }
pre code { border: none; padding: 0; color: inherit; background: transparent; }
table { width: 100%; border-collapse: collapse; font-size: 0.84rem; margin: 0.75rem 0; border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden; }
th { text-align: left; font-weight: 650; padding: 0.55rem 0.7rem; border-bottom: 2px solid var(--border); background: var(--chip-bg); font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
td { padding: 0.5rem 0.7rem; border-bottom: 1px solid var(--border-light); vertical-align: top; color: var(--text-secondary); }
tr:nth-child(even) td { background: var(--table-stripe); }
strong { color: var(--text); font-weight: 650; }
blockquote { background: #fffbf0; border-left: 3px solid #f0c040; padding: 0.5rem 0.9rem; margin: 0.6rem 0; font-size: 0.88rem; border-radius: 0 var(--radius-sm) var(--radius-sm) 0; color: var(--text-secondary); }
blockquote p { margin: 0.25rem 0; }
.table-wrap { overflow-x: auto; margin: 0.75rem 0; }
.table-wrap table { margin: 0; }
hr { border: none; border-top: 1px solid var(--border-light); margin: 1rem 0; }
em { color: var(--text-secondary); font-style: italic; }
.report-footer { text-align: center; font-size: 0.75rem; color: var(--muted); margin-top: 2.5rem; padding: 1rem; opacity: 0.7; }
.tag-row { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.75rem; }
@media print { body { padding: 0; font-size: 10pt; background: #fff; } .section { box-shadow: none; break-inside: avoid; } }
"""


def _safe_sample_stem(name: str, max_len: int = 60) -> str:
    """Extract a filesystem-safe stem from a sample filename.

    Strips path separators, extensions, and unsafe characters.
    Truncates to max_len chars (preferring suffix) when too long.
    """
    if not name:
        return ""
    # Take the last path component and strip extension(s)
    base = name.replace("\\", "/").rstrip("/").split("/")[-1]
    # Remove common double extensions: .exe.quarantine, .dll.dat, etc.
    while "." in base:
        root, ext = base.rsplit(".", 1)
        if len(ext) > 6:  # not a real extension (e.g. long hash-like string)
            break
        base = root
    # Remove unsafe chars
    safe = re.sub(r"[^A-Za-z0-9一-鿿_.-]+", "-", base).strip(".-") or "sample"
    if len(safe) <= max_len:
        return safe
    # Truncate: keep first 20 + "..." + last 37 chars
    return safe[:20] + "-" + safe[-(max_len - 21):]


def export_html_report(
    workspace: str,
    task_id: str,
    title: str,
    content: str,
    sample_name: str = "",
    sample_dir: str = "",
) -> Path:
    """Persist a completed analysis report as a self-contained HTML file.

    Saves alongside the sample when sample_dir is provided and exists,
    otherwise falls back to .chatcli/reports/.

    Naming: {sample_stem}_triage_report.html
    Fallback: malware-triage-{task_id}.html
    """
    stem = _safe_sample_stem(sample_name) if sample_name else ""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_task = re.sub(r"[^A-Za-z0-9_.-]+", "-", task_id or "").strip("-")
    if not safe_task:
        safe_task = stamp

    # Determine output directory: prefer sample's directory
    if sample_dir and Path(sample_dir).exists():
        report_dir = Path(sample_dir)
    else:
        report_dir = Path(workspace) / ".chatcli" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Check if a report for this task was already generated recently (by the AI's
    # template pipeline). Skip auto-export to avoid overwriting a better report.
    recent_cutoff = datetime.now().timestamp() - 120  # 2 minutes
    for existing in report_dir.iterdir():
        if not existing.is_file() or existing.suffix != ".html":
            continue
        if safe_task and safe_task in existing.name:
            if existing.stat().st_mtime > recent_cutoff:
                return existing  # Already exported; skip duplicate
        # Also check for the new naming pattern
        if stem and stem in existing.name and "_triage_report" in existing.name:
            if existing.stat().st_mtime > recent_cutoff:
                return existing

    # Build filename: {sample_stem}_triage_report.html
    if stem:
        path = report_dir / f"{stem}_triage_report.html"
    else:
        path = report_dir / f"malware-triage-{safe_task}.html"
    if path.exists():
        for idx in range(1, 100):
            candidate = path.with_name(f"{path.stem}-{idx}{path.suffix}")
            if not candidate.exists():
                path = candidate
                break
    # Strip completion markers and trailing noise from the report content
    clean = (content or "").strip()
    clean = re.sub(r"\n?\s*TASK\s*COMPLETE\s*$", "", clean, flags=re.IGNORECASE).strip()
    clean = re.sub(r"\n?\s*PHASE\s*COMPLETE\s*$", "", clean, flags=re.IGNORECASE).strip()
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    body = _markdownish_to_html(clean)
    doc_title = html.escape(title or "恶意样本静态分析报告")
    css = MALWARE_CSS or _fallback_report_css()
    html_text = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{doc_title}</title>
  <style>
{css}
  </style>
</head>
<body>
<div class="container">
  <div class="report-header">
    <h1>{doc_title}</h1>
    <div class="meta-line">
      <span>&#x1f4c5; {html.escape(generated)}</span>
      <span>&#x1f464; chatcli</span>
      <span>Task ID: {html.escape(task_id or "unknown")}</span>
    </div>
    <div class="tag-row">
      <span class="tag classification">防御性静态分析</span>
      <span class="tag">恶意样本分诊</span>
    </div>
  </div>

  <div class="section">
    <div class="section-body" style="display:block">
{body}
    </div>
  </div>

  <div class="report-footer">
    chatcli malware-triage &middot; {html.escape(generated)}
  </div>
</div>
</body>
</html>
"""
    path.write_text(html_text, encoding="utf-8")
    return path


def record_scope_confirmation(workspace: str, confirmation: str) -> None:
    """Persist one-time authorization/scope confirmation for the active task."""
    tf = _task_file(workspace)
    if not tf.exists():
        return
    content = _read_text_compat(tf)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    cleaned = " ".join(str(confirmation or "").split())
    if len(cleaned) > 500:
        cleaned = cleaned[:497] + "..."
    section = (
        "\n## Scope Confirmation\n\n"
        f"- Confirmed: {now}\n"
        f"- User statement: {cleaned or '(confirmation provided)'}\n"
        "- Applies to the current task and stated target scope only. Do not ask "
        "again for the same scope; ask again only if the target, authorization, "
        "or validation boundary changes.\n"
    )
    if "## Scope Confirmation" in content:
        import re
        content = re.sub(
            r"\n## Scope Confirmation\n.*?(?=\n## |\Z)",
            section.rstrip() + "\n",
            content,
            flags=re.S,
        )
    else:
        content = content.rstrip() + "\n" + section
    tf.write_text(content, encoding="utf-8")
    log_milestone(workspace, "Scope confirmation recorded")


def init_reverse_analysis_state(workspace: str, target: str, mode: str) -> None:
    """Add a persistent reverse-analysis state section to the active task."""
    tf = _task_file(workspace)
    if not tf.exists():
        return
    content = _read_text_compat(tf)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    section = (
        "\n## Reverse Analysis State\n\n"
        f"- Target: {target}\n"
        f"- Mode: {mode}\n"
        f"- Initialized: {now}\n"
        "- Resume rule: before continuing after context loss or compression, read "
        "this section and `.chatcli/worklog.md`; do not re-analyze entries already "
        "marked `[x]` unless new evidence invalidates them.\n\n"
        "### Phase Checklist\n\n"
        "- [ ] Lightweight triage recorded: hash, format, arch, sections, imports, strings, packer clues\n"
        "- [ ] IDA entry-order analysis recorded\n"
        "- [ ] Candidate function map recorded\n"
        "- [ ] Validation or permission-gate data flow explained\n"
        "- [ ] Constants, strings, offsets, or branches verified with binary_find/binary_hexdump\n"
        "- [ ] Solver or patch-audit status recorded\n\n"
        "### Candidate Functions\n\n"
        "<!-- Add: - [ ] 0xADDR name score=N evidence=... status=pending|analyzed|discarded -->\n\n"
        "### Analyzed Functions\n\n"
        "<!-- Add: - [x] 0xADDR name - role - key evidence - conclusion - next step -->\n\n"
        "### Verified Evidence\n\n"
        "<!-- Add: - [x] offset/string/constant - bytes/value - why it matters -->\n\n"
        "### Current Hypotheses\n\n"
        "<!-- Keep only active, evidence-backed hypotheses. Remove or mark stale guesses. -->\n\n"
        "### Next Step Queue\n\n"
        "<!-- Add concrete next actions. Prefer targeted function/range work over broad reruns. -->\n\n"
        "### Child Window Jobs\n\n"
        "<!-- Track: child name, assigned function/range, status, notes path, incorporated yes/no. -->\n\n"
        "### Solver / Patch Notes\n\n"
        "<!-- Track scratch solver path, derived input, patch candidates, risks, and remaining blockers -->\n\n"
        "### Open Questions\n\n"
        "<!-- Add unresolved checks, missing evidence, or decisions that require user input -->\n"
    )
    if "## Reverse Analysis State" in content:
        import re
        content = re.sub(
            r"\n## Reverse Analysis State\n.*?(?=\n## |\Z)",
            section.rstrip() + "\n",
            content,
            flags=re.S,
        )
    else:
        content = content.rstrip() + "\n" + section
    tf.write_text(content, encoding="utf-8")
    log_milestone(workspace, "Reverse analysis state initialized")


# ── Work log ──────────────────────────────────────────────────────


def log_action(workspace: str, action: str) -> None:
    """Append a timestamped action to the work log."""
    lf = _log_file(workspace)
    now = datetime.now().strftime("%H:%M")
    entry = f"- {now} — {action}\n"
    with open(lf, "a", encoding="utf-8") as f:
        f.write(entry)

    # Also touch task
    touch_task(workspace)


def log_milestone(workspace: str, text: str) -> None:
    """Log a significant milestone (bold in the log)."""
    lf = _log_file(workspace)
    now = datetime.now().strftime("%H:%M")
    entry = f"- {now} — **{text}**\n"
    with open(lf, "a", encoding="utf-8") as f:
        f.write(entry)
    touch_task(workspace)


