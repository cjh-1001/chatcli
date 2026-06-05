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
    return escaped


def _markdownish_to_html(text: str) -> str:
    """Convert the CLI's markdown-like reports into a self-contained HTML body."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    out: list[str] = []
    paragraph: list[str] = []
    in_list = False
    in_code = False
    code_lines: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            out.append("<p>" + "<br>".join(_inline_markdown(x) for x in paragraph) + "</p>")
            paragraph = []

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_code:
                out.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                flush_paragraph()
                close_list()
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not stripped:
            flush_paragraph()
            close_list()
            continue

        heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            close_list()
            level = min(6, len(heading.group(1)) + 1)
            out.append(f"<h{level}>{_inline_markdown(heading.group(2))}</h{level}>")
            continue

        bullet = re.match(r"^[-*]\s+(.+)$", stripped)
        if bullet:
            flush_paragraph()
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>" + _inline_markdown(bullet.group(1)) + "</li>")
            continue

        close_list()
        paragraph.append(stripped)

    if in_code:
        out.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
    flush_paragraph()
    close_list()
    return "\n".join(out)


def export_html_report(workspace: str, task_id: str, title: str, content: str) -> Path:
    """Persist a completed analysis report as a self-contained HTML file."""
    report_dir = Path(workspace) / ".chatcli" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    safe_task = re.sub(r"[^A-Za-z0-9_.-]+", "-", task_id or "").strip("-")
    if not safe_task:
        safe_task = datetime.now().strftime("%Y%m%d%H%M%S")
    path = report_dir / f"malware-triage-{safe_task}.html"
    if path.exists():
        for idx in range(1, 100):
            candidate = report_dir / f"malware-triage-{safe_task}-{idx}.html"
            if not candidate.exists():
                path = candidate
                break
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    body = _markdownish_to_html((content or "").strip())
    doc_title = html.escape(title or "恶意样本静态分析报告")
    html_text = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{doc_title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1f2937;
      --muted: #667085;
      --line: #d0d5dd;
      --accent: #0f766e;
      --code-bg: #f1f5f9;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", Arial, sans-serif;
      line-height: 1.65;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }}
    .wrap {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 28px 24px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 28px;
      line-height: 1.25;
    }}
    .meta {{
      color: var(--muted);
      font-size: 14px;
    }}
    main {{
      max-width: 1080px;
      margin: 24px auto 48px;
      padding: 0 24px;
    }}
    article {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 28px;
    }}
    h2, h3, h4 {{
      margin: 26px 0 10px;
      line-height: 1.35;
    }}
    h2 {{
      padding-bottom: 8px;
      border-bottom: 1px solid var(--line);
      font-size: 22px;
    }}
    h3 {{ font-size: 18px; }}
    p {{ margin: 10px 0; }}
    ul {{ margin: 10px 0 14px 22px; padding: 0; }}
    li {{ margin: 4px 0; }}
    code {{
      background: var(--code-bg);
      border: 1px solid #e2e8f0;
      border-radius: 4px;
      padding: 1px 5px;
      font-family: Consolas, "SFMono-Regular", monospace;
      font-size: 0.94em;
    }}
    pre {{
      overflow: auto;
      background: var(--code-bg);
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 14px;
    }}
    pre code {{
      border: 0;
      padding: 0;
      background: transparent;
    }}
    strong {{ color: #111827; }}
    .tag {{
      display: inline-block;
      margin-top: 8px;
      color: var(--accent);
      font-weight: 600;
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <h1>{doc_title}</h1>
      <div class="meta">生成时间：{html.escape(generated)} · Task ID：{html.escape(task_id or "unknown")}</div>
      <div class="tag">防御性静态分析报告</div>
    </div>
  </header>
  <main>
    <article>
{body}
    </article>
  </main>
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


