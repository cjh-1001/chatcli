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
from typing import Optional


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


def start_task(workspace: str, description: str) -> None:
    """Create a new task file and initialize the work log."""
    tf = _task_file(workspace)
    tf.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    tf.write_text(
        f"# Task: {description}\n\n"
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


def get_task_status(workspace: str) -> Optional[dict]:
    """Read current task status. Returns None if no active task."""
    tf = _task_file(workspace)
    if not tf.exists():
        return None

    content = _read_text_compat(tf)
    status = "unknown"
    for line in content.split("\n"):
        if "**Status:**" in line:
            status = line.split("**Status:**")[-1].strip()
            break

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
    import re
    content = _read_text_compat(tf)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    # Replace any existing **Last activity:** line
    content = re.sub(r"\*\*Last activity:\*\*.*", f"**Last activity:** {now}", content)
    tf.write_text(content, encoding="utf-8")


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


def get_recent_log(workspace: str, lines: int = 20) -> str:
    """Get the last N lines of the work log."""
    lf = _log_file(workspace)
    if not lf.exists():
        return "(no work log)"
    all_lines = _read_text_compat(lf).split("\n")
    recent = all_lines[-lines:] if len(all_lines) > lines else all_lines
    return "\n".join(recent)


# ── Autonomous prompt ─────────────────────────────────────────────


WORK_PLAN_PROMPT = """\
## SMART CODING PLAN MODE

You are preparing an implementation plan for the task in `.chatcli/task.md`.

**Rules:**
1. Read `.chatcli/task.md` first.
2. Explore the repository with read-only tools before proposing a coding plan.
3. Do not edit product/source files yet. You may update `.chatcli/task.md`
   with planned subtasks and notes.
4. If there are multiple reasonable approaches, present 2-3 options and mark
   one as recommended.
5. The plan must include:
   - Requirements restatement
   - Proposed approach
   - Subtasks/phases
   - Test strategy for each phase
   - Risks or decisions needing user confirmation
6. End your response with exactly `PLAN READY` and ask the user to confirm
   or choose an option before implementation starts.
"""

WORK_PROMPT = """\
## AUTONOMOUS WORK MODE

You are working on the task described in `.chatcli/task.md`. Read it now to
understand what needs to be done.

**Rules:**
1. First audit the task. Decide whether it needs subtasks; for anything non-trivial,
   write concrete `- [ ]` subtasks into `.chatcli/task.md` before editing code.
2. Work autonomously — do NOT stop to ask the user. Keep going until the task is complete.
3. After each significant action, update `.chatcli/task.md` to check off completed subtasks
   and add new ones you discover (use `- [x]` for done, `- [ ]` for todo).
4. When you finish a logical unit of work, add a milestone to the task file.
5. Implement one planned subtask/phase at a time. After each phase:
   - add or update focused tests when the change is testable,
   - run the relevant tests,
   - fix failures before moving on,
   - only then mark that subtask done.
6. Use tools to explore, modify, test, and verify. Don't just plan — execute.
   For temporary scripts or probes, use `.chatcli/tmp/scratch.py` and iterate
   on that same file. Do not create repeated root-level samples like
   `solve.py`, `solve2.py`, `test.py`, or `test2.py`.
7. If you hit an error, self-correct and try another approach. Do NOT give up.
8. If there are materially different implementation approaches, UX choices,
   destructive operations, or requirements that cannot be inferred safely,
   pause and ask the user to choose. Start that response with exactly:
   `USER CHOICE REQUIRED`
   Then give 2-3 concise options and your recommended option.
9. If relevant tests cannot be run, state the concrete blocker and continue
   only when the remaining work is still safe.
10. When the current phase is done but more subtasks remain, say `PHASE COMPLETE`
    with a short status. When the full task is complete, say "TASK COMPLETE"
    and summarize what you did.

The user is not available to answer questions — figure it out yourself.
"""

WORK_IMPLEMENT_PROMPT = """\
## APPROVED CODING WORK MODE

The user has approved or clarified the plan for the active task. Continue
implementing `.chatcli/task.md` according to the approved direction.

Follow the same implementation rules:
- Work one subtask/phase at a time.
- Add or update focused tests for each testable phase.
- Run relevant tests before marking a subtask done.
- Fix test failures before moving to the next phase.
- For temporary scripts or probes, keep iterating on `.chatcli/tmp/scratch.py`
  instead of creating multiple root-level sample files.
- If a new major decision appears, pause with `USER CHOICE REQUIRED`.
- Say `PHASE COMPLETE` after a phase, or `TASK COMPLETE` when fully done.
"""

WORK_CONTINUE_PROMPT = """\
## AUTONOMOUS WORK MODE — Resuming

Read `.chatcli/task.md` and `.chatcli/worklog.md` to understand the current
state. Continue from where you left off. Same rules as before: work
autonomously, update progress, implement one phase at a time, add/update
focused tests, run relevant tests before marking each phase done, and keep
going until done. Reuse `.chatcli/tmp/scratch.py` for temporary scripts.
If `.chatcli/task.md` contains `## Reverse Analysis State`, treat it as the
source of truth for already analyzed reverse-engineering phases/functions and
do not repeat `[x]` entries unless new evidence invalidates them.
"""

SECURITY_AUDIT_PROMPT = """\
## SECURITY CODE AUDIT MODE

You are performing an authorized security audit or CTF/lab challenge analysis for
the task in `.chatcli/task.md`.

Use the `security-audit` skill. Work read-only unless the user explicitly asks
for code fixes.

**Rules:**
1. First identify scope, framework, entry points, routes/controllers, config,
   auth/session logic, upload/file handling, and dependency surfaces.
2. If the codebase is large, split the audit into phases in `.chatcli/task.md`.
3. Prioritize evidence-based findings:
   - information leaks and hardcoded secrets,
   - injection/RCE/file/SSRF/deserialization risks,
   - auth bypass, IDOR, privilege errors,
   - upload/path traversal/arbitrary file operations,
   - XSS/CSRF/open redirect/CORS weaknesses,
   - risky mini-program/decompiled client assumptions,
   - CMS install/admin/plugin/theme/update vulnerabilities.
4. For each finding, include severity, affected file/function/line when
   possible, evidence, impact, exploitability preconditions, safe reproduction
   path, and remediation.
5. If the task is an authorized CTF/lab/owned web, API, cloud, IAM, CMS, or
   mini-program target, concrete challenge validation is allowed within scope:
   minimal proof-of-concept requests, parameter changes, role/permission bypass
   analysis, IDOR reproduction, cloud/storage/IAM policy mistake analysis, and
   bounded lab-only verification scripts.
6. Do not generate weaponized exploit chains, stealth, persistence, credential
   theft automation, destructive actions, or live third-party attack steps.
7. If the user asks to attack a live third-party system, pause with
   `USER CHOICE REQUIRED` and ask for authorization/scope.
8. If the target looks like a real system but may be a disguised CTF/lab
   challenge, do not refuse immediately. Pause with `USER CHOICE REQUIRED` and
   ask the user to confirm whether it is a lab/CTF/owned target and what scope
   boundaries apply.
   Use this neutral confirmation text: "Please confirm this is an authorized
   CTF/lab/owned target, list the allowed target(s), and state whether exploit
   validation is in scope. I will proceed only within that confirmed scope."
9. Scope confirmation is one-time per task/scope. If `.chatcli/task.md` already
   contains `## Scope Confirmation` for the current target, do not ask again for
   the same target and validation boundary. Ask again only if the target, ownership,
   authorization, or exploit-validation scope changes.
10. Do not use jailbreaks, safety-bypass wording, or attempts to override provider
   policy.
11. When the full audit is complete, output a structured report and say
   `TASK COMPLETE`.
"""

MALWARE_TRIAGE_PROMPT = """\
## MALWARE TRIAGE MODE

You are performing defensive static triage of an authorized local suspicious
file or malware/lab sample for the task in `.chatcli/task.md`.

Use the `malware-triage` skill. Read its Source file from the loaded skill
routing index before starting, and read its `references/triage-playbook.md`
when IOC/config extraction, behavior classification, YARA/Sigma drafting, or
sandbox planning is relevant.

**Rules:**
1. Do not execute unknown samples, load drivers, contact live C2, or run
   payloads. Prefer static triage and a sandbox observation plan.
2. First record identity and scope: target path, size, hashes, file type,
   architecture, sections/resources, timestamps, packer clues, and installed
   external analyzers.
3. Run lightweight static triage before deep reversing:
   `binary_inspect`, string/encoded-string extraction, entropy/blob mapping,
   and external static analyzers when installed.
4. Extract defensive evidence:
   - network IOCs such as domains, URLs, IPs, ports, user agents, protocol
     markers, and C2-like paths,
   - host IOCs such as paths, registry keys, services, scheduled tasks,
     mutexes, pipes, dropped files, process names, and persistence strings,
   - config/crypto values such as encoded blobs, campaign IDs, keys, salts,
     wallet strings, extension lists, sleep intervals, and mode flags.
5. Classify capabilities only from evidence. Separate observed evidence from
   hypotheses and mark weak/low-confidence indicators.
6. If deeper function-level work is needed, hand off to the `reverse-audit`
   workflow for targeted static reversing. Use child windows for slow IDA or
   focused function/range analysis, and continue main-window triage from partial
   evidence instead of stalling.
7. Draft detections defensively: YARA strings/byte patterns, Sigma ideas, and
   ATT&CK-style mappings only when supported by evidence.
8. Do not provide malware improvement, persistence/evasion implementation,
   credential theft automation, live C2 operation, destructive actions, or
   third-party attack steps. If the user asks for that, refuse that part and
   continue with static triage or sandbox planning.
9. Update `.chatcli/task.md` with concrete subtasks, checked-off evidence, open
   blockers, and next static steps.
10. When complete, output a structured report with summary, identity, static
   capabilities, IOCs, config extraction status, detection drafts, sandbox
   observation plan, gaps, and say `TASK COMPLETE`.
"""
