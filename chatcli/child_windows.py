"""Child-window, observer-child, and auto-request support for the REPL."""

import copy
from datetime import datetime
import hashlib
import io
from pathlib import Path
import re
import shlex
import threading
import time

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .agent import Agent
from .auto_requests import AutoRequestMixin
from .child_records import ChildRecordMixin
from .child_state import (
    ChildWindow,
    COMPLETED_CHILD_TTL,
    MAX_CONCURRENT_CHILDREN,
    MAX_TOTAL_CHILDREN,
)
from .orchestrate import ANALYSIS_ROLES, get_role_allowed_tools, get_role_prompt, get_observer_roles
from .worklog import get_task_status


class ChildWindowMixin(ChildRecordMixin, AutoRequestMixin):
    def _current_task_id(self) -> str:
        status = get_task_status(self.config.workspace) or {}
        return str(status.get("task_id") or "").strip()
    def _unique_child_name(self, base: str) -> str:
        root = self._safe_child_name(base)
        with self._children_lock:
            if root not in self.children:
                return root
            for i in range(2, 1000):
                candidate = f"{root}-{i}"
                if candidate not in self.children:
                    return candidate
        return f"{root}-{datetime.now().strftime('%H%M%S')}"
    def _safe_child_name(self, name: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", (name or "").strip()).strip("-_")
        return cleaned[:40] or "child"
    @staticmethod
    def _task_fingerprint(task: str) -> str:
        """Short hash of task text for deduplication."""
        normalized = re.sub(r"\s+", " ", (task or "").strip().lower())
        return hashlib.sha256(normalized.encode()).hexdigest()[:12]

    def _cleanup_orphans(self, active_task_id: str) -> int:
        """Remove completed children from old/stale task IDs. Returns count removed."""
        with self._children_lock:
            stale = [
                name for name, c in self.children.items()
                if c.status in ("done", "blocked", "error", "timeout")
                and c.task_id and active_task_id
                and c.task_id != active_task_id
            ]
            # Also clean old completed children beyond TTL
            now = time.time()
            for name, c in list(self.children.items()):
                if c.status in ("done", "blocked", "error", "timeout"):
                    if c.started_at > 0 and (now - c.started_at) > COMPLETED_CHILD_TTL:
                        if name not in stale:
                            stale.append(name)
            for name in stale:
                del self.children[name]
            return len(stale)

    def _running_child_count(self) -> int:
        with self._children_lock:
            return sum(1 for c in self.children.values() if c.status == "running")

    def _find_similar_child(self, task: str, task_id: str) -> ChildWindow | None:
        """Check if a child with very similar task already exists (dedup)."""
        fp = self._task_fingerprint(task)
        with self._children_lock:
            for child in self.children.values():
                if child.task_hash == fp and child.task_id == task_id:
                    return child
                # Also check: same name + similar task prefix
                if child.task_id == task_id:
                    existing = re.sub(r"\s+", " ", (child.task or "").strip().lower())
                    new = re.sub(r"\s+", " ", (task or "").strip().lower())
                    if existing and new and (
                        existing[:80] == new[:80] or existing in new or new in existing
                    ):
                        return child
        return None

    def _make_child(self, name: str, task_id: str | None = None, task: str = "") -> ChildWindow:
        child_name = self._safe_child_name(name)
        scoped_task_id = (task_id if task_id is not None else self._current_task_id()).strip()

        # Clean orphans before creating
        self._cleanup_orphans(scoped_task_id)

        with self._children_lock:
            # Dedup: if child with same name exists, return it
            if child_name in self.children:
                existing = self.children[child_name]
                if existing.status == "running":
                    raise ValueError(f"child already running: {child_name}")
                # Reuse idle/completed child
                return existing

            # Enforce max total children
            if len(self.children) >= MAX_TOTAL_CHILDREN:
                # Remove oldest completed children
                completed = sorted(
                    [(n, c) for n, c in self.children.items()
                     if c.status in ("done", "blocked", "error", "timeout")],
                    key=lambda x: x[1].started_at or 0,
                )
                for old_name, _ in completed[:max(1, len(completed) - MAX_TOTAL_CHILDREN + 4)]:
                    del self.children[old_name]

            buffer = io.StringIO()
            agent = Agent(copy.deepcopy(self.config))
            agent.console = Console(file=buffer, force_terminal=False, color_system=None, width=100)
            agent.auto_approve = self.agent.auto_approve
            agent.debug = self.agent.debug
            agent._session_name = f"child-{child_name}"
            agent._chatcli_task_id = scoped_task_id
            agent._chatcli_agent_role = "child"
            agent._chatcli_child_name = child_name
            agent._auto_save = lambda: None
            agent._log_work_action = lambda *args, **kwargs: None
            child = ChildWindow(
                name=child_name,
                agent=agent,
                buffer=buffer,
                task_id=scoped_task_id,
                notes_path=str(self._child_notes_path(child_name)),
                task_hash=self._task_fingerprint(task) if task else "",
            )
            self.children[child_name] = child
            return child
    def _child_prompt(self, child: ChildWindow, task: str) -> str:
        notes_path = Path(self.config.workspace) / ".chatcli" / "children" / f"{child.name}.md"
        return (
            f"[Child window: {child.name}]\n"
            "You are an independent parallel analysis session. The main window "
            "will continue its own work without waiting for you.\n"
            f"Task: {task}\n\n"
            "Rules:\n"
            f"- Write a thorough, self-contained result. The main window will only "
            f"  see your final output, not your conversation history.\n"
            f"- Persist key findings, file paths, hashes, offsets, decoded values, "
            f"  and concrete evidence to `{notes_path}` so the main window can "
            f"  read them later with the read_file tool.\n"
            "- Do not modify `.chatcli/task.md` or `.chatcli/worklog.md`; those "
            "  belong to the main window.\n"
            "- For malware/reverse subtasks, use the malware-triage or reverse-audit "
            "  skills as appropriate. Work methodically: inspect → extract → verify.\n"
            "- If you hit a hard blocker, return CHILD BLOCKED with the exact reason "
            "  so the main window can decide whether to retry or work around it.\n"
            "- End with CHILD COMPLETE and a compact but complete result that "
            "  includes: what you did, key evidence found, file paths written, "
            "  confidence level, and any recommended next steps for the main window.\n"
        )
    def _run_child_task(self, child: ChildWindow, task: str) -> None:
        # ── Dedup check ──
        task_id = child.task_id or self._current_task_id()
        similar = self._find_similar_child(task, task_id)
        if similar is not None and similar is not child:
            if similar.status == "running":
                self.console.print(
                    f"[dim]child dedup:[/] [cyan]{similar.name}[/] "
 f"[dim]already running similar task, skipping {child.name}[/]"
                )
                return
            if similar.status in ("done", "blocked", "error"):
                self.console.print(
                    f"[dim]child dedup:[/] [cyan]{similar.name}[/] "
                    f"[dim]already completed similar task, reusing result[/]"
                )
                # Copy result from similar child
                child.result = similar.result
                child.summary = similar.summary
                child.status = similar.status
                child.notes_path = similar.notes_path
                child.completed_at = similar.completed_at
                child.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                child.task = task
                self._write_child_record(child)
                return

        # ── Concurrency limit ──
        running = self._running_child_count()
        if running >= MAX_CONCURRENT_CHILDREN:
            self.console.print(
                f"[yellow]child queue:[/] [dim]{child.name} "
                f"({running}/{MAX_CONCURRENT_CHILDREN} children running, queued)[/]"
            )
            # Queue by waiting briefly and retrying (up to 30s)
            def queued_worker() -> None:
                waited = 0
                while self._running_child_count() >= MAX_CONCURRENT_CHILDREN and waited < 30:
                    time.sleep(2.0)
                    waited += 2
                self._start_child_worker(child, task)
            thread = threading.Thread(
                target=queued_worker,
                name=f"chatcli-child-{child.name}-queue",
                daemon=True,
            )
            child.thread = thread
            thread.start()
            return

        self._start_child_worker(child, task)

    def _start_child_worker(self, child: ChildWindow, task: str) -> None:
        """Actually start the child worker thread (called directly or from queue)."""
        with self._children_lock:
            if child.status == "running":
                return  # already started
            child.task_id = child.task_id or self._current_task_id()
            child.agent._chatcli_task_id = child.task_id
            child.status = "running"
            child.task = task
            child.result = ""
            child.error = ""
            child.summary = ""
            child.completed_at = ""
            child.started_at = time.monotonic()
            child.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._write_child_record(child)

        timeout = getattr(child, "timeout_seconds", 600.0)

        def worker() -> None:
            # Start timeout timer
            timed_out = False

            def on_timeout() -> None:
                nonlocal timed_out
                timed_out = True

            timer = threading.Timer(timeout, on_timeout)
            child._timeout_timer = timer
            timer.start()

            try:
                result = child.agent.run(self._child_prompt(child, task))
                timer.cancel()
                if timed_out:
                    return  # _mark_child_finished already called by timeout
                self._mark_child_finished(child, "done", result=result or "")
                self.console.print(
                    f"\n[green]child done[/] [cyan]{child.name}[/] "
                    f"[dim]{escape(child.summary)} | /child show {child.name}[/]"
                )
            except Exception as e:
                timer.cancel()
                if timed_out:
                    return
                self._mark_child_finished(
                    child,
                    "error",
                    error=f"{type(e).__name__}: {e}",
                )
                self.console.print(
                    f"\n[red]child error[/] [cyan]{child.name}[/] "
                    f"[dim]{escape(str(e)[:120])} | /child show {child.name}[/]"
                )

        thread = threading.Thread(
            target=worker,
            name=f"chatcli-child-{child.name}",
            daemon=True,
        )
        child.thread = thread
        thread.start()
    def _child_list(self):
        with self._children_lock:
            children = list(self.children.values())
        counts: dict[str, int] = {}
        for child in children:
            counts[child.status] = counts.get(child.status, 0) + 1
        count_text = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())) or "empty"
        table = Table(title=f"Child windows ({count_text})", box=box.SIMPLE, show_lines=False)
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Updated", no_wrap=True)
        table.add_column("Task")
        table.add_column("Summary")
        if not children:
            self.console.print("[dim]No child windows.[/]")
            return True
        for child in children:
            task = self._shorten_child_text(child.task, 46)
            summary = self._shorten_child_text(child.summary, 80)
            table.add_row(
                child.name,
                child.status,
                child.updated_at or child.created_at,
                task,
                summary,
            )
        self.console.print(table)
        return True
    def _child_show(self, name: str, lines: int = 40):
        child_name = self._safe_child_name(name)
        with self._children_lock:
            child = self.children.get(child_name)
        if not child:
            self.console.print(f"[yellow]Child not found:[/] [dim]{child_name}[/]")
            return True
        self.console.print(
            f"[cyan]{child.name}[/] [dim]{child.status} | updated {child.updated_at or child.created_at}[/]"
        )
        if child.task_id:
            self.console.print(f"[dim]task id: {child.task_id}[/]")
        if child.task:
            self.console.print(f"[dim]task: {child.task}[/]")
        if child.summary:
            self.console.print(f"[cyan]summary[/]: {escape(child.summary)}")
        if child.notes_path:
            self.console.print(f"[dim]record: {child.notes_path}[/]")
        if child.error:
            self.console.print(f"[red]{child.error}[/]")
        if child.result:
            preview = child.result.strip().splitlines()
            self.console.print("[dim]result[/]")
            for line in preview[-min(len(preview), 20):]:
                self.console.print(f"  {line}")
        output = child.buffer.getvalue().splitlines()
        if output:
            self.console.print("[dim]output tail[/]")
            for line in output[-max(1, lines):]:
                self.console.print(f"  [dim]{line}[/]")
        return True
    def _child_summarize(self, name: str = ""):
        with self._children_lock:
            if name:
                child = self.children.get(self._safe_child_name(name))
                children = [child] if child else []
            else:
                children = list(self.children.values())
        if not children:
            self.console.print("[yellow]No matching child windows to summarize.[/]")
            return True
        parts = []
        for child in children:
            tail = "\n".join(child.buffer.getvalue().splitlines()[-40:])
            parts.append(
                f"## {child.name}\n"
                f"status: {child.status}\n"
                f"task: {child.task}\n"
                f"summary: {child.summary or '(none)'}\n"
                f"record: {child.notes_path or '(none)'}\n"
                f"result:\n{child.result or '(no final result yet)'}\n"
                f"error: {child.error or '(none)'}\n"
                f"output_tail:\n{tail}\n"
            )
        prompt = (
            "[Main window child-summary request]\n"
            "Summarize these child window results. Extract useful findings, blockers, "
            "and recommended next actions. Keep it concise.\n\n"
            + "\n\n".join(parts)
        )
        self.agent.run(prompt)
        self._process_auto_requests()
        return True
    def _child_context_summary(self, limit: int = 8, task_id: str | None = None) -> str:
        with self._children_lock:
            children = list(self.children.values())
        active_task_id = (task_id if task_id is not None else self._current_task_id()).strip()
        if active_task_id:
            children = [child for child in children if child.task_id == active_task_id]
        if not children:
            return ""
        children = sorted(
            children,
            key=lambda c: c.updated_at or c.created_at,
            reverse=True,
        )[:max(1, limit)]
        running = [c for c in children if c.status == "running"]
        completed = [c for c in children if c.status in ("done", "blocked", "error")]
        lines = ["[Child window status — use read_file to get full child results]"]
        if running:
            lines.append("## Still running (do NOT duplicate their work):")
            for child in running:
                task = self._shorten_child_text(child.task or "", 120)
                lines.append(f"- {child.name}: {task}")
        if completed:
            lines.append("## Completed (read their records and merge findings):")
            for child in completed:
                status_mark = {"done": "✓", "blocked": "⊘", "error": "✗"}.get(child.status, child.status)
                summary = self._shorten_child_text(child.summary or "(no summary)", 400)
                notes = child.notes_path or f".chatcli/children/{child.name}.md"
                task_short = self._shorten_child_text(child.task or "", 100)
                lines.append(
                    f"- [{status_mark}] {child.name}: {summary}\n"
                    f"  record: {notes} | task: {task_short}"
                )
        if running:
            lines.append(
                "Do not wait for running children; continue main-window work "
                "and read their results in a later cycle."
            )
        if completed:
            lines.append(
                "Use read_file on each child's record path to get full results "
                "before finalizing the main report. Unmerged child findings are "
                "a common cause of incomplete reports."
            )
        return "\n".join(lines)
    @staticmethod
    def _compression_context(events: list[dict]) -> str:
        if not events:
            return ""
        lines = ["[Context compression occurred during the previous cycle]"]
        for event in events[-3:]:
            lines.append(
                "- summarized={messages_summarized} archived_to={archived_to} "
                "tokens={before_tokens}->{after_tokens} saved={saved_tokens}".format(**event)
            )
        lines.append(
            "Continue the same active task from .chatcli/task.md and child summaries; "
            "do not restart analysis from scratch."
        )
        return "\n".join(lines)
    def _child_wait(self, name: str = "all"):
        target = (name or "all").strip()
        with self._children_lock:
            if target.lower() in ("", "all", "*"):
                children = list(self.children.values())
            else:
                child = self.children.get(self._safe_child_name(target))
                children = [child] if child else []
        if not children:
            self.console.print("[yellow]No matching child windows to wait for.[/]")
            return True
        for child in children:
            thread = child.thread
            if thread and thread.is_alive():
                self.console.print(f"[dim]waiting child {child.name}...[/]")
                thread.join()
        self._process_auto_requests()
        return self._child_list()
    # ── Observer child methods ───────────────────────────────────

    def _make_observer_child(self, role_name: str, result_dir: str) -> ChildWindow | None:
        """Create a child agent with role-restricted tool set for analyzing results.

        The child gets only the tools allowed for its role, plus read_file for
        reading other children's records.
        """
        from .orchestrate import ANALYSIS_ROLES

        role = ANALYSIS_ROLES.get(role_name)
        if not role:
            self.console.print(f"[yellow]Unknown role:[/] [dim]{role_name}[/]")
            return None

        child_name = self._unique_child_name(role_name)
        child = self._make_child(child_name)

        # Filter tool registry to role-allowed tools
        allowed = role.get("allowed_tools", [])
        child.agent.tools = self._filter_tools_for_role(allowed)

        # Store role info for the prompt
        child._observer_role = role_name
        child._observer_result_dir = result_dir

        self.console.print(
            f"[green]observer created[/] [cyan]{child.name}[/] "
            f"[dim]({role_name}, {len(allowed)} tools)[/]"
        )
        return child

    def _filter_tools_for_role(self, allowed: list[str]):
        """Create a restricted ToolRegistry with only the specified tools."""
        from .tools.base import ToolRegistry

        filtered = ToolRegistry()
        main_tools = self.agent.tools
        for name in allowed:
            tool = main_tools.get(name)
            if tool is not None:
                filtered.register(tool)

        # Always include read_file for reading child records
        if "read_file" not in allowed:
            read_tool = main_tools.get("read_file")
            if read_tool is not None:
                filtered.register(read_tool)

        return filtered

    def _observer_prompt(self, child: ChildWindow, task: str) -> str:
        """Build the prompt for an observer child agent."""
        role_name = getattr(child, "_observer_role", "observer")
        result_dir = getattr(child, "_observer_result_dir", "")
        role = ANALYSIS_ROLES.get(role_name, {})
        role_prompt = get_role_prompt(role_name)
        notes_path = Path(self.config.workspace) / ".chatcli" / "children" / f"{child.name}.md"
        patterns = role.get("input_patterns", [])

        role_section = role_prompt if role_prompt else f"You are the {role_name}."
        dir_section = (
            f"\n\nResult directory to analyze: {result_dir}\n"
            f"Start by using glob on these role input patterns: {', '.join(patterns) or '(all relevant files)'}.\n"
            f"Read all relevant files from this directory using the read_file tool."
        ) if result_dir else ""

        return (
            f"[Observer: {child.name} — {role_name}]\n"
            f"You are an independent parallel analysis session. The main window "
            f"will continue its own work without waiting for you.\n\n"
            f"{role_section}"
            f"{dir_section}\n\n"
            f"Task: {task}\n\n"
            "Rules:\n"
            f"- Write a thorough, self-contained result. The main window and correlator "
            f"  will only see your final output, not your conversation history.\n"
            f"- Persist key findings, evidence, and conclusions to `{notes_path}`.\n"
            "- Do not modify `.chatcli/task.md` or `.chatcli/worklog.md`.\n"
            "- Be precise about evidence: cite exact file paths, line numbers, "
            "  hash values, API names, offsets.\n"
            "- For dynamic/monitor evidence, prioritize structured fields such as "
            "  dynamic_status.events, process_metrics.count/sample/top_memory, "
            "  traffic_capture, file_activity, and observer_agents before raw logs.\n"
            "- Use confidence labels (high/medium/low) for every claim.\n"
            "- End with a clear summary block that the correlator can consume.\n"
        )

    def _spawn_observers(self, result_dir: str, roles: list[str] | None = None) -> list[str]:
        """Spawn observer children for all or specified roles.

        Returns list of child names created.
        """
        role_names = roles if roles else get_observer_roles()
        created = []
        task_description = (
            f"Analyze the results in {result_dir}. Read result files, extract "
            f"evidence, form conclusions. Write findings to your child record."
        )

        for role_name in role_names:
            child = self._make_observer_child(role_name, result_dir)
            if child is None:
                continue

            task = f"[{role_name}] {task_description}"
            self._run_child_task(child, self._observer_prompt(child, task))
            created.append(child.name)

        return created

    # ── Command handling ─────────────────────────────────────────

    def _handle_observe(self, a):
        """Handle /observe command — spawn analysis observers for remote results."""
        args = shlex.split(a or "", posix=False) if a else []
        if not args:
            self.console.print(
                "[yellow]Usage:[/] /observe <result_dir> [roles...]\n"
                "[dim]Roles: static_observer, dynamic_observer, network_observer, correlator[/]"
            )
            return True

        result_dir = args[0]
        roles = args[1:] if len(args) > 1 else None
        created = self._spawn_observers(result_dir, roles)
        self.console.print(
            f"[green]{len(created)} observers spawned[/] "
            f"[dim]for {result_dir}[/]"
        )
        return True

    def _handle_child(self, a):
        try:
            parts = shlex.split(a or "", posix=False)
        except ValueError as e:
            self.console.print(f"[yellow]Invalid arguments:[/] [dim]{e}[/]")
            return True
        action = parts[0].lower() if parts else "list"
        if action in ("list", "ls", "status"):
            return self._child_list()
        if action == "new":
            if len(parts) < 2:
                self.console.print("[yellow]Usage: /child new <name> [task][/]")
                return True
            child = self._make_child(parts[1])
            self.console.print(f"[green]child created[/] [cyan]{child.name}[/]")
            if len(parts) > 2:
                task = " ".join(parts[2:])
                self._run_child_task(child, task)
                self.console.print(f"[green]child running[/] [cyan]{child.name}[/]")
            return True
        if action == "run":
            if len(parts) < 3:
                self.console.print("[yellow]Usage: /child run <name> <task>[/]")
                return True
            child_name = self._safe_child_name(parts[1])
            with self._children_lock:
                child = self.children.get(child_name)
            if not child:
                child = self._make_child(child_name)
                self.console.print(f"[green]child created[/] [cyan]{child.name}[/]")
            self._run_child_task(child, " ".join(parts[2:]))
            self.console.print(f"[green]child running[/] [cyan]{child.name}[/]")
            return True
        if action == "show":
            if len(parts) < 2:
                self.console.print("[yellow]Usage: /child show <name> [lines][/]")
                return True
            lines = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 40
            return self._child_show(parts[1], lines)
        if action in ("summarize", "summary"):
            return self._child_summarize(parts[1] if len(parts) > 1 else "")
        if action == "wait":
            return self._child_wait(parts[1] if len(parts) > 1 else "all")
        if action == "close":
            if len(parts) < 2:
                self.console.print("[yellow]Usage: /child close <name>[/]")
                return True
            child_name = self._safe_child_name(parts[1])
            with self._children_lock:
                child = self.children.get(child_name)
                if not child:
                    self.console.print(f"[yellow]Child not found:[/] [dim]{child_name}[/]")
                    return True
                if child.status == "running":
                    self.console.print("[yellow]Child is running; wait for it before closing.[/]")
                    return True
                del self.children[child_name]
            self.console.print(f"[green]child closed[/] [cyan]{child_name}[/]")
            return True
        self.console.print(
            "[yellow]Usage:[/] /child new|run|list|show|summarize|wait|close"
        )
        return True
