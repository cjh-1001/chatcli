"""Child-window and auto-request support for the REPL."""

import copy
from datetime import datetime
import io
from pathlib import Path
import re
import shlex
import threading

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .agent import Agent
from .auto_requests import AutoRequestMixin
from .child_records import ChildRecordMixin
from .child_state import ChildWindow
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
    def _make_child(self, name: str, task_id: str | None = None) -> ChildWindow:
        child_name = self._safe_child_name(name)
        with self._children_lock:
            if child_name in self.children:
                raise ValueError(f"child already exists: {child_name}")
            buffer = io.StringIO()
            agent = Agent(copy.deepcopy(self.config))
            agent.console = Console(file=buffer, force_terminal=False, color_system=None, width=100)
            agent.auto_approve = self.agent.auto_approve
            agent.debug = self.agent.debug
            agent._session_name = f"child-{child_name}"
            scoped_task_id = (task_id if task_id is not None else self._current_task_id()).strip()
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
            )
            self.children[child_name] = child
            return child
    def _child_prompt(self, child: ChildWindow, task: str) -> str:
        notes_path = Path(self.config.workspace) / ".chatcli" / "children" / f"{child.name}.md"
        return (
            f"[Child window: {child.name}]\n"
            "You are running as an independent child analysis session under the main chatcli window.\n"
            "Keep your own context. Do not rely on the main window to remember details.\n"
            f"Task: {task}\n\n"
            "Rules:\n"
            f"- Persist durable notes to `{notes_path}` when the task has findings worth keeping.\n"
            "- Do not modify `.chatcli/task.md` or `.chatcli/worklog.md`; those belong to the main window.\n"
            "- If this is reverse/exe analysis, use the reverse-audit skill: binary_inspect first, then IDA when useful, then explain evidence.\n"
            "- If blocked, return a concise status and the exact blocker instead of looping.\n"
            "- End with a compact result that the main window can summarize.\n"
            "- Put one clear final marker in the last lines: CHILD COMPLETE, CHILD BLOCKED, or CHILD ERROR.\n"
        )
    def _run_child_task(self, child: ChildWindow, task: str) -> None:
        with self._children_lock:
            if child.status == "running":
                raise ValueError(f"child is already running: {child.name}")
            child.task_id = child.task_id or self._current_task_id()
            child.agent._chatcli_task_id = child.task_id
            child.status = "running"
            child.task = task
            child.result = ""
            child.error = ""
            child.summary = ""
            child.completed_at = ""
            child.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._write_child_record(child)

        def worker() -> None:
            try:
                result = child.agent.run(self._child_prompt(child, task))
                self._mark_child_finished(child, "done", result=result or "")
                self.console.print(
                    f"\n[green]child done[/] [cyan]{child.name}[/] "
                    f"[dim]{escape(child.summary)} | /child show {child.name}[/]"
                )
            except Exception as e:
                self._mark_child_finished(
                    child,
                    "error",
                    error=f"{type(e).__name__}: {e}",
                )
                self.console.print(
                    f"\n[red]child error[/] [cyan]{child.name}[/] "
                    f"[dim]{escape(child.summary)} | /child show {child.name}[/]"
                )

        thread = threading.Thread(target=worker, name=f"chatcli-child-{child.name}", daemon=True)
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
        lines = ["[Child window status summary for main-loop planning]"]
        for child in children:
            summary = self._shorten_child_text(child.summary or "(no summary yet)", 260)
            task = self._shorten_child_text(child.task or "", 140)
            lines.append(
                f"- {child.name}: status={child.status}; summary={summary}; "
                f"record={child.notes_path or '(none)'}; task_id={child.task_id or '(none)'}; "
                f"task={task}"
            )
        lines.append(
            "Use completed child summaries to choose the next main-window step. "
            "If a child is still running, do not duplicate its detailed work in the main context."
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

