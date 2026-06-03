"""Auto-request queue support for REPL child delegation."""

from datetime import datetime
import json
import os
from pathlib import Path

from rich import box
from rich.table import Table


class AutoRequestMixin:
    def _auto_requests_path(self) -> Path:
        return Path(self.config.workspace) / ".chatcli" / "auto_requests.jsonl"
    def _auto_request_batch_paths(self) -> list[Path]:
        path = self._auto_requests_path()
        candidates: list[Path] = []
        legacy = path.with_name(f"{path.name}.processing")
        if legacy.exists():
            candidates.append(legacy)
        candidates.extend(sorted(path.parent.glob(f"{path.name}.*.processing")))
        unique: list[Path] = []
        seen = set()
        for candidate in candidates:
            key = str(candidate)
            if key not in seen:
                unique.append(candidate)
                seen.add(key)
        return unique
    def _read_auto_request_events(self) -> list[dict]:
        paths = []
        path = self._auto_requests_path()
        if path.exists():
            paths.append(path)
        paths.extend(self._auto_request_batch_paths())
        if not paths:
            return []
        events = []
        for event_path in paths:
            try:
                raw_lines = event_path.read_text(encoding="utf-8").splitlines()
            except Exception:
                continue
            for raw in raw_lines:
                if not raw.strip():
                    continue
                try:
                    event = json.loads(raw)
                except Exception:
                    continue
                if isinstance(event, dict):
                    events.append(event)
        return events
    def _pending_auto_request_count(self) -> int:
        return len(self._read_auto_request_events())
    def _handle_auto_requests(self, a: str):
        parts = a.split()
        action = parts[0].lower() if parts else "list"
        path = self._auto_requests_path()
        if action in ("list", "ls", "status"):
            events = self._read_auto_request_events()
            if not events:
                self.console.print("[dim]No queued auto requests.[/]")
                return True
            table = Table(title="Auto requests", box=box.SIMPLE, show_lines=False)
            table.add_column("Type", style="cyan", no_wrap=True)
            table.add_column("Name", no_wrap=True)
            table.add_column("Reason")
            for event in events:
                table.add_row(
                    str(event.get("request_type", "")),
                    str(event.get("name") or event.get("skill_name") or ""),
                    str(event.get("reason", "")),
                )
            self.console.print(table)
            return True
        if action in ("process", "run"):
            self._process_auto_requests()
            return True
        if action == "clear":
            try:
                if path.exists():
                    path.write_text("", encoding="utf-8")
                for batch_path in self._auto_request_batch_paths():
                    batch_path.unlink(missing_ok=True)
                self.console.print("[green]auto requests cleared[/]")
            except Exception as e:
                self.console.print(f"[yellow]auto request clear failed[/] [dim]{e}[/]")
            return True
        self.console.print("[yellow]Usage: /auto-requests list|process|clear[/]")
        return True
    def _record_skill_note(self, skill_name: str, note: str, reason: str = "") -> None:
        path = Path(self.config.workspace) / ".chatcli" / "skill-improvements.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a", encoding="utf-8") as f:
            f.write(
                f"\n## {now} - {skill_name or 'general'}\n\n"
                f"- Note: {note or '(no note)'}\n"
                f"- Reason: {reason or '(no reason)'}\n"
            )
    def _process_auto_requests(self):
        if self._auto_requests_processing:
            return
        path = self._auto_requests_path()
        batch_paths = self._auto_request_batch_paths()
        try:
            self._auto_requests_processing = True
            if path.exists():
                stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
                batch_path = path.with_name(f"{path.name}.{stamp}.processing")
                os.replace(path, batch_path)
                batch_paths.append(batch_path)
            if not batch_paths:
                self._auto_requests_processing = False
                return
            raw_lines = []
            for batch_path in batch_paths:
                try:
                    raw_lines.extend(batch_path.read_text(encoding="utf-8").splitlines())
                    batch_path.unlink(missing_ok=True)
                except Exception as e:
                    self.console.print(f"[yellow]auto request batch read failed[/] [dim]{e}[/]")
        except Exception as e:
            self.console.print(f"[yellow]auto request read failed[/] [dim]{e}[/]")
            self._auto_requests_processing = False
            return
        try:
            clear_after = False
            for raw in raw_lines:
                if not raw.strip():
                    continue
                try:
                    event = json.loads(raw)
                except Exception:
                    continue
                req_type = event.get("request_type", "")
                reason = event.get("reason", "")
                if req_type == "child_task":
                    task = event.get("task", "")
                    if not task:
                        continue
                    name = self._unique_child_name(event.get("name") or "auto-child")
                    child = self._make_child(name)
                    child.agent.auto_approve = True
                    self._run_child_task(child, task)
                    self.console.print(
                        f"[green]auto child[/] [cyan]{child.name}[/] [dim]{reason}[/]"
                    )
                elif req_type == "skill_improvement":
                    skill_name = event.get("skill_name", "") or "general"
                    note = event.get("note", "")
                    self._record_skill_note(skill_name, note, reason)
                    self.console.print(
                        f"[green]skill note recorded[/] [cyan]{skill_name}[/]"
                    )
                    if event.get("apply"):
                        name = self._unique_child_name(f"skill-{skill_name}")
                        child = self._make_child(name)
                        task = (
                            f"Use the skill-creator workflow to improve skill `{skill_name}`. "
                            f"Reusable note: {note}. Reason: {reason}. Keep the edit concise, "
                            "do not add one-off details, preserve safety boundaries, and report changed files."
                        )
                        self._run_child_task(child, task)
                        self.console.print(
                            f"[green]auto skill child[/] [cyan]{child.name}[/]"
                        )
                elif req_type == "history_clear":
                    clear_after = True
                    self.console.print(f"[yellow]history clear requested[/] [dim]{reason}[/]")
            if clear_after:
                self.agent.clear_history(archive=True)
        finally:
            self._auto_requests_processing = False

