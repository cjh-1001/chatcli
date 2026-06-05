"""Session, history, and autosave support for Agent."""

import json
import shutil
from datetime import datetime
from pathlib import Path

from .context import build_system_prompt


def session_dir_for_workspace(workspace: str | Path) -> Path:
    return Path(workspace).resolve() / ".chatcli" / "sessions"


def last_session_file_for_workspace(workspace: str | Path) -> Path:
    return Path(workspace).resolve() / ".chatcli" / "last_session.json"


class AgentSessionMixin:
    def _update_system_prompt(self):
        """Refresh the system prompt to match current workspace."""
        if self._history and self._history[0].get("role") == "system":
            self._history[0] = {"role": "system", "content": build_system_prompt(
                self.workspace, self.config.context_file
            )}

    def _repair_history(self):
        """Fix empty content messages that strict APIs reject."""
        repaired = 0
        for m in self._history:
            content = m.get("content", "")
            if isinstance(content, str) and not content.strip():
                m["content"] = "(done)"
                repaired += 1
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and "text" in block and not block["text"].strip():
                        block["text"] = "(done)"
                        repaired += 1
        if repaired and self.debug:
            self._safe_print(f"[dim]● repaired {repaired} empty messages[/]")

    def auto_restore(self) -> bool:
        """Restore the last session if it exists. Returns True if restored."""
        from .checkpoint import was_crashed, get_crash_info

        if was_crashed(self.workspace):
            crash_info = get_crash_info(self.workspace)
            crash_time = crash_info.get("started", "unknown") if crash_info else "unknown"
            self._safe_print(
                f"[yellow]! previous session may have crashed[/] "
                f"[dim]({crash_time})[/]"
            )
            self._safe_print(
                f"[dim]● restoring last saved state...[/]"
            )

        last_session_file = self._last_session_file()
        last_backup = last_session_file.with_name(last_session_file.name + ".bak")
        if not last_session_file.exists() and not last_backup.exists():
            return False

        try:
            data = self._read_json_with_backup(last_session_file)
            self._history = data.get("messages", self._history)
            self._session_name = data.get("name")
            self._total_tokens = data.get("tokens", {"input": 0, "output": 0})
            self._tool_calls_total = int(data.get("tool_calls", self._tool_calls_total))

            # Update system prompt to reflect current workspace
            self._update_system_prompt()

            self._repair_history()

            msg_count = len([m for m in self._history if m["role"] != "system"])
            name = self._session_name or "last session"
            self._safe_print(f"[dim]● restored {name}[/] [dim]({msg_count} messages)[/]")
            return True
        except Exception as e:
            self._safe_print(f"[yellow]x failed to restore session[/] [dim]{e}[/]")
            return False

    def _atomic_write_json(self, path: Path, data: dict) -> None:
        """Write JSON atomically and keep a one-version backup."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        backup = path.with_name(path.name + ".bak")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if path.exists():
            try:
                shutil.copy2(path, backup)
            except Exception:
                pass
        tmp.replace(path)

    def _read_json_with_backup(self, path: Path) -> dict:
        """Read JSON, falling back to the last backup if the main file is bad."""
        backup = path.with_name(path.name + ".bak")
        last_error: Exception | None = None
        for candidate in (path, backup):
            if not candidate.exists():
                continue
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except Exception as e:
                last_error = e
        if last_error:
            raise last_error
        raise FileNotFoundError(path)

    def _session_data(self, name: str | None = None) -> dict:
        return {
            "name": name or self._session_name or "last",
            "workspace": self.workspace,
            "saved_at": datetime.now().isoformat(),
            "tokens": self._total_tokens,
            "tool_calls": self._tool_calls_total,
            "messages": self._history,
        }

    def _session_path(self, name: str) -> Path:
        if Path(name).name != name or "/" in name or "\\" in name:
            raise ValueError("Session name must not contain path separators.")
        return self._sessions_dir() / f"{name}.json"

    def _sessions_dir(self) -> Path:
        return session_dir_for_workspace(self.workspace)

    def _last_session_file(self) -> Path:
        return last_session_file_for_workspace(self.workspace)

    def _safe_session_stem(self) -> str:
        name = self._session_name or "last"
        stem = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in name)
        return stem.strip("-_") or "last"

    def _archive_compressed_messages(self, messages: list[dict]) -> Path | None:
        """Persist raw messages before replacing them with a summary."""
        if not messages:
            return None
        archive_dir = self._sessions_dir() / "_segments" / self._safe_session_stem()
        archive_path = archive_dir / f"{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
        data = {
            "session": self._session_name or "last",
            "workspace": self.workspace,
            "archived_at": datetime.now().isoformat(),
            "message_count": len(messages),
            "messages": messages,
        }
        try:
            self._atomic_write_json(archive_path, data)
            return archive_path
        except Exception as e:
            self._safe_print(
                f"[yellow]x compression archive failed[/] [dim]{e}; keeping full history[/]"
            )
            return None

    def save_session(self, name: str | None = None) -> str:
        """Save current session to disk. Returns session name."""
        self._sessions_dir().mkdir(parents=True, exist_ok=True)

        if not name:
            name = datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            filepath = self._session_path(name)
        except ValueError as e:
            self._safe_print(f"[yellow]x invalid session name[/] [dim]{e}[/]")
            return self._session_name or "last"
        self._session_name = name

        data = self._session_data(name)

        # Save named session
        self._atomic_write_json(filepath, data)

        # Save as last session for auto-restore
        self._atomic_write_json(self._last_session_file(), data)

        msg_count = len([m for m in self._history if m["role"] != "system"])
        self._safe_print(f"[dim]● session '{name}' saved[/] [dim]({msg_count} messages)[/]")
        return name

    def load_session(self, name: str) -> bool:
        """Load a named session. Returns True on success."""
        try:
            filepath = self._session_path(name)
        except ValueError as e:
            self._safe_print(f"[yellow]x invalid session name[/] [dim]{e}[/]")
            return False
        backup = filepath.with_name(filepath.name + ".bak")
        if not filepath.exists() and not backup.exists():
            self._safe_print(f"[yellow]x session '{name}' not found[/]")
            return False

        try:
            data = self._read_json_with_backup(filepath)
            self._history = data.get("messages", [])
            self._session_name = name
            self._total_tokens = data.get("tokens", {"input": 0, "output": 0})
            self._tool_calls_total = int(data.get("tool_calls", self._tool_calls_total))

            # Update system prompt
            self._update_system_prompt()

            self._repair_history()

            msg_count = len([m for m in self._history if m["role"] != "system"])
            self._safe_print(f"[dim]● loaded '{name}'[/] [dim]({msg_count} messages)[/]")
            self._auto_save()
            return True
        except Exception as e:
            self._safe_print(f"[red]x failed to load '{name}'[/] [dim]{e}[/]")
            return False

    def list_sessions(self) -> list[dict]:
        """List all saved sessions."""
        sessions_dir = self._sessions_dir()
        if not sessions_dir.exists():
            return []

        sessions = []
        for f in sorted(sessions_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                sessions.append({
                    "name": f.stem,
                    "workspace": data.get("workspace", ""),
                    "saved_at": data.get("saved_at", ""),
                    "messages": len([m for m in data.get("messages", []) if m["role"] != "system"]),
                })
            except Exception:
                pass
        return sessions

    def _auto_save(self):
        """Save the current in-memory history to the resumable last session."""
        try:
            self._atomic_write_json(self._last_session_file(), self._session_data())
            self._last_autosave_error = None
        except Exception as e:
            msg = str(e) or type(e).__name__
            if msg != self._last_autosave_error:
                self._safe_print(f"[yellow]x auto-save failed[/] [dim]{msg}[/]")
                self._last_autosave_error = msg

    def reset(self):
        """Clear conversation history."""
        self._init_system_prompt()
        self._auto_save()
        self._safe_print("[dim]● history cleared[/]")

    def clear_history(self, archive: bool = True) -> None:
        """Clear chat history while preserving durable learning surfaces."""
        if archive:
            messages = self._history[1:] if self._history else []
            archive_path = self._archive_compressed_messages(messages)
            if archive_path:
                self._safe_print(f"[dim]history archived to {archive_path}[/]")
        self._init_system_prompt()
        self._auto_save()
        self._safe_print(
            "[green]history cleared[/] "
            "[dim]memory, skills, config, checkpoints, and evolve state preserved[/]"
        )

    def toggle_auto(self) -> bool:
        """Toggle auto-approve mode. Returns new state."""
        self.auto_approve = not self.auto_approve
        if self.auto_approve:
            self._safe_print("[green]+ AUTO MODE ON[/] [dim]all tools auto-approved[/]")
        else:
            self._safe_print("[dim]+ AUTO MODE OFF[/] [dim]permissions restored[/]")
        return self.auto_approve

    def toggle_debug(self) -> bool:
        """Toggle debug mode. Returns new state."""
        self.debug = not self.debug
        if self.debug:
            self._safe_print("[yellow]● DEBUG MODE ON[/] [dim]message counts, tool calls, tokens[/]")
        else:
            self._safe_print("[dim]● DEBUG MODE OFF[/]")
        return self.debug


