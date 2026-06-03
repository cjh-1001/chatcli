from pathlib import Path
import os
import platform
import shutil
import sys
import threading
from rich.console import Console
from rich.panel import Panel
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.shortcuts import radiolist_dialog
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.styles import Style
from .agent import Agent
from .child_windows import ChildWindow, ChildWindowMixin
from .context import get_workspace_info
from rich import box
from .evolve import start_evolve, start_continuous, build_evolve_first_prompt
from .checkpoint import list_backups, restore_backup
from .memory import list_memories, _memory_dir
from .skills import discover_skills, rank_skills
from rich.table import Table
from .ui_commands import COMMAND_DEFS, COMMAND_ALIASES, REPLCompleter
from .ui_reverse import ReverseCommandMixin
from .ui_work import WorkCommandMixin

WELCOME_INFO = """[bold cyan]chatcli[/] - CLI superpowers
Provider: {provider} | Model: {model}
Workspace: {workspace}
Type /help for commands, /exit to quit."""

class REPL(ChildWindowMixin, ReverseCommandMixin, WorkCommandMixin):
    def __init__(self, config):
        self.config = config
        self.console = Console()
        self.agent = Agent(config)
        self.children: dict[str, ChildWindow] = {}
        self._children_lock = threading.RLock()
        self._auto_requests_processing = False
        self._awaiting_work_choice = False
        self._awaiting_scope_confirmation = False
        self._interactive = sys.stdin.isatty() and sys.stdout.isatty()
        if config.auto_resume: self.agent.auto_restore()
        hf = Path(config.workspace).resolve() / ".chatcli" / "history"
        hf.parent.mkdir(parents=True, exist_ok=True)
        kb = KeyBindings()
        @kb.add("c-d")
        def _(event): event.app.exit()
        style = Style.from_dict({
            "prompt": "bold cyan",
            "completion-menu.completion": "bg:#202020 #d0d0d0",
            "completion-menu.completion.current": "bg:#005f87 #ffffff",
            "completion-menu.meta.completion": "bg:#202020 #9aa0a6",
            "completion-menu.meta.completion.current": "bg:#005f87 #ffffff",
        })
        self.session = None
        if self._interactive:
            self.session = PromptSession(
                history=FileHistory(str(hf)), key_bindings=kb, style=style,
                completer=REPLCompleter(config.workspace),
                complete_while_typing=True,
                complete_style=CompleteStyle.MULTI_COLUMN,
                reserve_space_for_menu=8,
                multiline=False)
    def print_welcome(self):
        info = get_workspace_info(self.config.workspace)
        body = WELCOME_INFO.format(provider=self.config.provider.provider, model=self.config.provider.model, workspace=info or str(self.config.workspace))
        self.console.print(Panel(body, border_style="cyan", padding=(1,2)))
    def print_help(self):
        table = Table(
            title="Commands",
            box=box.SIMPLE,
            show_lines=False,
            header_style="bold cyan",
        )
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description")
        for _, usage, description in COMMAND_DEFS:
            table.add_row(usage, description)
        self.console.print(table)
    def run(self):
        from .checkpoint import mark_clean
        try:
            self.print_welcome()
            if not self.session:
                self.console.print("[yellow]No interactive terminal available.[/]")
                return
            if getattr(self, '_resume_flag', False) and not self.config.auto_resume:
                self.agent.auto_restore()
            # Handle --evolve CLI flag: launch continuous mode directly
            if getattr(self, '_evolve_flag', False):
                focus = getattr(self, '_evolve_focus', '')
                start_continuous(self.config.workspace, focus=focus)
                self.agent.run_continuous()
                return
            while True:
                try: ui = self.session.prompt([("class:prompt", "  > ")]).strip()
                except (EOFError, KeyboardInterrupt): self.console.print("\n[dim]Goodbye![/]"); break
                if not ui: continue
                r = self._handle_command(ui)
                if r == "EXIT": break
                if r is not None: continue
                self._handle_smart_input(ui)
        finally:
            mark_clean(self.config.workspace)
    def _handle_command(self, ui):
        p=ui.split()
        if not p or not p[0].startswith("/"): return None
        c=p[0].lower(); a=" ".join(p[1:]) if len(p)>1 else ""
        if c in COMMAND_ALIASES:
            c, alias_arg = COMMAND_ALIASES[c]
            a = alias_arg if not a else f"{alias_arg} {a}"
        if c in ("/help","/?"): self.print_help(); return True
        if c in ("/exit","/quit","/q"): self.agent.save_session(); return "EXIT"
        simple_commands = {
            "/reset": lambda: self.agent.reset(),
            "/auto": lambda: self.agent.toggle_auto(),
            "/debug": lambda: self.agent.toggle_debug(),
            "/compress": lambda: self.agent.compress_now(),
        }
        if c in simple_commands:
            simple_commands[c]()
            return True
        if c=="/session": return self._handle_session(a)
        if c=="/history": return self._handle_history(a)
        if c=="/skills": return self._handle_skills(a)
        if c=="/child": return self._handle_child(a)
        if c in ("/auto-requests", "/autorequests"): return self._handle_auto_requests(a)
        if c=="/plan":
            self.agent.plan(a or "Help me plan a task")
            self._process_auto_requests()
            return True
        if c=="/init":
            self.agent.init_project()
            self._process_auto_requests()
            return True
        if c=="/work": return self._handle_work(a)
        if c=="/audit": return self._handle_audit(a)
        if c=="/malware": return self._handle_malware(a)
        if c=="/reverse": return self._handle_reverse(a)
        if c=="/evolve": return self._handle_evolve(a)
        if c=="/doctor": return self._handle_doctor()
        if c=="/permissions": return self._handle_permissions(a)
        if c=="/checkpoint": return self._handle_checkpoint(a)
        if c=="/memory": return self._handle_memory(a)
        if c=="/context":
            cf = Path(self.config.workspace) / self.config.context_file
            self.console.print(f"[dim]Context:{cf}[/]" if cf.exists() else f"[dim]No context at {cf}[/]")
            return True
        return None
    def _handle_session(self, a):
        parts = a.split(maxsplit=1)
        action = parts[0].lower() if parts else "open"
        rest = parts[1] if len(parts) > 1 else ""
        if action == "save":
            self.agent.save_session(rest if rest else None)
            return True
        if action == "load":
            if not rest:
                selected = self._pick_session()
                if selected:
                    self.agent.load_session(selected)
                return True
            self.agent.load_session(rest)
            return True
        if action in ("open", "pick", "select"):
            selected = self._pick_session()
            if selected:
                self.agent.load_session(selected)
            return True
        if action in ("list", "ls"):
            return self._sessions()
        self.console.print("[yellow]Usage: /session | /session save [name] | load [name] | list[/]")
        return True
    def _pick_session(self):
        sessions = self.agent.list_sessions()
        if not sessions:
            self.console.print("[dim]No saved sessions.[/]")
            return None
        values = []
        for item in sessions[:30]:
            name = item.get("name", "")
            label = (
                f"{name}  "
                f"{item.get('saved_at', '')[:19]}  "
                f"{item.get('messages', 0)} messages"
            )
            values.append((name, label))
        if not self._interactive:
            self._sessions()
            self.console.print("[yellow]Non-interactive terminal: use /session load <name>[/]")
            return None
        try:
            return radiolist_dialog(
                title="Load session",
                text="Use Up/Down to choose a session, Enter to load, Esc to cancel.",
                values=values,
            ).run()
        except Exception as e:
            self.console.print(f"[yellow]Session picker unavailable:[/] [dim]{e}[/]")
            self._sessions()
            return None
    def _handle_history(self, a):
        parts = a.split()
        action = parts[0].lower() if parts else "clear"
        if action != "clear":
            self.console.print("[yellow]Usage: /history clear [--no-archive][/]")
            return True
        archive = "--no-archive" not in parts
        self.agent.clear_history(archive=archive)
        return True
    def _handle_skills(self, a):
        parts = a.split(maxsplit=2)
        action = parts[0].lower() if parts else "list"
        if action in ("list", "ls"):
            skills = discover_skills(self.config.workspace)
            table = Table(title="Skills", box=box.SIMPLE, show_lines=False)
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Description")
            table.add_column("Triggers")
            table.add_column("Size", justify="right")
            table.add_column("Source")
            for skill in skills:
                table.add_row(
                    skill.name,
                    skill.description[:120],
                    ", ".join(skill.triggers[:6]),
                    str(skill.body_chars),
                    str(skill.path),
                )
            self.console.print(table)
            return True
        if action in ("match", "route"):
            query = " ".join(parts[1:]).strip()
            if not query:
                self.console.print("[yellow]Usage: /skills match <query>[/]")
                return True
            matches = rank_skills(query, self.config.workspace)
            if not matches:
                self.console.print("[dim]No skill matched.[/]")
                return True
            table = Table(title="Skill matches", box=box.SIMPLE, show_lines=False)
            table.add_column("Score", justify="right")
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Triggers")
            table.add_column("Source")
            for score, skill in matches:
                table.add_row(
                    str(score),
                    skill.name,
                    ", ".join(skill.triggers[:8]),
                    str(skill.path),
                )
            self.console.print(table)
            return True
        if action == "improve":
            if len(parts) < 3:
                self.console.print("[yellow]Usage: /skills improve <skill> <note>[/]")
                return True
            skill_name = parts[1]
            note = parts[2]
            prompt = (
                "Use the skill-creator workflow to update an existing chatcli skill.\n"
                f"Target skill: {skill_name}\n"
                f"Improvement note: {note}\n\n"
                "Requirements:\n"
                "- First locate the skill by name using the loaded skills list or files under chatcli/skills.\n"
                "- Keep the change concise and reusable; do not add one-off conversation details.\n"
                "- If the note is about reverse engineering, prefer updating reverse-audit.\n"
                "- If the existing skill is too conservative or unclear, tighten the boundary and add clear allowed workflows.\n"
                "- Preserve safety boundaries for real unauthorized targets.\n"
                "- Report the file changed and say TASK COMPLETE when done."
            )
            self.agent.run(prompt)
            self._process_auto_requests()
            return True
        self.console.print("[yellow]Usage: /skills list | match <query> | improve <skill> <note>[/]")
        return True
    def _handle_doctor(self):
        table = Table(title="chatcli doctor", box=box.SIMPLE, show_lines=False)
        table.add_column("Check", style="cyan", no_wrap=True)
        table.add_column("Result")
        provider = self.config.provider
        table.add_row("Python", f"{platform.python_version()} ({Path(sys.executable).name})")
        table.add_row("Platform", platform.platform())
        table.add_row("Interactive", "yes" if self._interactive else "no")
        table.add_row("Workspace", str(Path(self.config.workspace).resolve()))
        table.add_row("State dir", str(Path(self.config.workspace).resolve() / ".chatcli"))
        table.add_row("Provider", f"{provider.provider} / {provider.model}")
        table.add_row("API base", provider.api_base or "(provider default)")
        table.add_row("API key", "set" if provider.api_key else "missing")
        table.add_row("Timeout", f"{getattr(self.config, 'request_timeout', 120)}s")
        table.add_row("Tools", str(len(self.agent.tools.list_tools())))
        skills = discover_skills(self.config.workspace)
        if skills:
            names = ", ".join(skill.name for skill in skills[:6])
            suffix = "" if len(skills) <= 6 else ", ..."
            table.add_row("Skills", f"{len(skills)} ({names}{suffix})")
        else:
            table.add_row("Skills", "0 (missing)")
        table.add_row("Permission mode", self.config.permissions.mode)
        table.add_row("Auto requests", str(self._pending_auto_request_count()))
        table.add_row(
            "Sensitive files",
            "protected" if self.config.permissions.protect_sensitive_files else "not protected",
        )
        context_path = Path(self.config.workspace) / self.config.context_file
        table.add_row("Context file", str(context_path) if context_path.exists() else "(missing)")
        path_hint = "ok"
        python_cmd = shutil.which("python")
        py_cmd = shutil.which("py")
        if os.name == "nt" and (
            "WindowsApps" in sys.executable
            or (python_cmd and "WindowsApps" in python_cmd)
        ):
            path_hint = "python points to WindowsApps; prefer py.exe or fix PATH"
        elif py_cmd:
            path_hint = f"ok (py: {py_cmd})"
        table.add_row("PATH", path_hint)
        self.console.print(table)
        return True
    def _handle_permissions(self, a):
        parts = a.split()
        valid_modes = {"default", "ask", "accept_edits", "dont_ask", "auto"}
        if len(parts) >= 2 and parts[0].lower() == "mode":
            mode = parts[1].lower().replace("-", "_")
            if mode not in valid_modes:
                self.console.print(
                    "[yellow]Usage: /permissions mode "
                    "default|ask|accept_edits|dont_ask|auto[/]"
                )
                return True
            self.config.permissions.mode = mode
            self.agent.permissions.config.mode = mode
            self.agent.auto_approve = mode == "auto"
            self.console.print(f"[green]Permission mode set to {mode} for this session.[/]")
            return True

        perm = self.config.permissions
        self.console.print(f"[cyan]mode[/]: {perm.mode}")
        self.console.print(
            f"[cyan]sensitive protection[/]: "
            f"{'on' if perm.protect_sensitive_files else 'off'}"
        )
        self.console.print(f"[cyan]auto[/]: {', '.join(perm.auto) or '(none)'}")
        self.console.print(f"[cyan]ask[/]: {', '.join(perm.ask) or '(none)'}")
        self.console.print(f"[cyan]deny[/]: {', '.join(perm.deny) or '(none)'}")
        if perm.sensitive:
            self.console.print(f"[cyan]sensitive[/]: {', '.join(perm.sensitive)}")
        return True
    def _sessions(self):
        sessions = self.agent.list_sessions()
        if not sessions:
            self.console.print("[dim]No saved sessions.[/]")
            return True
        for s in sessions[:20]:
            self.console.print(
                f"[cyan]{s['name']}[/] [dim]{s.get('saved_at', '')} "
                f"{s.get('messages', 0)} messages[/]"
            )
        return True
    def _handle_evolve(self, a):
        import shlex; tokens=shlex.split(a) if a else []
        cont=False; target=""; goal=""; skip=0
        for i,t in enumerate(tokens):
            if skip>0: skip-=1; continue
            if t in ("--continuous","-c"): cont=True
            elif t in ("--target","-t") and i+1<len(tokens): target=tokens[i+1]; skip=1
            elif t in ("--goal","-g") and i+1<len(tokens): goal=tokens[i+1]; skip=1
            elif i==0: target=t
        if cont:
            start_continuous(self.config.workspace, focus=target)
            self.console.print(Panel(
                f"[bold cyan]CONTINUOUS EVOLUTION[/]\n"
                f"[dim]Focus: {target or 'general'}[/]\n"
                f"[dim]Ctrl+C to interrupt[/]",
                border_style="cyan",
            ))
            self.agent.run_continuous()
        else:
            state = start_evolve(self.config.workspace, target, goal=goal)
            self.console.print(Panel(
                f"[bold cyan]EVOLUTION MODE[/]\n"
                f"[dim]Target: {target or ''}[/]\n"
                f"[dim]Ctrl+C to interrupt[/]",
                border_style="cyan",
            ))
            self.agent.run(build_evolve_first_prompt(state))
        return True
    def _handle_checkpoint(self, a):
        if not a or a == "list":
            backups = list_backups()
            if not backups:
                self.console.print("[dim]No backups.[/]")
                return True
            for b in backups[:20]:
                self.console.print(f"[cyan]{b.get('id')}[/] [dim]{b.get('file')}[/]")
            return True
        if a.startswith("restore "):
            backup_id = a.split(maxsplit=1)[1]
            ok = restore_backup(backup_id)
            self.console.print("[green]Restored.[/]" if ok else "[yellow]Backup not found.[/]")
            return True
        self.console.print("[yellow]Usage: /checkpoint list | restore <id>[/]")
        return True
    def _handle_memory(self, a):
        if not a or a == "list":
            memories = list_memories(self.config.workspace)
            if not memories:
                self.console.print("[dim]No memories.[/]")
                return True
            for m in memories:
                self.console.print(
                    f"[cyan]{m.get('file')}[/] [dim]{m.get('type', 'note')}[/] "
                    f"{m.get('title', '')}"
                )
            return True
        self.console.print(f"[dim]Memory dir: {_memory_dir(self.config.workspace)}[/]")
        return True
