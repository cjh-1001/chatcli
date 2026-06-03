"""Reverse-analysis REPL commands."""

import shlex
from pathlib import Path
import re

from rich.panel import Panel

from .reverse_prompt import REVERSE_ANALYSIS_PROMPT
from .worklog import init_reverse_analysis_state, record_scope_confirmation, start_task


class ReverseCommandMixin:
    def _resolve_reverse_target(self, token: str) -> Path:
        path = Path(token)
        if not path.is_absolute():
            path = Path(self.config.workspace) / path
        return path

    def _infer_reverse_modes(self, note: str) -> tuple[bool, bool, bool]:
        lowered = note.lower()
        crackme = bool(re.search(
            r"crackme|ctf|flag|serial|password|注册码|注册机|验证|校验|口令|密码|算法|迷宫|maze",
            lowered,
            re.I,
        ))
        patch = bool(re.search(
            r"patch|补丁|爆破|改跳|改分支|绕过|字节|offset|偏移|patched",
            lowered,
            re.I,
        ))
        behavior = bool(re.search(
            r"behavior|dynamic|sandbox|行为|沙箱|运行行为|观测|ioc",
            lowered,
            re.I,
        ))
        if patch:
            crackme = True
        return crackme, patch, behavior

    def _start_reverse_ida_child(
        self,
        target: str,
        crackme: bool,
        patch_requested: bool,
    ) -> str:
        base = f"ida-{Path(target).stem}"
        child_name = self._unique_child_name(base)
        child = self._make_child(child_name)
        # Background reverse jobs cannot answer hidden permission prompts.
        # The parent /reverse command is the user's explicit request to analyze
        # this local target, so approve ask-level tools inside this child only.
        child.agent.auto_approve = True
        task = (
            "[Background IDA reverse-analysis job]\n"
            f"Target: {target}\n"
            f"CTF/crackme focus: {str(crackme).lower()}\n"
            f"Patch audit requested: {str(patch_requested).lower()}\n\n"
            "Run in the child window so the main window can keep auditing.\n"
            "Do not execute the target binary.\n"
            "Workflow:\n"
            "1. Run `binary_inspect` for identity and fast triage.\n"
            "2. Run `ida_analyze` with bounded settings: `auto_wait_timeout=30`, "
            "`include_pseudocode=false` first, and a generous outer timeout.\n"
            "3. If obfuscation is visible, run `ida_deobfuscate` with "
            "`include_pseudocode=false`, `auto_wait_timeout=20`, and "
            "`max_instructions_per_function=5000`.\n"
            "4. Persist concise findings to the child notes file: candidate "
            "functions, strings, imports, suspected flattened/junk regions, "
            "and JSON output paths.\n"
            "5. End with CHILD COMPLETE or CHILD BLOCKED.\n"
        )
        self._run_child_task(child, task)
        self.console.print(
            f"[green]IDA child running[/] [cyan]{child.name}[/] "
            f"[dim]use /child show {child.name}[/]"
        )
        return child.name
    def _handle_reverse(self, a):
        try:
            tokens = [t.strip("\"'") for t in shlex.split(a or "", posix=False)]
        except ValueError as e:
            self.console.print(f"[yellow]Invalid arguments:[/] [dim]{e}[/]")
            return True
        use_ida = True
        behavior = False
        crackme = False
        patch_requested = False
        free_parts = []
        for token in tokens:
            lowered = token.lower()
            if lowered in ("--ida", "-i"):
                use_ida = True
            elif lowered == "--no-ida":
                use_ida = False
            elif lowered in ("--behavior", "--dynamic"):
                behavior = True
            elif lowered == "--crackme":
                crackme = True
            elif lowered in ("--patch", "--patch-audit"):
                patch_requested = True
                crackme = True
            else:
                free_parts.append(token)
        if not free_parts:
            self.console.print("[yellow]Usage: /reverse <exe> [optional goal or flags][/] [dim]flags: --no-ida --crackme --patch --behavior[/]")
            return True

        target_index = 0
        for idx, part in enumerate(free_parts):
            if self._resolve_reverse_target(part).exists():
                target_index = idx
                break
        raw_target = free_parts[target_index]
        request_note = " ".join(
            part for idx, part in enumerate(free_parts) if idx != target_index
        ).strip() or "(infer from binary evidence)"
        inferred_crackme, inferred_patch, inferred_behavior = self._infer_reverse_modes(request_note)
        crackme = crackme or inferred_crackme
        patch_requested = patch_requested or inferred_patch
        behavior = behavior or inferred_behavior
        if patch_requested:
            crackme = True
        target_path = self._resolve_reverse_target(raw_target)
        target = str(target_path)

        task_kind = "Binary patch audit" if patch_requested else "Reverse analysis"
        start_task(self.config.workspace, f"{task_kind}: {target}")
        mode = "IDA static analysis" if use_ida else "static binary triage"
        if crackme:
            mode += " + CTF/crackme focus"
        if patch_requested:
            mode += " + patch audit"
        if behavior:
            mode += " + behavior plan"
        init_reverse_analysis_state(self.config.workspace, target, mode)
        record_scope_confirmation(
            self.config.workspace,
            f"User invoked /reverse for local target {target}; static reverse analysis is authorized for this target.",
        )
        background_ida_child = "(none)"
        main_use_ida = use_ida
        if use_ida:
            background_ida_child = self._start_reverse_ida_child(
                target,
                crackme=crackme,
                patch_requested=patch_requested,
            )
            main_use_ida = False
            mode += f" + background IDA child {background_ida_child}"
        self.console.print(Panel(
            "[bold magenta]REVERSE ANALYSIS[/]\n"
            f"[dim]Target: {target}[/]\n"
            f"[dim]Mode: {mode}[/]\n"
            "[dim]The target binary will not be executed.[/]",
            border_style="magenta", padding=(0,1)
        ))
        self._run_work_loop(REVERSE_ANALYSIS_PROMPT.format(
            target=target,
            use_ida=str(main_use_ida).lower(),
            background_ida_child=background_ida_child,
            behavior=str(behavior).lower(),
            crackme=str(crackme).lower(),
            patch_requested=str(patch_requested).lower(),
            request_note=request_note,
        ), allow_pauses=False, max_cycles=max(60, self._max_work_cycles()))
        return True

