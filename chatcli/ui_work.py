"""Work-mode, smart-task, and audit REPL commands."""

from pathlib import Path
import re

from rich.panel import Panel

from .worklog import (
    WORK_CONTINUE_PROMPT,
    WORK_IMPLEMENT_PROMPT,
    WORK_PLAN_PROMPT,
    WORK_PROMPT,
    MALWARE_TRIAGE_PROMPT,
    SECURITY_AUDIT_PROMPT,
    get_task_status,
    mark_task_done,
    record_scope_confirmation,
    start_task,
)

SMART_WORK_PANEL = """[bold green]SMART WORK[/]
[dim]Detected an implementation task. Starting autonomous work.[/]
[dim]Use /work status to inspect progress.[/]"""

USER_CHOICE_MARKER = "USER CHOICE REQUIRED"
PLAN_READY_MARKER = "PLAN READY"


ACTION_PATTERNS = [
    r"\bfix\b", r"\bimplement\b", r"\badd\b", r"\bcreate\b",
    r"\bbuild\b", r"\bupdate\b", r"\bchange\b", r"\bmodify\b",
    r"\brefactor\b", r"\bdebug\b", r"\btest\b", r"\brun\b",
    r"\binstall\b", r"\bwrite\b", r"\bgenerate\b", r"\brepair\b",
    r"\bimprove\b", r"\bmake\b",
    r"修", r"实现", r"添加", r"新增", r"修改", r"优化", r"重构",
    r"创建", r"生成", r"写", r"运行", r"测试", r"安装", r"完善",
    r"接入", r"集成", r"删除", r"调整", r"改成", r"执行", r"处理",
    r"完成", r"开发", r"升级", r"支持", r"继续", r"做", r"弄",
]

SECURITY_AUDIT_PATTERNS = [
    r"代码审计", r"安全审计", r"审计", r"漏洞", r"信息泄露",
    r"敏感信息", r"反编译", r"小程序", r"微信", r"cms",
    r"sql注入", r"xss", r"rce", r"ssrf", r"越权", r"任意文件",
    r"\bsecurity audit\b", r"\bvulnerability\b", r"\bvuln\b",
    r"\bsecret leak\b", r"\bcode audit\b", r"\bcms\b",
]

MALWARE_TRIAGE_PATTERNS = [
    r"恶意样本", r"攻击样本", r"样本分析", r"木马", r"病毒", r"后门",
    r"恶意文件", r"威胁分析", r"行为分析", r"沙箱", r"家族分析",
    r"\bmalware\b", r"\bmalicious\b", r"\bsuspicious (binary|file|sample)\b",
    r"\bsample triage\b", r"\bioc\b", r"\biocs\b", r"\byara\b",
    r"\bsigma\b", r"\bsandbox\b", r"\bcapa\b", r"\bfloss\b",
    r"\bconfig extraction\b", r"\bc2\b", r"\bransomware\b",
    r"\bstealer\b", r"\bloader\b", r"\bdropper\b", r"\bbackdoor\b",
]

QUESTION_PREFIXES = (
    "why", "what", "how", "explain", "tell me", "show me",
    "为什么", "是什么", "怎么", "如何", "解释", "讲讲",
)

DELEGATION_PREFIXES = (
    "please ", "can you ", "could you ", "帮我", "给我", "请", "麻烦",
    "能不能帮我", "可以帮我",
)


class WorkCommandMixin:
    def _set_agent_task_scope(self, task_id: str = "") -> None:
        self.agent._chatcli_task_id = str(task_id or "").strip()
        self.agent._chatcli_agent_role = "main"
        self.agent._chatcli_child_name = ""
    def _handle_smart_input(self, ui: str):
        if self._awaiting_work_choice:
            was_scope_confirmation = self._awaiting_scope_confirmation
            self._awaiting_work_choice = False
            self._awaiting_scope_confirmation = False
            if was_scope_confirmation:
                record_scope_confirmation(self.config.workspace, ui)
            scope_note = (
                "[Scope confirmation has been recorded in .chatcli/task.md. "
                "Do not ask again for the same target and validation boundary; "
                "ask again only if scope changes.]\n\n"
                if was_scope_confirmation else ""
            )
            prompt = (
                "[User choice for the active task]\n"
                f"{ui}\n\n"
                f"{scope_note}"
                f"{WORK_IMPLEMENT_PROMPT}"
            )
            self._run_work_loop(prompt)
            return
        if self._has_active_work() and self._looks_like_work_followup(ui):
            prompt = (
                "[User follow-up for the active task]\n"
                f"{ui}\n\n"
                f"{WORK_IMPLEMENT_PROMPT}"
            )
            self._run_work_loop(prompt)
            return
        if self._should_start_security_audit(ui):
            self._start_security_audit(ui)
            return
        if self._should_start_malware_triage(ui):
            self._start_malware_triage(ui)
            return
        if self._should_start_smart_work(ui):
            self._start_smart_work(ui)
            return
        self._set_agent_task_scope("")
        self.agent.run(ui)
        self._process_auto_requests()
    def _should_start_security_audit(self, ui: str) -> bool:
        lowered = ui.strip().lower()
        if not lowered:
            return False
        return any(re.search(p, lowered, re.IGNORECASE) for p in SECURITY_AUDIT_PATTERNS)
    def _start_security_audit(self, ui: str):
        task_id = start_task(self.config.workspace, f"Security audit: {ui}")
        self._set_agent_task_scope(task_id)
        self.console.print(Panel(
            "[bold magenta]SECURITY AUDIT / LAB ANALYSIS[/]\n"
            f"[dim]Scope: {ui}[/]\n"
            "[dim]Authorized audit or CTF/lab analysis; output will be evidence-based.[/]",
            border_style="magenta", padding=(0,1)
        ))
        self._run_work_loop(SECURITY_AUDIT_PROMPT)
    def _should_start_malware_triage(self, ui: str) -> bool:
        lowered = ui.strip().lower()
        if not lowered:
            return False
        if re.search(r"\b(skill|skills|prompt|route|routing)\b|能力|功能|触发|路由", lowered, re.IGNORECASE):
            if any(re.search(p, lowered, re.IGNORECASE) for p in ACTION_PATTERNS):
                return False
        return any(re.search(p, lowered, re.IGNORECASE) for p in MALWARE_TRIAGE_PATTERNS)
    def _start_malware_triage(self, ui: str):
        task_id = start_task(self.config.workspace, f"Malware triage: {ui}")
        self._set_agent_task_scope(task_id)
        self.console.print(Panel(
            "[bold magenta]MALWARE TRIAGE[/]\n"
            f"[dim]Scope: {ui}[/]\n"
            "[dim]Static defensive analysis; unknown samples will not be executed.[/]",
            border_style="magenta", padding=(0,1)
        ))
        self._run_work_loop(MALWARE_TRIAGE_PROMPT, allow_pauses=False, max_cycles=max(60, self._max_work_cycles()))
    def _handle_malware(self, a: str):
        scope = a.strip() if a else "current workspace"
        self._start_malware_triage(scope)
        return True
    def _continue_active_work(self, note: str = "continue"):
        tf = Path(self.config.workspace) / ".chatcli" / "task.md"
        if not tf.exists():
            self.console.print("[yellow]No active work task.[/]")
            return True
        if self._awaiting_work_choice:
            self._handle_smart_input(note)
            return True
        self._run_work_loop(WORK_CONTINUE_PROMPT)
        return True
    def _show_active_status(self):
        status = get_task_status(self.config.workspace)
        if not status:
            self.console.print("[dim]No active work task.[/]")
            return True
        done = status.get("done", 0)
        total = status.get("total", 0)
        self.console.print(
            f"[cyan]{status.get('status', 'unknown')}[/] "
            f"[dim]{done}/{total} subtasks done[/]"
        )
        if status.get("subtasks"):
            for item in status["subtasks"][:20]:
                mark = "x" if item.get("done") else " "
                self.console.print(f"[dim]- [{mark}] {item.get('text', '')}[/]")
        return True
    def _has_active_work(self) -> bool:
        status = get_task_status(self.config.workspace)
        if not status:
            return False
        return str(status.get("status", "")).strip().lower() == "in_progress"
    def _looks_like_work_followup(self, ui: str) -> bool:
        lowered = ui.strip().lower()
        if lowered in ("continue", "go on", "keep going", "resume", "继续", "接着", "接着做"):
            return True
        prefixes = (
            "choose ", "use ", "option ", "方案", "选择", "选", "用",
            "按", "采用", "继续", "接着",
        )
        return lowered.startswith(prefixes)
    def _should_start_smart_work(self, ui: str) -> bool:
        if not getattr(self.config, "smart_work", True):
            return False
        text = ui.strip()
        if not text:
            return False
        lowered = text.lower()
        has_action = any(re.search(p, lowered, re.IGNORECASE) for p in ACTION_PATTERNS)
        if not has_action:
            return False
        if lowered.startswith(DELEGATION_PREFIXES):
            return True
        question_like = lowered.startswith(QUESTION_PREFIXES) or lowered.endswith(("?", "？"))
        if question_like and len(text) < 30:
            return False
        return True
    def _start_smart_work(self, ui: str):
        task_id = start_task(self.config.workspace, ui)
        self._set_agent_task_scope(task_id)
        self.console.print(Panel(
            f"{SMART_WORK_PANEL}\n"
            f"[dim]Task: {ui}[/]\n"
            f"[dim]Autonomous loop: up to {self._max_work_cycles()} cycles[/]",
            border_style="green", padding=(0,1)
        ))
        self._run_work_loop(self._initial_work_prompt())
    def _handle_audit(self, a):
        scope = a.strip() if a else "current workspace"
        self._start_security_audit(scope)
        return True
    def _handle_work(self, a):
        if a=="status":
            return self._show_active_status()
        if a=="continue":
            return self._continue_active_work("continue")
        if a=="done":
            mark_task_done(self.config.workspace)
            self._set_agent_task_scope("")
            return True
        if a:
            task_id = start_task(self.config.workspace, a)
            self._set_agent_task_scope(task_id)
            self.console.print(Panel(
                f"[bold green]WORK MODE[/]\n"
                f"[dim]Task: {a}[/]\n"
                f"[dim]Autonomous loop: up to {self._max_work_cycles()} cycles[/]",
                border_style="green", padding=(0,1)
            ))
            self._run_work_loop(self._initial_work_prompt())
            return True
        return self._continue_active_work("continue")
    def _initial_work_prompt(self):
        if getattr(self.config, "confirm_plan", True):
            return WORK_PLAN_PROMPT
        return WORK_PROMPT
    def _max_work_cycles(self):
        return max(1, int(getattr(self.config, "max_work_cycles", 20)))
    def _is_work_complete(self, result: str) -> bool:
        if "TASK COMPLETE" in (result or "").upper():
            mark_task_done(self.config.workspace)
            return True
        status = get_task_status(self.config.workspace)
        if not status:
            return True
        state = str(status.get("status", "")).strip().lower()
        if state in ("done", "complete", "completed"):
            return True
        total = int(status.get("total", 0) or 0)
        done = int(status.get("done", 0) or 0)
        if total > 0 and done >= total:
            mark_task_done(self.config.workspace)
            return True
        return False
    def _needs_user_choice(self, result: str) -> bool:
        return USER_CHOICE_MARKER in (result or "").upper()
    def _is_scope_confirmation_request(self, result: str) -> bool:
        text = (result or "").lower()
        return (
            "authorized ctf/lab/owned target" in text
            or "authorization/scope" in text
            or "scope boundaries" in text
            or "exploit validation is in scope" in text
        )
    def _needs_plan_confirmation(self, result: str) -> bool:
        return PLAN_READY_MARKER in (result or "").upper()
    def _format_work_progress(self) -> str:
        status = get_task_status(self.config.workspace) or {}
        state = status.get("status", "unknown")
        total = int(status.get("total", 0) or 0)
        done = int(status.get("done", 0) or 0)
        if total:
            return f"{state} {done}/{total}"
        return f"{state}"
    def _work_cycle_guidance(self, cycle: int) -> str:
        return (
            "[Work-cycle planning rule]\n"
            f"Cycle: {cycle}\n"
            "- Begin by checking what changed since the previous cycle: task state, worklog, "
            "tool outputs, cached JSON paths, and child-window summaries.\n"
            "- Update `.chatcli/task.md` when the current evidence changes the plan. Keep a "
            "short next-step queue instead of restarting broad analysis.\n"
            "- Prefer existing artifacts first: cached IDA JSON, partial IDA checkpoints, "
            "reverse_evidence_map summaries, child records, and verified offsets.\n"
            "- If a slow IDA/deobfuscation job is running or timed out with partial results, "
            "continue main-window work from lightweight triage and the partial evidence; "
            "delegate only specific functions/ranges to child windows.\n"
            "- End the cycle with a concrete state: completed phase, updated blocker, "
            "spawned child task, or next targeted tool call. Do not repeat completed work."
        )
    def _print_work_cycle_header(self, cycle: int, max_cycles: int) -> None:
        self.console.print(
            f"[cyan]work[/] [dim]{cycle}/{max_cycles} {self._format_work_progress()}[/]"
        )
    def _run_work_loop(
        self,
        first_prompt: str,
        allow_pauses: bool = True,
        max_cycles: int | None = None,
    ):
        max_cycles = max_cycles or self._max_work_cycles()
        prompt = first_prompt
        pending_compression_events: list[dict] = []
        task_id = self._current_task_id()
        self._set_agent_task_scope(task_id)
        for cycle in range(1, max_cycles + 1):
            self._print_work_cycle_header(cycle, max_cycles)
            effective_prompt = prompt
            compression_context = self._compression_context(pending_compression_events)
            task_id = self._current_task_id()
            self._set_agent_task_scope(task_id)
            child_context = self._child_context_summary(task_id=task_id)
            cycle_guidance = self._work_cycle_guidance(cycle)
            context_parts = [
                part for part in (cycle_guidance, compression_context, child_context) if part
            ]
            if context_parts:
                effective_prompt = effective_prompt.rstrip() + "\n\n" + "\n\n".join(context_parts)
            result = self.agent.run(effective_prompt)
            pending_compression_events = self.agent.pop_compression_events()
            self._process_auto_requests(expected_task_id=task_id)
            if self._needs_plan_confirmation(result):
                if allow_pauses:
                    self._awaiting_work_choice = True
                    self.console.print(
                        f"[yellow]plan ready[/] [dim]{self._format_work_progress()} - reply to continue[/]"
                    )
                    return
                prompt = (
                    "[Reverse mode continuation]\n"
                    "The previous response reached a plan checkpoint. The user has "
                    "already authorized this local reverse-analysis task. Continue "
                    "with the next static-analysis step without waiting for approval. "
                    "Do not execute the target binary and do not patch unless patch "
                    "audit evidence is already strong.\n\n"
                    f"{WORK_CONTINUE_PROMPT}"
                )
                continue
            if self._is_work_complete(result):
                self._set_agent_task_scope("")
                self.console.print(
                    f"[green]done[/] [dim]{self._format_work_progress()}[/]"
                )
                return
            if self._needs_user_choice(result):
                if allow_pauses:
                    self._awaiting_work_choice = True
                    self._awaiting_scope_confirmation = self._is_scope_confirmation_request(result)
                    self.console.print(
                        f"[yellow]waiting[/] [dim]{self._format_work_progress()} - reply to continue[/]"
                    )
                    return
                prompt = (
                    "[Reverse mode continuation]\n"
                    "The previous response requested user choice. For this `/reverse` "
                    "local target, scope is already recorded. Choose the conservative "
                    "static-analysis path yourself, defer optional destructive actions, "
                    "and continue until a useful evidence-based report or real blocker "
                    "is reached.\n\n"
                    f"{WORK_CONTINUE_PROMPT}"
                )
                continue
            if cycle >= max_cycles:
                break
            status = get_task_status(self.config.workspace) or {}
            total = int(status.get("total", 0) or 0)
            done = int(status.get("done", 0) or 0)
            remaining = (total - done) if total else "unknown"
            usage = self.agent.get_usage_summary()
            self.console.print(
                f"[dim]continue {cycle}/{max_cycles} | remaining {remaining} | {usage}[/]"
            )
            prompt = WORK_CONTINUE_PROMPT
        self.console.print(
            f"[yellow]paused[/] [dim]{max_cycles} cycles | {self._format_work_progress()} | /work continue[/]"
        )

