"""Work-mode, smart-task, and audit REPL commands."""

from pathlib import Path
import re

from rich.panel import Panel

from .work_prompts import (
    MALWARE_CONTINUE_PROMPT,
    MALWARE_TRIAGE_PROMPT,
    SECURITY_AUDIT_PROMPT,
    WORK_CONTINUE_PROMPT,
    WORK_IMPLEMENT_PROMPT,
    WORK_PLAN_PROMPT,
    WORK_PROMPT,
)
from .worklog import (
    export_html_report,
    get_task_status,
    log_milestone,
    mark_task_done,
    record_scope_confirmation,
    start_task,
)

SMART_WORK_PANEL = """[bold green]SMART WORK[/]
[dim]Detected an implementation task. Starting autonomous work.[/]
[dim]Use /work status to inspect progress.[/]"""

USER_CHOICE_MARKER = "USER CHOICE REQUIRED"
PLAN_READY_MARKER = "PLAN READY"
TASK_COMPLETE_MARKER = "TASK COMPLETE"
PHASE_COMPLETE_MARKER = "PHASE COMPLETE"


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
        self._malware_review_done = False  # require self-review before completion
        # Clean orphans from previous tasks to avoid context pollution
        cleaned = self._cleanup_orphans(task_id)
        running = self._running_child_count()
        if cleaned or running:
            self.console.print(
                f"[dim]children: {running} running, {cleaned} stale cleaned[/]"
            )
        self.console.print(Panel(
            "[bold magenta]MALWARE TRIAGE[/]\n"
            f"[dim]Scope: {ui}[/]\n"
            "[dim]Static defensive analysis; unknown samples will not be executed.[/]",
            border_style="magenta", padding=(0,1)
        ))
        self._run_work_loop(MALWARE_TRIAGE_PROMPT, allow_pauses=True, max_cycles=self._max_work_cycles())
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
    def _stringify_completion_fragment(self, value, parts: list[str], limit: int = 200000) -> None:
        if sum(len(part) for part in parts) >= limit:
            return
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for key in ("content", "tool_calls", "function", "arguments", "input", "text"):
                if key in value:
                    self._stringify_completion_fragment(value[key], parts, limit)
        elif isinstance(value, list):
            for item in value:
                self._stringify_completion_fragment(item, parts, limit)

    def _recent_assistant_tool_text(self, history_start: int | None) -> str:
        if history_start is None:
            return ""
        parts: list[str] = []
        for message in self.agent._history[history_start:]:
            role = str(message.get("role", "")).lower() if isinstance(message, dict) else ""
            if role == "user":
                continue
            self._stringify_completion_fragment(message, parts)
        return "\n".join(parts)

    def _assistant_text_from_message(self, message: dict) -> str:
        if not isinstance(message, dict):
            return ""
        if str(message.get("role", "")).lower() != "assistant":
            return ""
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
            return "\n".join(part for part in parts if part)
        return ""

    def _recent_final_assistant_text(self, history_start: int | None) -> str:
        if history_start is None:
            return ""
        for message in reversed(self.agent._history[history_start:]):
            text = self._assistant_text_from_message(message)
            if text and self._has_completion_signal(text):
                return text
        return ""

    def _is_malware_task(self) -> bool:
        status = get_task_status(self.config.workspace)
        if not status:
            return False
        first_line = (status.get("content") or "").splitlines()[0:1]
        return bool(first_line and first_line[0].lower().startswith("# task: malware triage:"))

    def _completion_report_text(self, result: str, history_start: int | None) -> str:
        if result and self._has_completion_signal(result):
            return result
        recent = self._recent_final_assistant_text(history_start)
        if recent:
            return recent
        return result or ""

    def _extract_sample_name(self) -> str:
        """Extract a readable sample name from the current malware task."""
        status = get_task_status(self.config.workspace) or {}
        content = status.get("content", "")
        if not content:
            return ""
        first_line = content.splitlines()[0] if content.splitlines() else ""
        # First line format: "# Task: Malware triage: <user_input>"
        prefix = "malware triage:"
        lower_first = first_line.lower()
        if prefix not in lower_first:
            return ""
        rest = first_line[lower_first.index(prefix) + len(prefix):].strip()
        if not rest:
            return ""
        # Prefer a filename with common sample extension
        m = re.search(
            r"([^/\s]+\.(?:exe|dll|sys|msi|bin|dat|elf|apk|jar|dex|scr|com|bat|"
            r"cmd|ps1|vbs|js|wsf|hta|docm|xlsm|pptm|pdf|zip|rar|7z|tar|gz|cab|"
            r"iso|img|dmp|raw|sct|lnk|tmp|swf))",
            rest,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)
        # Fallback: take the first whitespace-delimited token
        name = rest.split()[0] if rest.split() else rest
        return name[:100]

    def _extract_sample_dir(self) -> str:
        """Extract the directory containing the sample from the task description.

        Returns the sample's parent directory if a full path was given,
        otherwise falls back to the workspace root.
        """
        status = get_task_status(self.config.workspace) or {}
        content = status.get("content", "")
        if not content:
            return str(Path(self.config.workspace))
        first_line = content.splitlines()[0] if content.splitlines() else ""
        prefix = "malware triage:"
        lower_first = first_line.lower()
        if prefix not in lower_first:
            return str(Path(self.config.workspace))
        rest = first_line[lower_first.index(prefix) + len(prefix):].strip()
        # Try to extract a full path (Windows or Unix style)
        m = re.search(
            r"([A-Za-z]:[/\\][^\s]*?[/\\])?"  # Windows drive:\path\
            r"([^\s]*?[/\\])"                   # any path/
            r"[^/\s]+\.(?:exe|dll|sys|msi|bin|dat|elf|apk|jar|dex|scr|com|bat|"
            r"cmd|ps1|vbs|js|wsf|hta|docm|xlsm|pptm|pdf|zip|rar|7z|tar|gz|cab|"
            r"iso|img|dmp|raw|sct|lnk|tmp|swf)",
            rest,
            re.IGNORECASE,
        )
        if m:
            # Reconstruct the directory path from the match
            full_path = m.group(0)
            parent = str(Path(full_path).parent.resolve())
            if parent and Path(parent).exists():
                return parent
        return str(Path(self.config.workspace))

    def _collect_child_results(self) -> str:
        """Collect completed child-window results for injection into main context.

        Returns a compact summary of all completed children that the main
        agent should incorporate before finalizing its report.
        """
        with self._children_lock:
            children = list(self.children.values())
        if not children:
            return ""
        active_task_id = self._current_task_id().strip()
        relevant = [
            c for c in children
            if c.status in ("done", "blocked", "error")
            and (not active_task_id or c.task_id == active_task_id)
        ]
        if not relevant:
            return ""
        parts = ["[Child window results — incorporate before TASK COMPLETE]"]
        for child in relevant:
            status_label = {"done": "✓", "blocked": "⊘", "error": "✗"}.get(child.status, child.status)
            parts.append(f"\n## Child: {child.name} [{status_label}]")
            parts.append(f"Task: {child.task}")
            if child.summary:
                parts.append(f"Summary: {child.summary}")
            if child.result:
                # Include the last 800 chars of the result for context
                result_tail = child.result.strip()
                if len(result_tail) > 800:
                    result_tail = "…" + result_tail[-800:]
                parts.append(f"Result:\n{result_tail}")
            if child.error:
                parts.append(f"Error: {child.error}")
            notes_path = getattr(child, "notes_path", "") or str(
                Path(self.config.workspace) / ".chatcli" / "children" / f"{child.name}.md"
            )
            parts.append(f"Full record: {notes_path}")
        parts.append(
            "\nRead the child record files if you need full details. "
            "Merge all completed child findings into the main report before "
            "saying TASK COMPLETE."
        )
        return "\n".join(parts)

    def _maybe_export_malware_report(self, result: str, history_start: int | None) -> None:
        if not self._is_malware_task():
            return
        status = get_task_status(self.config.workspace) or {}
        report = self._completion_report_text(result, history_start).strip()
        if not report:
            return
        task_id = str(status.get("task_id") or "").strip()
        sample_name = self._extract_sample_name()
        sample_dir = self._extract_sample_dir()
        try:
            path = export_html_report(
                self.config.workspace,
                task_id,
                "恶意样本静态分析报告",
                report,
                sample_name=sample_name,
                sample_dir=sample_dir,
            )
            log_milestone(self.config.workspace, f"HTML report exported: {path}")
            self.console.print(f"[green]report[/] [dim]{path}[/]")
        except Exception as e:
            self.console.print(f"[yellow]report export failed:[/] [dim]{e}[/]")

    def _looks_like_final_triage_report(self, text: str) -> bool:
        lowered = (text or "").lower()
        # Require both "ioc" (English or Chinese context) and a minimum
        # number of report section indicators to avoid false positives
        # on partial outputs or tool results that happen to mention IOCs.
        has_ioc_signal = (
            "ioc" in lowered
            or "威胁指标" in text
            or "网络指标" in text
        )
        if not has_ioc_signal:
            return False
        hints = (
            # Chinese section headers
            "样本身份", "静态能力", "配置提取", "检测规则", "沙箱观察",
            "文件哈希", "关键字符串", "网络 ioc", "主机 ioc",
            "后续分析建议", "分析限制", "攻击行为链", "影响评估",
            "检测与处置", "处置建议", "覆盖清单", "行为覆盖",
            # English section markers
            "sha256", "sha-256", "md5",
            "conclusion", "recommendations", "limitations",
            "attack chain", "coverage", "key capabilities",
            # Report structure markers
            "executive summary", "摘要", "结论", "总结",
            "yara", "sigma", "edr hunting", "sandbox",
            # Confidence/verdict markers
            "verdict", "判定", "置信度", "confidence",
        )
        return sum(1 for hint in hints if hint in lowered) >= 6

    def _report_missing_network_iocs(self, text: str) -> bool:
        """Return True if a malware report lacks network IOC coverage.

        The report should either contain IPs/domains/URLs OR explicitly state
        that no network IOCs were found. A report that just omits network
        indicators is likely incomplete.
        """
        lowered = (text or "").lower()
        # Explicitly states no network IOCs found — acceptable
        if re.search(
            r"(未发现|没有|无|no|未提取到|暂无)\s*(网络|network|C2\s*(IP|地址|通信|连接)|域名|domain|IOC|IP\s*(地址|信息))",
            lowered,
        ):
            return False
        # Has IPv4 pattern
        if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            return False
        # Has domain-like pattern
        if re.search(r"\b[a-z0-9][a-z0-9.-]{1,200}\.[a-z]{2,20}\b", lowered):
            return False
        # Has URL pattern
        if re.search(r"https?://", lowered):
            return False
        return True

    def _has_completion_signal(self, text: str) -> bool:
        if TASK_COMPLETE_MARKER in (text or "").upper():
            return True
        return self._looks_like_final_triage_report(text or "")

    def _is_work_complete(self, result: str, history_start: int | None = None) -> bool:
        if self._has_completion_signal(result or ""):
            # Don't accept completion if children are still running for this task
            task_id = self._current_task_id()
            running_children = [
                c for c in self.children.values()
                if c.status == "running"
                and task_id and c.task_id == task_id
            ]
            if not running_children:
                mark_task_done(self.config.workspace)
                return True
            # Children still running — tell the model to wait or read them
            return False
        if self._has_completion_signal(self._recent_assistant_tool_text(history_start)):
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
    def _needs_phase_pause(self, result: str) -> bool:
        return PHASE_COMPLETE_MARKER in (result or "").upper()
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
            f"[Cycle {cycle}]\n"
            "- Check child summaries + task.md for what changed; don't repeat done work.\n"
            "- Prefer cached JSON paths, child records, and existing tool outputs over re-running.\n"
            "- One concrete action per cycle: extract, classify, validate, or write. End with next step."
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
        # Auto-approve tools during automated work modes — the user
        # explicitly started this task and shouldn't need to press
        # Enter for every tool call.
        saved_auto_approve = self.agent.auto_approve
        self.agent.auto_approve = True
        try:
            return self._run_work_loop_inner(first_prompt, allow_pauses, max_cycles)
        finally:
            self.agent.auto_approve = saved_auto_approve

    def _run_work_loop_inner(
        self,
        first_prompt: str,
        allow_pauses: bool,
        max_cycles: int,
    ):
        prompt = first_prompt
        pending_compression_events: list[dict] = []
        task_id = self._current_task_id()
        self._set_agent_task_scope(task_id)
        loop_error = None
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
            history_start = len(self.agent._history)
            try:
                result = self.agent.run(effective_prompt)
            except Exception as e:
                import traceback
                self.console.print(
                    f"[red]Work loop error (cycle {cycle}/{max_cycles}):[/] "
                    f"{type(e).__name__}: {e}"
                )
                self.console.print(f"[dim]{traceback.format_exc()}[/]")
                loop_error = e
                break
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
            if self._is_work_complete(result, history_start):
                # For malware tasks: require a self-review round before
                # accepting completion. The model should check its own
                # report for gaps, weak evidence, and unextracted artifacts
                # before truly finishing.
                if self._is_malware_task() and not self._malware_review_done:
                    self._malware_review_done = True
                    # Collect completed child results for the review
                    child_results = self._collect_child_results()
                    child_section = ""
                    if child_results:
                        self.console.print(
                            "[yellow]self-review[/] "
                            f"[dim]{sum(1 for c in self.children.values() if c.status in ('done','blocked','error'))} children done, checking gaps...[/]"
                        )
                        child_section = (
                            "\n\n**Child window results**:\n"
                            + child_results
                            + "\n\nRead child record files with read_file for full details. "
                            "Incorporate child findings into the report now.\n"
                        )
                    else:
                        self.console.print(
                            "[yellow]self-review[/] "
                            "[dim]checking report for gaps before finish...[/]"
                        )
                    prompt = (
                        "[Self-review — Quality Gate]\n"
                        "You said TASK COMPLETE. Before finishing, run this checklist "
                        "and fix any gaps:\n\n"
                        "□ Unextracted: any undecoded strings/XOR/configs/IPs remaining?\n"
                        "□ Weak evidence: any claim with only 1 import/generic string?\n"
                        "□ IOC quality: `ioc_quality_classifier` run on all IOCs?\n"
                        "□ Detection lint: `detection_rule_lint` run on YARA/Sigma?\n"
                        "□ Claim validation: `behavior_claim_validator` run?\n"
                        "□ Coverage: `behavior_coverage_matrix` run? 'not_observed' families resolvable?\n"
                        "□ External tools: capa/FLOSS/DIE output fully incorporated?\n"
                        "□ Children: all completed child records read and merged?\n"
                        + (
                            "\n**Completed child results**:\n" + child_results + "\n"
                            if child_results else ""
                        ) +
                        "\nIf you find gaps: take concrete tool actions to fill them "
                        "now. If every item is checked and the report is truly complete, "
                        "say TASK COMPLETE with a brief confirmation.\n"
                    )
                    continue
                self._maybe_export_malware_report(result, history_start)
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
            if self._is_malware_task() and self._needs_phase_pause(result):
                if allow_pauses:
                    self.console.print(
                        f"[yellow]phase complete[/] [dim]{self._format_work_progress()} - /work continue[/]"
                    )
                    return
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
            # Build continue prompt with child awareness for malware tasks
            if self._is_malware_task():
                running = [
                    c for c in self.children.values()
                    if c.status == "running"
                    and (not task_id or c.task_id == task_id)
                ]
                completed_unreviewed = [
                    c for c in self.children.values()
                    if c.status in ("done", "blocked")
                    and (not task_id or c.task_id == task_id)
                ]
                # Use the malware-specific continue prompt for faster iteration
                base = MALWARE_CONTINUE_PROMPT
                extra_parts = []
                if running:
                    names = ", ".join(c.name for c in running[:5])
                    extra_parts.append(
                        f"[Children running: {names} — do NOT duplicate their work]"
                    )
                if completed_unreviewed:
                    names = ", ".join(
                        f"{c.name} ({c.status})" for c in completed_unreviewed[:5]
                    )
                    extra_parts.append(
                        f"[Children completed: {names} — read their records with read_file]"
                    )
                if extra_parts:
                    prompt = base.rstrip() + "\n\n" + "\n".join(extra_parts)
                else:
                    prompt = base
            else:
                prompt = WORK_CONTINUE_PROMPT
        if loop_error:
            self.console.print(
                f"[red]Aborted[/] [dim]after error in cycle {max_cycles} | "
                f"{self._format_work_progress()}[/]"
            )
        else:
            self.console.print(
                f"[yellow]paused[/] [dim]{max_cycles} cycles | "
                f"{self._format_work_progress()} | /work continue[/]"
            )
