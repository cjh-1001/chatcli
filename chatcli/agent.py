"""Core agent loop — think → act → observe cycle."""

import time
from rich.console import Console
from rich.panel import Panel

from .config import Config
from .tools import create_registry
from .providers import create_provider
from .permissions import PermissionManager
from .context import build_system_prompt
from .agent_compression import CompressionMixin
from .agent_session import AgentSessionMixin
from .agent_tools import AgentToolMixin
from .agent_output import AgentOutputMixin


class Agent(AgentSessionMixin, CompressionMixin, AgentToolMixin, AgentOutputMixin):
    def __init__(self, config: Config):
        self.config = config
        self.console = Console()
        self.tools = create_registry(config)
        self.provider = create_provider(config)
        self.permissions = PermissionManager(config.permissions)
        self.workspace = config.workspace
        self._history: list[dict] = []
        self.auto_approve = (
            str(getattr(config.permissions, "mode", "default")).lower().replace("-", "_")
            == "auto"
        )
        self.debug = False
        self._total_tokens = {"input": 0, "output": 0}
        self._total_time = 0.0
        self._tool_calls_total = 0
        self._session_name: str | None = None
        self._chatcli_task_id = ""
        self._chatcli_agent_role = "main"
        self._chatcli_child_name = ""
        self._text_buffer = ""  # for paragraph-level output buffering
        self._stream_open_line = False
        self._last_autosave_error: str | None = None
        self._compression_events: list[dict] = []
        self._init_system_prompt()
        # Crash detection: mark session as running
        from .checkpoint import mark_running
        mark_running(self.workspace)

    def _init_system_prompt(self):
        system_prompt = build_system_prompt(self.workspace, self.config.context_file)
        self._history = [{"role": "system", "content": system_prompt}]

    # ── Session persistence ──────────────────────────────────────

    PLAN_PROMPT = """\
You are in **PLAN MODE**. The user wants a detailed implementation plan before any code is written.

## Your task
1. Analyze the request thoroughly
2. Use read-only tools (read_file, glob, grep, list_dir) to explore the codebase
3. Produce a structured plan with:
   - Requirements restatement
   - Affected files / modules
   - Step-by-step implementation phases
   - Dependencies between steps
   - Risks and edge cases
   - Estimated complexity

## Critical rules
- **Read-only exploration ONLY**: do NOT write files, edit code, or run destructive commands
- After presenting the plan, ask the user to confirm before implementation
- Be thorough: missing a key step is worse than having an extra one

The user's request follows below.
---
"""

    # ── Self-correction detection ─────────────────────────────────

    import re as _re

    # Patterns that suggest the model is still trying, not done.
    # Each pattern uses \b for word boundaries to avoid false matches
    # like "I should note that..." in the middle of a complete answer.
    _SELF_DIRECTION_RE = _re.compile(
        r"\b(?:"
        r"I should(?!\s+(?:note|mention|point|clarify|emphasize|add|explain))|"
        r"I need to(?!\s+(?:note|mention|point|clarify|emphasize|add|explain))|"
        r"let me try|let me attempt|let me check|let me look|"
        r"next I'll|I'll try|I will try|I can try|I have to|I must|"
        r"I wasn't able|I couldn't|didn't work|failed to|"
        r"I need more|I still need|not yet|"
        r"I haven't|I need to look|I should check"
        r")\b",
        _re.IGNORECASE,
    )

    # Only scan the tail of the response — self-direction language at the
    # end strongly suggests the model is still trying to figure things out.
    _SELF_DIRECTION_TAIL_CHARS = 400

    # Detect unparsed tool call fragments that the provider couldn't handle.
    # If the raw response still contains <tool_call or <tool_calls, the
    # model tried to use a tool but the format was wrong — retry.
    _UNPARSED_TOOL_RE = _re.compile(
        r"<tool_calls?\b|<parameter\s+name\s*=", _re.IGNORECASE
    )

    # Regex to parse CYCLE DONE markers from continuous evolution output
    _CYCLE_DONE_RE = _re.compile(
        r"CYCLE\s*DONE:\s*(.+?)\s*\|\s*(.+?)\s*\|\s*SCORE:\s*(\d+)",
        _re.IGNORECASE,
    )

    def _should_self_correct(self, final_text: str, exhausted: bool,
                              correction_round: int) -> bool:
        """Decide whether the model needs another self-correction round."""
        if not self.config.self_correction:
            return False

        # Always retry if tool rounds exhausted (model might be stuck in a loop)
        if exhausted:
            return True

        text = (final_text or "").strip()

        # Empty or trivial response — model gave up
        if not text or text == "[no text response]":
            return True

        # Response contains unparsed tool call fragments — the model tried
        # to use tools but the format was malformed (e.g. XML attribute style
        # instead of JSON). Tell it to use the correct format.
        if self._UNPARSED_TOOL_RE.search(text):
            return True

        # Check for self-direction language in the tail of the response.
        # Genuine self-correction phrases appear near the end; incidental
        # matches in a long complete answer are ignored.
        tail = text[-self._SELF_DIRECTION_TAIL_CHARS:]
        if self._SELF_DIRECTION_RE.search(tail):
            return True

        return False

    def _build_self_correction_prompt(self, last_response: str,
                                       original_task: str,
                                       retry_num: int) -> str:
        """Build a self-correction prompt to feed back as user input."""
        last = (last_response or "(no response)").strip()
        if len(last) > 500:
            last = last[:497] + "..."

        # Detect if the issue was malformed tool call syntax
        format_hint = ""
        if self._UNPARSED_TOOL_RE.search(last):
            format_hint = (
                "\n**IMPORTANT:** Your tool call syntax was incorrect. "
                "Use ONLY this exact format:\n"
                '<tool_call>\n'
                '{"name": "tool_name", "arguments": {"param": "value"}}\n'
                '</tool_call>\n'
                "Do NOT use XML attributes like name=\"...\" or <parameter> elements. "
                "Put the tool name and arguments as JSON inside the tags.\n\n"
            )

        return (
            f"[Auto-retry #{retry_num}]\n"
            f"Your previous response was: \"{last}\"\n\n"
            f"The original request was: \"{original_task}\"\n\n"
            f"{format_hint}"
            f"You haven't fully completed this task yet. "
            f"Analyze what went wrong or what's still missing. "
            f"If enough evidence is available, synthesize the result now; "
            f"otherwise take the next concrete tool action to move forward. "
            f"Do not end with only intent such as 'I need to continue'."
        )

    # ── Core agent loop ───────────────────────────────────────────

    def _retry_chat(self, tool_schemas: list[dict], max_retries: int = 3):
        """Call provider.chat() with exponential backoff on connection errors."""
        last_error = None
        for attempt in range(max_retries):
            try:
                return self.provider.chat(
                    messages=self._history,
                    tools=tool_schemas,
                    stream=True,
                    on_text=lambda t: self._emit_text(t),
                )
            except Exception as e:
                last_error = e
                msg = str(e).lower()
                # Only retry on connection/network errors
                is_retryable = any(kw in msg for kw in (
                    "connection", "timeout", "network", "reset",
                    "refused", "unreachable", "dns", "temporary",
                    "rate limit", "too many", "server error",
                    "internal server", "service unavailable",
                    "bad gateway", "gateway timeout",
                ))
                if not is_retryable or attempt >= max_retries - 1:
                    raise

                wait = (2 ** attempt) * 1.0  # 1s, 2s, 4s
                self._safe_print(
                    f"  [dim]~ retry {attempt + 1}/{max_retries} "
                    f"in {wait:.0f}s... ({type(e).__name__})[/]"
                )
                time.sleep(wait)

        raise last_error  # type: ignore

    def _provider_error_message(self, error: Exception) -> str | None:
        """Return a user-facing message for common LLM provider errors."""
        err_type = type(error)
        module = getattr(err_type, "__module__", "").lower()
        name = getattr(err_type, "__name__", "")
        text = str(error)
        lowered = text.lower()
        status = getattr(error, "status_code", None)
        if status is None:
            response = getattr(error, "response", None)
            status = getattr(response, "status_code", None)

        is_provider_error = (
            "openai" in module
            or "anthropic" in module
            or "api" in name.lower()
            or status is not None
        )
        if not is_provider_error:
            return None

        provider = self.config.provider.provider
        model = self.config.provider.model
        api_base = self.config.provider.api_base or "(provider default)"

        if status == 401 or "authentication" in name.lower() or "invalid api key" in lowered:
            cause = "API authentication failed: the configured API key is missing or invalid."
            hint = self._provider_auth_hint()
        elif status == 403 or "permission" in lowered or "forbidden" in lowered:
            cause = "API permission failed: the key is valid but is not allowed to use this model or endpoint."
            hint = "Check the provider account permissions, model name, and API base URL."
        elif status == 404 or "model" in lowered and "not found" in lowered:
            cause = "API request failed: the model or endpoint was not found."
            hint = "Check provider.model and provider.api_base in .chatcli/config.yaml."
        else:
            cause = f"API request failed: {name or 'provider error'}"
            hint = "Check the provider configuration and retry after fixing the API service issue."

        return (
            f"{cause}\n"
            f"Provider: {provider}\n"
            f"Model: {model}\n"
            f"API base: {api_base}\n"
            f"{hint}"
        )

    def _provider_auth_hint(self) -> str:
        """Build a provider-specific auth hint without exposing the API key."""
        provider = (self.config.provider.provider or "").lower()
        api_base = (self.config.provider.api_base or "").lower()
        api_key = self.config.provider.api_key or ""

        if "xiaomimimo.com" in api_base:
            if api_key.startswith("tp-") and "api.xiaomimimo.com" in api_base:
                return (
                    "This looks like a MiMo Token Plan key, but the configured API base "
                    "is the pay-as-you-go endpoint. Use the Token Plan Base URL shown on "
                    "the MiMo subscription page, or switch to a pay-as-you-go key for "
                    "https://api.xiaomimimo.com/v1. You can also set MIMO_API_KEY or "
                    "CHATCLI_API_KEY. The key value is not printed here."
                )
            if api_key.startswith("sk-") and "token-plan" in api_base:
                return (
                    "This looks like a pay-as-you-go MiMo key, but the configured API base "
                    "is a Token Plan endpoint. Use the pay-as-you-go base "
                    "https://api.xiaomimimo.com/v1, or switch to a Token Plan key and its "
                    "matching Token Plan Base URL. You can also set MIMO_API_KEY or "
                    "CHATCLI_API_KEY. The key value is not printed here."
                )
            return (
                "Check .chatcli/config.yaml provider.api_key and provider.api_base, or set "
                "MIMO_API_KEY or CHATCLI_API_KEY. For MiMo Token Plan keys, the Base URL "
                "must match the one shown on the subscription page. The key value is not "
                "printed here."
            )

        if provider == "anthropic":
            env_hint = "ANTHROPIC_API_KEY or CHATCLI_API_KEY"
        else:
            env_hint = "OPENAI_API_KEY or CHATCLI_API_KEY"
        return (
            "Check .chatcli/config.yaml provider.api_key, or set "
            f"{env_hint}. The key value is not printed here."
        )

    def _run_tool_loop(self) -> tuple[str, bool]:
        """Run the think→act→observe tool loop using current history.

        Returns (final_text, exhausted) where exhausted=True means
        max_tool_rounds was reached before the model produced a final answer.
        """
        tool_schemas = self.tools.to_schemas()

        for round_num in range(self.config.max_tool_rounds):
            if self.debug:
                self._debug_round_header(round_num)

            # Auto-compress if context is getting too long
            if self.config.auto_compress:
                self._maybe_compress()

            t0 = time.time()
            response = self._retry_chat(tool_schemas)
            elapsed = time.time() - t0

            if self.debug:
                self._debug_response(response)

            # Flush any buffered text before continuing
            self._flush_text_buffer()

            # Show token usage + timing
            self._show_usage(response, elapsed)

            if response.text:
                self._safe_print()

            # If no tool calls, we're done
            if not response.tool_calls:
                text = response.text.strip() if response.text else ""
                if not text:
                    text = "[no text response]"
                self._history.append({"role": "assistant", "content": text})
                self._auto_save()
                return text, False

            # Build assistant message with tool calls
            self._history.append(
                self.provider.format_assistant_message(response.text, response.tool_calls)
            )

            # Execute each tool call and collect results
            tool_results = []
            for tc in response.tool_calls:
                result = self._execute_tool(tc["name"], tc["input"])
                tool_results.append({
                    "tool_use_id": tc["id"],
                    "content": result,
                    "is_error": result.startswith("Error") or "error" in result.lower()[:20],
                })

            # Add tool results in provider's format
            self._history.extend(self.provider.format_tool_results(tool_results))
            self._auto_save()

        self._safe_print("[yellow]! max tool rounds reached[/]")
        return "", True

    def run(self, user_message: str) -> str:
        """Run a conversational turn with tool loop and self-correction.

        When self_correction is enabled, the agent detects incomplete
        responses and automatically feeds a self-correction prompt back
        as user input, looping until the task is complete or max rounds.
        """
        turn_start = time.monotonic()
        tokens_before = dict(self._total_tokens)
        tools_before = self._tool_calls_total
        original_message = user_message
        self._history.append({"role": "user", "content": user_message})
        self._auto_save()

        final_text = ""
        # Guard against zero/negative config values
        max_correction_rounds = max(4, self.config.max_self_correction_rounds)

        for correction_round in range(max_correction_rounds):
            try:
                final_text, exhausted = self._run_tool_loop()
            except Exception as e:
                message = self._provider_error_message(e)
                if not message:
                    raise
                self._flush_text_buffer()
                self._safe_print(f"[yellow]{message}[/]")
                self._history.append({"role": "assistant", "content": message})
                self._auto_save()
                return message

            # Check if we should self-correct
            needs_correction = self._should_self_correct(final_text, exhausted, correction_round)
            if needs_correction and correction_round < max_correction_rounds - 1:
                self_prompt = self._build_self_correction_prompt(
                    final_text, original_message, correction_round + 1
                )
                self._history.append({"role": "user", "content": self_prompt})
                self._auto_save()

                self._safe_print(
                    f" [cyan]~ auto-retry {correction_round + 1}[/] "
                    f"[dim]self-correcting...[/]"
                )
                continue

            if needs_correction:
                self._safe_print(
                    " [cyan]~ final continuation[/] "
                    "[dim]forcing synthesis or next concrete action...[/]"
                )
                self._history.append({
                    "role": "user",
                    "content": (
                        "[Final continuation]\n"
                        "The previous response still did not complete the task. "
                        "Do one final continuation: either produce the best evidence-based "
                        "answer from the current tool results, or make exactly one more "
                        "high-value tool call and then summarize. Do not stop with only "
                        "a plan or intent statement."
                    ),
                })
                self._auto_save()
                try:
                    final_text, _ = self._run_tool_loop()
                except Exception as e:
                    message = self._provider_error_message(e)
                    if not message:
                        raise
                    self._flush_text_buffer()
                    self._safe_print(f"[yellow]{message}[/]")
                    self._history.append({"role": "assistant", "content": message})
                    self._auto_save()
                    return message
                break

            # Task appears complete
            break

        if self.debug:
            self._debug_summary()
        self._show_turn_summary(turn_start, tokens_before, tools_before)
        self._auto_save()
        return final_text or ""

    def _parse_cycle_results(self, text: str) -> list[tuple[str, str, int]]:
        """Parse CYCLE DONE: <target> | <goal> | SCORE: <N> markers."""
        return [
            (m.group(1).strip(), m.group(2).strip(), int(m.group(3)))
            for m in self._CYCLE_DONE_RE.finditer(text)
        ]

    def _run_one_continuous_cycle(self, state: dict, consecutive_idle: int
                                  ) -> tuple[int, bool]:
        """Execute a single continuous improvement cycle.

        Returns (new_consecutive_idle, should_stop).
        """
        from .evolve import build_continuous_prompt, record_cycle

        prompt = build_continuous_prompt(state)

        try:
            result = self.run(prompt)
        except KeyboardInterrupt:
            raise  # let caller handle Ctrl+C
        except Exception as e:
            self._safe_print(
                f"  [yellow]! cycle error: {e}[/] "
                f"[dim]retrying in 5s...[/]"
            )
            time.sleep(5)
            consecutive_idle += 1
            if consecutive_idle >= 3:
                self._safe_print(
                    "  [yellow]! 3 consecutive errors[/] "
                    "[dim]pausing continuous mode[/]"
                )
                return consecutive_idle, True
            return consecutive_idle, False

        # Parse CYCLE DONE markers from model output
        cycles = self._parse_cycle_results(result or "")

        if cycles:
            for target, goal, score in cycles:
                updated = record_cycle(
                    self.workspace, target, goal,
                    f"Score: {score}", score,
                )
                n = updated.get("cycles_completed", "?")
                self._safe_print(
                    f"  [green]✓ cycle {n}[/] "
                    f"[dim]{target} | {goal[:60]} | score={score}[/]"
                )
            return 0, False

        consecutive_idle += 1
        if consecutive_idle >= 2:
            self._safe_print(
                "  [yellow]! 2 rounds without cycle markers[/] "
                "[dim]pausing continuous mode[/]"
            )
            return consecutive_idle, True

        self._safe_print(
            "  [dim]~ no cycle marker found, restarting anyway...[/]"
        )
        return consecutive_idle, False

    def run_continuous(self) -> None:
        """Run continuous self-improvement with automatic cycle restart.

        Unlike run() which does one conversational turn, this loops
        indefinitely — after each agent.run() completes, it parses
        CYCLE DONE markers, records progress, and restarts with a
        fresh continuation prompt.  Ctrl+C or stalled progress exits.
        """
        from .evolve import get_state

        self._safe_print(
            f"  [dim]● continuous mode: auto-restart after each cycle[/]"
        )

        consecutive_idle = 0

        while True:
            state = get_state(self.workspace)
            if not state or state.get("status") != "running":
                self._safe_print("  [dim]● continuous evolution ended[/]")
                break

            # Compress history between cycles so old context doesn't
            # bleed into new cycles and waste tokens
            if self.config.auto_compress:
                self._maybe_compress()

            try:
                consecutive_idle, should_stop = self._run_one_continuous_cycle(
                    state, consecutive_idle,
                )
            except KeyboardInterrupt:
                self._safe_print("")
                self._safe_print("  [dim]● continuous paused (Ctrl+C)[/]")
                break

            if should_stop:
                break

            time.sleep(0.5)

        self._auto_save()

    def plan(self, user_message: str) -> str:
        """Run in plan mode: explore codebase, produce plan, wait for approval."""
        self._safe_print(Panel(
            "[bold yellow]# PLAN MODE[/]\n"
            "[dim]Read-only exploration. Type 'go ahead' to execute the plan.[/]",
            border_style="yellow", padding=(0, 1),
        ))
        return self.run(self.PLAN_PROMPT + user_message)

    INIT_PROMPT = """\
You are initializing a project context file for chatcli. Your task:

1. Explore the project structure using read_file, glob, grep, list_dir
2. Identify: tech stack, entry points, directory layout, conventions, dependencies
3. Create `.chatcli/context.md` (write_file) with this structure:

```
# Project: <name>

## Tech Stack
- Language: ...
- Framework: ...
- Key dependencies: ...

## Directory Structure
- `src/` — main source code
- `tests/` — test files
- ...

## Entry Points
- `main.py` — CLI entry point
- ...

## Conventions
- Naming: ...
- Testing: ...
- ...

## Notes
- Any important patterns or gotchas
```

**Rules:**
- Explore thoroughly before writing — read key config files (package.json, pyproject.toml, go.mod, etc.)
- The context file helps future chatcli sessions understand this project
- Write concise, factual descriptions
- After creating the file, summarize what you found
"""

    def init_project(self) -> str:
        """Explore the project and generate .chatcli/context.md."""
        self._safe_print(Panel(
            "[bold green]# INIT MODE[/]\n"
            "[dim]Exploring project and generating .chatcli/context.md...[/]",
            border_style="green", padding=(0, 1),
        ))
        return self.run(self.INIT_PROMPT)
