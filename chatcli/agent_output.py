"""Console output, streaming text, usage, and debug helpers for Agent."""

import json
import re
import time

from rich.panel import Panel


class AgentOutputMixin:
    @staticmethod
    def _sanitize(text: str) -> str:
        """Strip characters that can't be encoded in GBK (Windows console)."""
        try:
            text.encode("gbk")
            return text
        except UnicodeEncodeError:
            return text.encode("gbk", errors="replace").decode("gbk")

    def _safe_print(self, *args, markup: bool = True, **kwargs) -> None:
        """Print rich text, sanitizing for Windows GBK console.

        Set markup=False for user/LLM text that may contain literal
        bracket sequences like [/something] or [U+XXXX].
        """
        safe_args = []
        for a in args:
            if isinstance(a, str):
                safe_args.append(self._sanitize(a))
            else:
                safe_args.append(a)
        try:
            self.console.print(*safe_args, markup=markup, **kwargs)
            # On Windows, Rich buffers partial lines (no trailing \n) and
            # won't flush until a newline arrives or the buffer fills.
            # Explicit flush ensures streaming text appears immediately.
            if kwargs.get("end", "\n") != "\n" or not args:
                self.console.file.flush()
        except (UnicodeEncodeError, Exception):
            # Rich sometimes fails on markup or encoding; skip gracefully
            pass

    # ── Text buffering + wrapping ────────────────────────────────────

    _TEXT_FLUSH_BOUNDARIES = ["\n\n", "\n", ". ", "! ", "? ", ": ", "。", "！", "？", "："]
    _TEXT_MAX_BUFFER = 100  # force-flush after this many chars even without a boundary

    def _wrap_long_lines(self, text: str) -> str:
        """Soft-wrap lines that exceed the terminal width, at word boundaries."""
        import textwrap
        width = min(self.console.width or 100, 100)
        lines = text.split("\n")
        wrapped = []
        for line in lines:
            if len(line) > width:
                wrapped.extend(textwrap.wrap(
                    line, width=width,
                    break_long_words=False,
                    break_on_hyphens=False,
                    drop_whitespace=False,
                ))
            else:
                wrapped.append(line)
        return "\n".join(wrapped)

    def _format_cli_text(self, text: str) -> str:
        """Make streamed model text friendlier for a plain CLI."""
        if not text:
            return text
        literal_newlines = text.count("\\n") + text.count("\\r\\n")
        if literal_newlines >= 2 or "\\n-" in text or "\\n#" in text or "\\n*" in text:
            text = text.replace("\\r\\n", "\n").replace("\\n", "\n")
        lines = []
        for line in text.split("\n"):
            cleaned = re.sub(r"^\s{0,3}#{1,6}\s+", "", line)
            cleaned = re.sub(r"^\s*[-*]\s+#{1,6}\s+", "- ", cleaned)
            lines.append(cleaned)
        return "\n".join(lines)

    def _emit_text(self, text: str) -> None:
        """Buffer streaming text; flush at sentence/paragraph boundaries.

        Batches small token-chunks together for smooth console output,
        but force-flushes after _TEXT_MAX_BUFFER chars to avoid long stalls.
        """
        self._text_buffer += text

        # Find the latest natural flush point (sentence / paragraph break)
        flush_at = -1
        for boundary in self._TEXT_FLUSH_BOUNDARIES:
            idx = self._text_buffer.rfind(boundary)
            if idx >= 0:
                flush_at = max(flush_at, idx + len(boundary))

        # No boundary found and buffer is getting large → force flush
        if flush_at < 0 and len(self._text_buffer) >= self._TEXT_MAX_BUFFER:
            flush_at = len(self._text_buffer)

        if flush_at > 0:
            chunk = self._text_buffer[:flush_at]
            self._text_buffer = self._text_buffer[flush_at:]
            chunk = self._format_cli_text(chunk)
            self._safe_print(self._wrap_long_lines(chunk), end="", markup=False)
            self._stream_open_line = not chunk.endswith("\n")

    def _flush_text_buffer(self) -> None:
        """Flush any remaining buffered text to the console."""
        if self._text_buffer:
            chunk = self._format_cli_text(self._text_buffer)
            self._safe_print(self._wrap_long_lines(chunk), end="", markup=False)
            self._stream_open_line = not chunk.endswith("\n")
            self._text_buffer = ""
        self._close_stream_line()

    def _close_stream_line(self) -> None:
        """Ensure structured output starts on a fresh line."""
        if self._stream_open_line:
            self._safe_print()
            self._stream_open_line = False

    @staticmethod
    def _fmt_tokens(n: int) -> str:
        """Format token count compactly: 1234 -> 1.2k, 123456 -> 123k."""
        if n >= 1_000_000:
            return f"{n/1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n/1_000:.1f}k"
        return str(n)

    @staticmethod
    def _fmt_time(s: float) -> str:
        """Format seconds compactly."""
        if s < 1.0:
            return f"{s*1000:.0f}ms"
        if s < 60:
            return f"{s:.1f}s"
        m, sec = divmod(int(s), 60)
        return f"{m}m{sec}s"

    def _show_usage(self, response, elapsed: float) -> None:
        """Show compact token + timing line after each response."""
        inp = out = 0
        if response.usage:
            inp = response.usage.get("input_tokens", 0)
            out = response.usage.get("output_tokens", 0)
            self._total_tokens["input"] += inp
            self._total_tokens["output"] += out
        self._total_time += elapsed

        bits = []
        if inp or out:
            bits.append(f"[dim]{self._fmt_tokens(inp)} in[/]")
            bits.append(f"[dim]{self._fmt_tokens(out)} out[/]")
        bits.append(f"[dim]{self._fmt_time(elapsed)}[/]")
        self._safe_print(f"  {' | '.join(bits)}")

    def _show_turn_summary(
        self, started_at: float, tokens_before: dict, tools_before: int
    ) -> None:
        """Show a Codex/Claude Code-style per-turn usage footer."""
        elapsed = time.monotonic() - started_at
        in_delta = self._total_tokens["input"] - int(tokens_before.get("input", 0))
        out_delta = self._total_tokens["output"] - int(tokens_before.get("output", 0))
        tools_delta = self._tool_calls_total - tools_before
        parts = [f"[dim]done {self._fmt_time(elapsed)}[/]"]
        if in_delta or out_delta:
            parts.extend([
                f"[dim]{self._fmt_tokens(in_delta)} in[/]",
                f"[dim]{self._fmt_tokens(out_delta)} out[/]",
                (
                    f"[dim]total {self._fmt_tokens(self._total_tokens['input'])} in / "
                    f"{self._fmt_tokens(self._total_tokens['output'])} out[/]"
                ),
            ])
        if tools_delta:
            parts.append(f"[dim]{tools_delta} tools[/]")
        self._safe_print(f"  {' | '.join(parts)}")

    def get_usage_summary(self) -> str:
        """Return a summary of total token usage and time."""
        total_in = self._fmt_tokens(self._total_tokens["input"])
        total_out = self._fmt_tokens(self._total_tokens["output"])
        total_time = self._fmt_time(self._total_time)
        if not self._total_tokens["input"] and not self._total_tokens["output"]:
            return f"[dim]{self._tool_calls_total} tools | {total_time} model time[/]"
        return (
            f"[dim]{total_in} in | {total_out} out | "
            f"{self._tool_calls_total} tools | {total_time} model time[/]"
        )

    # ── Context compression ──────────────────────────────────────

    # ── Debug helpers ────────────────────────────────────────────

    def _debug_round_header(self, round_num: int) -> None:
        roles = [m["role"] for m in self._history]
        role_counts = {r: roles.count(r) for r in set(roles)}
        total_chars = sum(
            len(json.dumps(m.get("content", ""), ensure_ascii=False))
            for m in self._history
        )
        self._safe_print(
            Panel(
                f"[bold]Round {round_num + 1}[/]\n"
                f"Messages: {len(self._history)} ({role_counts})\n"
                f"Context size: ~{total_chars} chars",
                border_style="dim magenta", padding=(0, 1),
            )
        )

    def _debug_response(self, response) -> None:
        from rich.markup import escape as _escape
        if response.tool_calls:
            for i, tc in enumerate(response.tool_calls):
                args = _escape(json.dumps(tc["input"], ensure_ascii=False))
                if len(args) > 200:
                    args = args[:200] + "..."
                self._safe_print(
                    f"[dim magenta]tool #{i}[/] [cyan]{_escape(tc['name'])}[/] "
                    f"[dim]id={tc['id'][:20]}... args={args}[/]"
                )
        if response.text:
            preview = _escape(response.text[:150].replace("\n", " "))
            self._safe_print(f"[dim magenta]text[/] [dim]{preview}...[/]")
        if response.usage:
            self._safe_print(
                f"[dim magenta]usage[/] [dim]in={response.usage.get('input_tokens', '?')} "
                f"out={response.usage.get('output_tokens', '?')}[/]"
            )

    def _debug_summary(self) -> None:
        self._safe_print(
            f"[dim magenta]total tokens[/] [dim]"
            f"in={self._total_tokens['input']} "
            f"out={self._total_tokens['output']}[/]"
        )

