"""Context compression support for Agent."""

import json
from pathlib import Path


class CompressionMixin:
    def _estimate_tokens(self, text: str) -> int:
        """Rough token count. Falls back to char-based heuristic if tiktoken missing."""
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except Exception:
            # CJK chars are ~1.5 tokens each; ASCII ~0.25 tokens each.
            # Use a weighted average: count CJK characters separately.
            cjk = sum(1 for ch in text if '一' <= ch <= '鿿'
                      or '　' <= ch <= '〿' or '＀' <= ch <= '￯')
            ascii_chars = len(text) - cjk
            return int(cjk * 1.5 + ascii_chars * 0.3)

    def _history_tokens(self) -> int:
        """Estimate total tokens in conversation history."""
        total = 0
        for m in self._history:
            content = m.get("content", "")
            if isinstance(content, str):
                total += self._estimate_tokens(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and "text" in block:
                        total += self._estimate_tokens(block["text"])
                    elif isinstance(block, dict) and "input" in block:
                        total += self._estimate_tokens(json.dumps(block["input"]))
        return total

    def _maybe_compress(self) -> bool:
        """Compress history if it exceeds the threshold. Returns True if compressed."""
        threshold = self.config.compress_threshold
        tokens = self._history_tokens()
        if tokens < threshold:
            return False

        # Keep: system prompt + last 30% of messages (working memory)
        keep_count = max(3, int(len(self._history) * 0.3))
        to_compress = self._history[1:-keep_count]  # exclude system[0] and recent
        recent = self._history[-keep_count:]

        if len(to_compress) < 5:
            return False  # not enough to be worth compressing

        archive_path = self._archive_compressed_messages(to_compress)
        if archive_path is None:
            return False

        self._safe_print(
            f"[dim]~ compressing context: {self._fmt_tokens(tokens)} -> "
            f"summarizing {len(to_compress)} messages...[/]"
        )

        # Build compression request
        summary_text = self._build_summary(to_compress)

        # Replace compressed messages with summary
        self._history = [
            self._history[0],  # system prompt
            {"role": "user", "content": summary_text},
        ] + recent

        new_tokens = self._history_tokens()
        saved = tokens - new_tokens
        self._safe_print(
            f"[dim]~ compressed: {self._fmt_tokens(tokens)} -> "
            f"{self._fmt_tokens(new_tokens)} "
            f"(saved {self._fmt_tokens(saved)}; raw archived to {archive_path})[/]"
        )
        self._compression_events.append({
            "before_tokens": tokens,
            "after_tokens": new_tokens,
            "saved_tokens": saved,
            "archived_to": str(archive_path),
            "messages_summarized": len(to_compress),
        })
        self._auto_save()
        return True

    def pop_compression_events(self) -> list[dict]:
        """Return and clear compression events since the last caller check."""
        events = list(self._compression_events)
        self._compression_events.clear()
        return events

    def _build_summary(self, messages: list[dict]) -> str:
        """Build a compression prompt and get a summary from the model."""
        # Build a compact representation of the history to compress
        parts = []
        for m in messages:
            role = m.get("role", "?")
            content = m.get("content", "")
            if isinstance(content, list):
                # Anthropic format: blocks
                texts = []
                for block in content:
                    if isinstance(block, dict):
                        if "text" in block:
                            texts.append(str(block["text"])[:200])
                        elif "tool_use" in block:
                            texts.append(f"[tool: {block.get('name','?')}]")
                        elif "tool_result" in block:
                            texts.append(f"[result: {str(block.get('content',''))[:100]}]")
                content = " ".join(texts)
            elif isinstance(content, str):
                content = content[:300]
            parts.append(f"[{role}] {content}")

        history_text = "\n".join(parts)
        if len(history_text) > 8000:
            history_text = history_text[:8000] + "\n... (truncated)"
        durable_state = self._durable_state_for_compression()

        summary_prompt = (
            "Summarize this conversation history. Include:\n"
            "- Key decisions made and why\n"
            "- Files modified and what changed\n"
            "- Important findings or patterns\n"
            "- Current task and progress\n"
            "- Child-window results and record paths that should guide next steps\n"
            "- User preferences or conventions noted\n\n"
            "Be concise. This summary replaces the detailed history "
            "to save context space.\n\n"
            f"--- Conversation history ---\n{history_text}\n"
            f"--- Durable task/child state ---\n{durable_state}\n"
            "---\n\nSummary:"
        )

        try:
            # Use a short timeout for the compression call — if the API
            # is unresponsive we fall back to the local extractor instead
            # of freezing the entire session.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.provider.chat,
                    messages=[{"role": "user", "content": summary_prompt}],
                    tools=[],
                    stream=False,
                )
                try:
                    response = future.result(timeout=30)
                except concurrent.futures.TimeoutError:
                    self._safe_print(
                        "  [dim]~ compression API timed out, using local fallback[/]"
                    )
                    return self._fallback_summary(history_text + "\n\n" + durable_state)
            summary = response.text.strip()
            if summary:
                return (
                    "[This is a compressed summary of the earlier conversation. "
                    "The detailed messages have been replaced to save context. "
                    "Key information is preserved below.]\n\n"
                    f"{summary}"
                )
        except Exception as e:
            self._safe_print(
                f"  [dim]~ compression API failed ({type(e).__name__}), "
                f"using local fallback[/]"
            )

        # Fallback: extract key facts manually
        return self._fallback_summary(history_text + "\n\n" + durable_state)

    def _durable_state_for_compression(self) -> str:
        """Read durable task and child-window state for smarter compression."""
        parts = []
        try:
            task_path = Path(self.workspace) / ".chatcli" / "task.md"
            if task_path.exists():
                text = task_path.read_text(encoding="utf-8", errors="replace")
                parts.append("## .chatcli/task.md\n" + text[:6000])
        except Exception:
            pass
        try:
            children_dir = Path(self.workspace) / ".chatcli" / "children"
            active_task_id = str(getattr(self, "_chatcli_task_id", "") or "").strip()
            if children_dir.exists():
                records = sorted(
                    children_dir.glob("*.md"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )[:8]
                child_parts = []
                for path in records:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    if active_task_id and f"- Task ID: {active_task_id}" not in text:
                        continue
                    lines = []
                    for line in text.splitlines():
                        if line.startswith(("- Status:", "- Updated:", "- Task ID:", "- Task:", "- Summary:")):
                            lines.append(line)
                        if len(lines) >= 8:
                            break
                    child_parts.append(f"### {path.name}\n" + "\n".join(lines))
                if child_parts:
                    parts.append("## Child records\n" + "\n\n".join(child_parts))
        except Exception:
            pass
        return "\n\n".join(parts) if parts else "(no durable task/child state found)"

    def _fallback_summary(self, history_text: str) -> str:
        """Extract key facts when LLM summarization fails."""
        import re
        facts = []
        for line in history_text.split("\n"):
            line = line.strip()
            if any(kw in line.lower() for kw in
                   ["decided", "changed", "modified", "created", "fixed",
                    "important", "remember", "convention", "pattern"]):
                facts.append(line[:200])

        if not facts:
            facts = ["Conversation about code improvement and tool usage."]

        return (
            "[Compressed conversation summary]\n\n"
            + "\n".join(f"• {f}" for f in facts[:30])
        )

    def compress_now(self) -> bool:
        """Manually trigger compression (for /compress command)."""
        return self._maybe_compress()


