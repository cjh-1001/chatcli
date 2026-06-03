"""Base provider interface."""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    stop_reason: str = "end_turn"
    usage: dict = field(default_factory=dict)


class BaseProvider(ABC):
    """Abstract base for LLM providers."""

    # Providers override this to indicate their message format
    message_format: str = "anthropic"  # "anthropic" or "openai"

    @abstractmethod
    def chat(
        self,
        messages: list[dict],
        tools: list[dict],
        stream: bool = True,
        on_text: Callable[[str], None] | None = None,
    ) -> LLMResponse:
        """Send a chat completion request. Returns the model's response."""
        ...

    def format_assistant_message(self, text: str, tool_calls: list[dict]) -> dict:
        """Build an assistant message dict in this provider's format."""
        if self.message_format == "openai":
            openai_tool_calls = []
            for tc in tool_calls:
                openai_tool_calls.append({
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["name"],
                        "arguments": json.dumps(tc["input"], ensure_ascii=False),
                    },
                })
            return {
                "role": "assistant",
                "content": text or None,
                "tool_calls": openai_tool_calls,
            }
        else:
            # Anthropic content block format
            content = []
            if text:
                content.append({"type": "text", "text": text})
            for tc in tool_calls:
                content.append({
                    "type": "tool_use",
                    "id": tc["id"],
                    "name": tc["name"],
                    "input": tc["input"],
                })
            return {"role": "assistant", "content": content}

    def format_tool_results(self, results: list[dict]) -> list[dict]:
        """Build tool result messages in this provider's format."""
        if self.message_format == "openai":
            messages = []
            for r in results:
                messages.append({
                    "role": "tool",
                    "tool_call_id": r["tool_use_id"],
                    "content": r["content"],
                })
            return messages
        else:
            # Anthropic: single user message with tool_result blocks
            content = []
            for r in results:
                content.append({
                    "type": "tool_result",
                    "tool_use_id": r["tool_use_id"],
                    "content": r["content"],
                    "is_error": r.get("is_error", False),
                })
            return [{"role": "user", "content": content}]
