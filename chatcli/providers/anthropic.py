"""Anthropic Claude provider."""

import json
from collections.abc import Callable

import anthropic
import httpx
from .base import BaseProvider, LLMResponse


class AnthropicProvider(BaseProvider):
    def __init__(self, config):
        self.config = config
        # Generous read timeout so streaming isn't killed when the model
        # pauses between chunks. SDK retries are disabled — agent-level
        # _retry_chat handles retries with backoff.
        timeout = httpx.Timeout(
            config.request_timeout,
            connect=30.0,
            read=max(config.request_timeout, 600.0),
            write=60.0,
            pool=30.0,
        )
        self.client = anthropic.Anthropic(
            api_key=config.provider.api_key or None,
            base_url=config.provider.api_base or None,
            timeout=timeout,
            max_retries=0,  # agent._retry_chat handles retries
        )

    def chat(self, messages: list[dict], tools: list[dict], stream: bool = True,
             on_text: Callable[[str], None] | None = None) -> LLMResponse:
        # Separate system message from conversation
        system = ""
        conversation = []
        for m in messages:
            if m["role"] == "system":
                system += m["content"] + "\n"
            else:
                conversation.append(m)

        # Convert user/assistant messages to anthropic format
        anthropic_messages = []
        for m in conversation:
            role = m["role"]
            content = m["content"]
            if isinstance(content, str):
                anthropic_messages.append({"role": role, "content": content})
            elif isinstance(content, list):
                # Already in anthropic content block format
                anthropic_messages.append({"role": role, "content": content})

        # Convert tools to anthropic format
        anthropic_tools = []
        for t in tools:
            anthropic_tools.append({
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["input_schema"],
            })

        kwargs = {
            "model": self.config.provider.model,
            "max_tokens": self.config.provider.max_tokens,
            "messages": anthropic_messages,
        }
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        if system:
            kwargs["system"] = system.strip()
        if self.config.provider.thinking:
            max_tokens = int(self.config.provider.max_tokens or 0)
            requested_budget = int(self.config.provider.thinking_budget or 0)
            if max_tokens > 1024:
                # Anthropic extended thinking requires the budget to fit inside
                # max_tokens and still leave room for the visible answer.
                budget = max(1024, min(requested_budget, max_tokens // 2))
            else:
                budget = 0
        else:
            budget = 0

        if budget:
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": budget,
            }

        if stream:
            return self._stream_response(kwargs, on_text)
        else:
            return self._sync_response(kwargs)

    def _sync_response(self, kwargs: dict) -> LLMResponse:
        resp = self.client.messages.create(**kwargs)
        return self._parse_response(resp)

    def _stream_response(self, kwargs: dict, on_text: Callable[[str], None] | None) -> LLMResponse:
        text_parts = []
        tool_use_blocks: dict[int, dict] = {}
        usage = {}
        stop_reason = "end_turn"

        with self.client.messages.stream(**kwargs) as stream:
            for event in stream:
                if event.type == "content_block_delta":
                    if event.delta.type == "text_delta":
                        text_parts.append(event.delta.text)
                        if on_text:
                            on_text(event.delta.text)
                    elif event.delta.type == "input_json_delta":
                        idx = event.index
                        if idx not in tool_use_blocks:
                            tool_use_blocks[idx] = {"name": "", "input": ""}
                        tool_use_blocks[idx]["input"] += event.delta.partial_json

                elif event.type == "content_block_start":
                    if event.content_block.type == "tool_use":
                        tool_use_blocks[event.index] = {
                            "name": event.content_block.name,
                            "input": "",
                            "id": event.content_block.id,
                        }

                elif event.type == "message_delta":
                    if event.usage:
                        usage = {
                            "input_tokens": getattr(event.usage, "input_tokens", 0),
                            "output_tokens": getattr(event.usage, "output_tokens", 0),
                        }
                    if event.delta.stop_reason:
                        stop_reason = event.delta.stop_reason

            final = stream.get_final_message()

        tool_calls = []
        for idx, block in tool_use_blocks.items():
            raw_input = block.get("input", "")
            try:
                tool_calls.append({
                    "id": block.get("id", f"toolu_{idx}"),
                    "name": block["name"],
                    "input": json.loads(raw_input) if raw_input else {},
                })
            except json.JSONDecodeError:
                import sys as _sys
                print(
                    f"\n[chatcli] Warning: failed to parse JSON arguments "
                    f"for tool '{block.get('name', '?')}' "
                    f"(len={len(raw_input)}). "
                    f"Input will be empty — the tool error may help the model self-correct.\n",
                    file=_sys.stderr,
                )
                tool_calls.append({
                    "id": block.get("id", f"toolu_{idx}"),
                    "name": block["name"],
                    "input": {},
                })

        return LLMResponse(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=usage,
        )

    def _parse_response(self, resp) -> LLMResponse:
        text = ""
        tool_calls = []
        for block in resp.content:
            if block.type == "text":
                text += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            stop_reason=resp.stop_reason,
            usage={
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            },
        )
