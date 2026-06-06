"""OpenAI (and compatible) provider."""

import json
from collections.abc import Callable

import httpx
from openai import OpenAI
from .base import BaseProvider, LLMResponse


class OpenAIProvider(BaseProvider):
    message_format = "openai"

    def __init__(self, config):
        self.config = config
        # Use a httpx.Timeout with a generous read timeout so streaming
        # responses aren't killed when the model pauses between chunks.
        # The SDK's own max_retries is set to 0 — our agent-level
        # _retry_chat handles retries with backoff instead.
        timeout = httpx.Timeout(
            config.request_timeout,          # overall default
            connect=30.0,                     # TCP/TLS handshake
            read=max(config.request_timeout, 600.0),   # wait between stream chunks
            write=60.0,                       # upload request body
            pool=30.0,                        # wait for connection from pool
        )
        self.client = OpenAI(
            api_key=config.provider.api_key or "sk-placeholder",
            base_url=config.provider.api_base or None,
            timeout=timeout,
            max_retries=0,  # agent._retry_chat handles retries
        )

    def chat(self, messages: list[dict], tools: list[dict], stream: bool = True,
             on_text: Callable[[str], None] | None = None) -> LLMResponse:
        # Convert anthropic-style tool schemas to OpenAI format
        openai_tools = []
        for t in tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": {
                        "type": "object",
                        "properties": t["input_schema"].get("properties", {}),
                        "required": t["input_schema"].get("required", []),
                    },
                },
            })

        kwargs = {
            "model": self.config.provider.model,
            "max_tokens": self.config.provider.max_tokens,
            "messages": messages,
        }
        if openai_tools:
            kwargs["tools"] = openai_tools

        if stream:
            return self._stream_response(kwargs, on_text)
        else:
            return self._sync_response(kwargs)

    def _sync_response(self, kwargs: dict) -> LLMResponse:
        resp = self.client.chat.completions.create(**kwargs)
        return self._parse_choice(resp.choices[0], resp.usage)

    def _stream_response(self, kwargs: dict, on_text: Callable[[str], None] | None) -> LLMResponse:
        text_parts = []
        tool_call_deltas: dict[int, dict] = {}
        usage = {}
        stop_reason = "end_turn"

        stream = self.client.chat.completions.create(stream=True, **kwargs)
        for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta

            if delta.content and on_text:
                on_text(delta.content)
            if delta.content:
                text_parts.append(delta.content)

            if delta.tool_calls:
                for tc in delta.tool_calls:
                    idx = tc.index
                    if idx not in tool_call_deltas:
                        tool_call_deltas[idx] = {"id": "", "name": "", "arguments": ""}
                    if tc.id:
                        tool_call_deltas[idx]["id"] = tc.id
                    if tc.function:
                        if tc.function.name:
                            tool_call_deltas[idx]["name"] += tc.function.name
                        if tc.function.arguments:
                            tool_call_deltas[idx]["arguments"] += tc.function.arguments

            if chunk.choices[0].finish_reason:
                stop_reason = chunk.choices[0].finish_reason

            if chunk.usage:
                usage = {
                    "input_tokens": chunk.usage.prompt_tokens or 0,
                    "output_tokens": chunk.usage.completion_tokens or 0,
                }

        tool_calls = []
        for idx, block in tool_call_deltas.items():
            raw_args = block.get("arguments", "")
            try:
                tool_calls.append({
                    "id": block["id"] or f"call_{idx}",
                    "name": block["name"],
                    "input": json.loads(raw_args) if raw_args else {},
                })
            except json.JSONDecodeError:
                import sys as _sys
                print(
                    f"\n[chatcli] Warning: failed to parse JSON arguments "
                    f"for tool '{block.get('name', '?')}' "
                    f"(len={len(raw_args)}). "
                    f"Input will be empty — the tool error may help the model self-correct.\n",
                    file=_sys.stderr,
                )
                tool_calls.append({
                    "id": block["id"] or f"call_{idx}",
                    "name": block["name"],
                    "input": {},
                })

        return LLMResponse(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=usage,
        )

    def _parse_choice(self, choice, raw_usage) -> LLMResponse:
        msg = choice.message
        text = msg.content or ""
        tool_calls = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                raw_args = getattr(tc.function, "arguments", "") or ""
                try:
                    args = json.loads(raw_args)
                except (json.JSONDecodeError, AttributeError):
                    import sys as _sys
                    print(
                        f"\n[chatcli] Warning: failed to parse JSON arguments "
                        f"for tool '{getattr(tc.function, 'name', '?')}' "
                        f"(len={len(raw_args)}). "
                        f"Input will be empty — the tool error may help the model self-correct.\n",
                        file=_sys.stderr,
                    )
                    args = {}
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": args,
                })
        usage = {}
        if raw_usage:
            usage = {
                "input_tokens": raw_usage.prompt_tokens or 0,
                "output_tokens": raw_usage.completion_tokens or 0,
            }
        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            stop_reason=choice.finish_reason or "stop",
            usage=usage,
        )
