"""LLM provider abstraction layer."""

from .base import BaseProvider
from .anthropic import AnthropicProvider
from .openai import OpenAIProvider
from .text_tools import TextToolsProvider


def create_provider(config) -> BaseProvider:
    """Factory to create the right provider from config."""
    p = config.provider.provider
    if p == "anthropic":
        return AnthropicProvider(config)
    elif p in ("openai", "openai-compatible"):
        return OpenAIProvider(config)
    elif p == "text-tools":
        return TextToolsProvider(config)
    else:
        raise ValueError(f"Unknown provider: {p}. Valid: anthropic, openai, openai-compatible, text-tools")


__all__ = [
    "BaseProvider", "AnthropicProvider", "OpenAIProvider",
    "TextToolsProvider", "create_provider",
]
