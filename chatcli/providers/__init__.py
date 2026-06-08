"""LLM provider abstraction layer."""

from .base import BaseProvider


def create_provider(config) -> BaseProvider:
    """Factory to create the right provider from config."""
    p = config.provider.provider
    if p == "anthropic":
        from .anthropic import AnthropicProvider
        return AnthropicProvider(config)
    elif p in ("openai", "openai-compatible"):
        from .openai import OpenAIProvider
        return OpenAIProvider(config)
    elif p == "text-tools":
        from .text_tools import TextToolsProvider
        return TextToolsProvider(config)
    else:
        raise ValueError(f"Unknown provider: {p}. Valid: anthropic, openai, openai-compatible, text-tools")


def __getattr__(name: str):
    if name == "AnthropicProvider":
        from .anthropic import AnthropicProvider
        return AnthropicProvider
    if name == "OpenAIProvider":
        from .openai import OpenAIProvider
        return OpenAIProvider
    if name == "TextToolsProvider":
        from .text_tools import TextToolsProvider
        return TextToolsProvider
    raise AttributeError(name)


__all__ = [
    "BaseProvider", "AnthropicProvider", "OpenAIProvider",
    "TextToolsProvider", "create_provider",
]
