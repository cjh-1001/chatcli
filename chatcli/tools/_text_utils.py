"""Shared text helpers for chatcli tools."""


def short_text(value, limit: int = 200) -> str:
    """Truncate *value* to *limit* chars, collapsing whitespace.

    Returns the original text (with whitespace normalized) when it fits;
    appends ``"..."`` when truncated.
    """
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."
