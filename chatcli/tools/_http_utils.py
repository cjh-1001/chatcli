"""Shared constants for tools (HTTP, I/O limits)."""

# ═══════════════════════════════════════════════════════════════════
# HTTP constants
# ═══════════════════════════════════════════════════════════════════

SEARCH_TIMEOUT = 20.0

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
}

# ═══════════════════════════════════════════════════════════════════
# I/O limits
# ═══════════════════════════════════════════════════════════════════

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB — shared by read, write, edit, web_fetch
