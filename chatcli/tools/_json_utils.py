"""Shared JSON helpers for chatcli tools."""

import json
from pathlib import Path
from typing import Any


# Default max file size for JSON inputs (50 MB).
# Some tools (e.g. detection_lint) override this with a lower value at call time.
MAX_JSON_SIZE = 50 * 1024 * 1024


def load_json(path: Path, *, label: str = "", max_size: int = MAX_JSON_SIZE) -> tuple[Any | None, str | None]:
    """Safely load a JSON file, returning ``(data, None)`` or ``(None, error)``.

    *label* is used in error messages to identify the calling tool (e.g.
    ``"attack chain"``).  *max_size* overrides the default size guard.
    """
    if not path.exists():
        return None, f"missing JSON file: {path}"
    if path.is_dir():
        return None, f"path is a directory, not JSON: {path}"
    size = path.stat().st_size
    if size > max_size:
        context = f" for {label}" if label else ""
        return None, f"JSON file too large{context} ({size} bytes): {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), None
    except Exception as exc:
        return None, f"failed to read JSON {path}: {exc}"
