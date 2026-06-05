"""Child-window state containers."""

from dataclasses import dataclass, field
from datetime import datetime
import io
import time
import threading
from typing import Any


@dataclass
class ChildWindow:
    name: str
    agent: Any
    buffer: io.StringIO
    status: str = "idle"          # idle | running | done | blocked | error | timeout
    task: str = ""
    result: str = ""
    error: str = ""
    summary: str = ""
    notes_path: str = ""
    completed_at: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = ""
    thread: threading.Thread | None = None
    task_id: str = ""
    # Lifecycle management
    started_at: float = 0.0       # time.monotonic() when run started
    timeout_seconds: float = 600.0  # default 10 min timeout
    _timeout_timer: threading.Timer | None = field(default=None, repr=False)
    # Deduplication: content hash of the task description
    task_hash: str = ""


# ── Child concurrency limits ──────────────────────────────────────

# Maximum concurrent running children across all tasks.
MAX_CONCURRENT_CHILDREN = 8

# Maximum total children (running + completed) before old completed
# children are auto-cleaned.
MAX_TOTAL_CHILDREN = 24

# Auto-clean completed children older than this many seconds.
COMPLETED_CHILD_TTL = 3600  # 1 hour
