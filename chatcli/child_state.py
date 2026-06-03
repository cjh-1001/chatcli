"""Child-window state containers."""

from dataclasses import dataclass, field
from datetime import datetime
import io
import threading
from typing import Any


@dataclass
class ChildWindow:
    name: str
    agent: Any
    buffer: io.StringIO
    status: str = "idle"
    task: str = ""
    result: str = ""
    error: str = ""
    summary: str = ""
    notes_path: str = ""
    completed_at: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = ""
    thread: threading.Thread | None = None

