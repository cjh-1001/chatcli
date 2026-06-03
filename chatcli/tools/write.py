"""File writing tool."""

import fnmatch
from pathlib import Path
from .base import Tool, ToolResult
from ..checkpoint import backup_file
from ._http_utils import MAX_FILE_SIZE


class WriteTool(Tool):
    name = "write_file"
    description = (
        "Write content to a file. Creates parent directories if needed. "
        "Backs up existing files before overwriting. Max content: 5MB "
        f"({MAX_FILE_SIZE // (1024*1024)} MB). For temporary scripts, use "
        ".chatcli/tmp/scratch.py and iterate on that file instead of creating "
        "multiple root-level samples."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the file to write",
            },
            "content": {
                "type": "string",
                "description": "The content to write to the file",
            },
        },
        "required": ["file_path", "content"],
    }

    _TEMP_SCRIPT_PATTERNS = (
        "solve*.py", "solver*.py", "tmp*.py", "scratch*.py",
        "poc*.py", "probe*.py", "explore*.py", "test.py", "test[0-9]*.py",
    )

    def __init__(self, config=None):
        self.config = config

    def _temp_script_policy_error(self, path: Path, workspace: str) -> str | None:
        if not getattr(self.config, "enforce_temp_script_iteration", True):
            return None
        if path.exists():
            return None
        try:
            root = Path(workspace or ".").resolve()
            target = path.resolve()
        except Exception:
            return None
        if target.parent != root:
            return None
        name = target.name.lower()
        if not any(fnmatch.fnmatch(name, pattern) for pattern in self._TEMP_SCRIPT_PATTERNS):
            return None
        scratch_dir = getattr(self.config, "temp_script_dir", ".chatcli/tmp")
        scratch_name = getattr(self.config, "temp_script_name", "scratch.py")
        scratch = root / scratch_dir / scratch_name
        return (
            "Error: temporary script sprawl blocked. "
            f"Use {scratch} and iterate on that same file with edit_file or multi_edit, "
            "instead of creating another root-level sample script."
        )

    def execute(self, file_path: str, content: str, **kwargs) -> ToolResult:
        if len(content.encode('utf-8')) > MAX_FILE_SIZE:
            return ToolResult(
                content=f"Error: content too large ({len(content.encode('utf-8'))} bytes). Maximum is 5 MB.",
                is_error=True,
            )
        path = Path(file_path)
        policy_error = self._temp_script_policy_error(path, kwargs.get("workspace", "."))
        if policy_error:
            return ToolResult(content=policy_error, is_error=True)
        was_existing = path.exists()
        backup_id = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if was_existing:
                try:
                    backup_id = backup_file(path)
                except Exception:
                    backup_id = None  # Non-fatal — proceed without backup
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            size = path.stat().st_size
            msg = f"Written {size} bytes to {file_path}"
            if was_existing:
                msg += f" (backup: {backup_id})"
            return ToolResult(
                content=msg,
                metadata={"path": str(path), "size": size, "backup": backup_id if was_existing else None},
            )
        except Exception as e:
            return ToolResult(content=f"Error writing file: {e}", is_error=True)
