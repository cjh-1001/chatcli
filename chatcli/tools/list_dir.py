"""Directory listing tool."""

from pathlib import Path
from datetime import datetime
from .base import Tool, ToolResult


class ListDirTool(Tool):
    name = "list_dir"
    description = "List files and directories in a given path (max 200 entries)."
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "The directory to list. Defaults to workspace root.",
            },
        },
        "required": [],
    }

    def execute(self, path: str | None = None, **kwargs) -> ToolResult:
        workspace = kwargs.get("workspace", ".")
        target = Path(path) if path else Path(workspace)

        if not target.exists():
            return ToolResult(content=f"Path not found: {target}", is_error=True)
        if not target.is_dir():
            return ToolResult(content=f"Not a directory: {target}", is_error=True)

        try:
            entries = sorted(target.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            return ToolResult(content=f"Permission denied: {target}", is_error=True)

        lines = []
        for entry in entries[:200]:
            st = None
            try:
                st = entry.stat()
                mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            except OSError:
                mtime = "?"
            type_char = "d" if entry.is_dir() else "f"
            if entry.is_file():
                size = f"{st.st_size:>10}" if st else "         ?"
            else:
                size = "         -"
            lines.append(f"{type_char} {mtime} {size}  {entry.name}")

        if len(entries) > 200:
            lines.append(f"... ({len(entries) - 200} more entries)")

        return ToolResult(
            content=f"Contents of {target}:\n" + "\n".join(lines) if lines else f"{target} is empty",
            metadata={"count": len(entries)},
        )
