"""Exact string replacement edit tool (like Claude Code's Edit)."""

from pathlib import Path
from .base import Tool, ToolResult
from ..checkpoint import backup_file
from ._http_utils import MAX_FILE_SIZE


class EditTool(Tool):
    name = "edit_file"
    description = (
        "Perform exact string replacements in an existing file. "
        "Usage: provide old_string (exact text to replace) and new_string (replacement text). "
        "The old_string must be unique in the file. Max file size: 5MB. Backs up the file before modification."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the file to modify",
            },
            "old_string": {
                "type": "string",
                "description": "The exact text to replace",
            },
            "new_string": {
                "type": "string",
                "description": "The replacement text",
            },
        },
        "required": ["file_path", "old_string", "new_string"],
    }

    def execute(self, file_path: str, old_string: str, new_string: str, **kwargs) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if not old_string:
            return ToolResult(content="Error: old_string cannot be empty.", is_error=True)

        # Reject files over limit (consistent with other tools)
        if path.stat().st_size > MAX_FILE_SIZE:
            return ToolResult(
                content=f"Error: file too large ({path.stat().st_size} bytes). Maximum is 5 MB.",
                is_error=True,
            )

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            return ToolResult(content=f"Error reading file: {e}", is_error=True)

        count = content.count(old_string)
        if count == 0:
            return ToolResult(content="Error: old_string not found in file.", is_error=True)
        if count > 1:
            return ToolResult(
                content=f"Error: old_string appears {count} times in the file. "
                "Make it unique by including more surrounding context.",
                is_error=True,
            )

        new_content = content.replace(old_string, new_string, 1)
        try:
            backup_id = backup_file(path)
        except Exception:
            backup_id = None  # Non-fatal — proceed without backup
        try:
            path.write_text(new_content, encoding="utf-8")
        except Exception as e:
            return ToolResult(content=f"Error writing file: {e}", is_error=True)

        msg = f"Successfully edited {file_path}"
        if backup_id:
            msg += f" (backup: {backup_id})"
        return ToolResult(
            content=msg,
            metadata={"path": str(path), "backup": backup_id},
        )
