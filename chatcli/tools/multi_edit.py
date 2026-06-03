"""Atomic multi-replacement edit tool."""

from pathlib import Path
from .base import Tool, ToolResult
from ..checkpoint import backup_file
from ._http_utils import MAX_FILE_SIZE


class MultiEditTool(Tool):
    name = "multi_edit"
    description = (
        "Apply multiple exact string replacements to one existing file atomically. "
        "Each old_string must be unique at the time it is applied. "
        "Use this when several edits belong together in the same file."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the file to modify",
            },
            "edits": {
                "type": "array",
                "description": "Ordered replacements to apply atomically.",
                "items": {
                    "type": "object",
                    "properties": {
                        "old_string": {
                            "type": "string",
                            "description": "The exact text to replace",
                        },
                        "new_string": {
                            "type": "string",
                            "description": "The replacement text",
                        },
                    },
                    "required": ["old_string", "new_string"],
                },
            },
        },
        "required": ["file_path", "edits"],
    }

    def execute(self, file_path: str, edits: list[dict], **kwargs) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if path.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)
        if path.stat().st_size > MAX_FILE_SIZE:
            return ToolResult(
                content=f"Error: file too large ({path.stat().st_size} bytes). Maximum is 5 MB.",
                is_error=True,
            )
        if not isinstance(edits, list) or not edits:
            return ToolResult(content="Error: edits must be a non-empty list.", is_error=True)
        if len(edits) > 50:
            return ToolResult(content="Error: too many edits. Maximum is 50.", is_error=True)

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            return ToolResult(content=f"Error reading file: {e}", is_error=True)

        new_content = content
        for idx, edit in enumerate(edits, 1):
            old_string = edit.get("old_string", "")
            new_string = edit.get("new_string", "")
            if not old_string:
                return ToolResult(content=f"Error: edit #{idx} old_string cannot be empty.", is_error=True)
            count = new_content.count(old_string)
            if count == 0:
                return ToolResult(content=f"Error: edit #{idx} old_string not found.", is_error=True)
            if count > 1:
                return ToolResult(
                    content=(
                        f"Error: edit #{idx} old_string appears {count} times. "
                        "Include more surrounding context to make it unique."
                    ),
                    is_error=True,
                )
            new_content = new_content.replace(old_string, new_string, 1)

        if new_content == content:
            return ToolResult(content="No changes: replacements produced identical content.")

        try:
            backup_id = backup_file(path)
        except Exception:
            backup_id = None

        try:
            path.write_text(new_content, encoding="utf-8")
        except Exception as e:
            return ToolResult(content=f"Error writing file: {e}", is_error=True)

        msg = f"Applied {len(edits)} edits to {file_path}"
        if backup_id:
            msg += f" (backup: {backup_id})"
        return ToolResult(
            content=msg,
            metadata={"path": str(path), "edits": len(edits), "backup": backup_id},
        )
