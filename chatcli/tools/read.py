"""File reading tool."""

from pathlib import Path
from .base import Tool, ToolResult
from ._http_utils import MAX_FILE_SIZE


class ReadTool(Tool):
    name = "read_file"
    description = (
        "Read a file from the local filesystem. "
        "Returns the file content with line numbers (1-indexed). "
        "Use offset and limit for long files. Whole-file reads are capped at 5MB. "
        "Output truncated at 50000 characters."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the file to read",
            },
            "offset": {
                "type": "integer",
                "description": "Line number to start reading from (1-indexed)",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of lines to read",
            },
        },
        "required": ["file_path"],
    }

    def execute(self, file_path: str, offset: int | None = None, limit: int | None = None, **kwargs) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if path.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)

        if offset is not None and offset < 1:
            return ToolResult(content="Error: offset must be >= 1.", is_error=True)
        if limit is not None and limit < 1:
            return ToolResult(content="Error: limit must be >= 1.", is_error=True)
        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE and (offset is None or limit is None):
            return ToolResult(
                content=(
                    f"File too large ({file_size} bytes). "
                    "Use both offset and limit to read a bounded line range."
                ),
                is_error=True,
            )

        try:
            if file_size > MAX_FILE_SIZE:
                lines = []
                start_line = offset or 1
                end_line = start_line + (limit or 0) - 1
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line_no, line in enumerate(f, start=1):
                        if line_no < start_line:
                            continue
                        if line_no > end_line:
                            break
                        lines.append(line)
                total_lines = None
            else:
                with open(path, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                total_lines = len(lines)
        except Exception as e:
            return ToolResult(content=f"Error reading file: {e}", is_error=True)

        start = (offset - 1) if offset else 0
        if file_size > MAX_FILE_SIZE:
            selected = lines
        else:
            end = start + limit if limit else len(lines)
            selected = lines[start:end]

        numbered = []
        for i, line in enumerate(selected, start=start + 1):
            numbered.append(f"{i}\t{line.rstrip()}")

        result = "\n".join(numbered)
        if len(result) > 50000:
            result = result[:50000] + "\n... (truncated)"

        return ToolResult(content=result, metadata={"lines": len(selected), "total_lines": total_lines})
