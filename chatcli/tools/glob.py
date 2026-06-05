"""File pattern matching tool."""

from pathlib import Path
from .base import Tool, ToolResult, get_workspace


class GlobTool(Tool):
    name = "glob"
    description = "Find files matching a glob pattern (e.g., '**/*.py', 'src/**/*.ts'). Returns matching file paths sorted by modification time (max 200 files)."
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {
                "type": "string",
                "description": "The glob pattern to match files against",
            },
            "path": {
                "type": "string",
                "description": "The directory to search in. Defaults to the workspace root.",
            },
        },
        "required": ["pattern"],
    }

    def execute(self, pattern: str, path: str | None = None, **kwargs) -> ToolResult:
        if not pattern or not pattern.strip():
            return ToolResult(content="Error: pattern cannot be empty.", is_error=True)
        workspace = get_workspace(kwargs)
        base = Path(path) if path else Path(workspace)
        if not base.exists():
            return ToolResult(content=f"Directory not found: {base}", is_error=True)

        try:
            matches = sorted(base.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        except Exception as e:
            return ToolResult(content=f"Glob error: {e}", is_error=True)

        # Filter to files only by default
        files = [str(m) for m in matches[:200] if m.is_file()]
        if not files:
            return ToolResult(content=f"No files matched pattern '{pattern}' in {base}")
        return ToolResult(content="\n".join(files), metadata={"count": len(files)})
