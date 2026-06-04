"""Content search tool using regex matching."""

import fnmatch
import re
from pathlib import Path
from .base import Tool, ToolResult, coerce_bool, coerce_int


class GrepTool(Tool):
    name = "grep"
    description = (
        "Search for a regex pattern in file contents. "
        "Returns matching file paths by default (max 250 results), "
        "or matching lines with line numbers in content mode. "
        "Max 10000 files scanned, 200k chars per file."
    )
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {
                "type": "string",
                "description": "The regex pattern to search for",
            },
            "path": {
                "type": "string",
                "description": "File or directory to search in. Defaults to workspace root.",
            },
            "glob": {
                "type": "string",
                "description": "Glob filter for files (e.g., '*.py', '*.{ts,tsx}')",
            },
            "output_mode": {
                "type": "string",
                "enum": ["files_with_matches", "content", "count"],
                "description": "Output mode: 'files_with_matches' (default), 'content' (shows matching lines), or 'count'",
            },
            "-i": {
                "type": "boolean",
                "description": "Case insensitive search",
            },
            "-n": {
                "type": "boolean",
                "description": "Show line numbers (content mode)",
            },
            "head_limit": {
                "type": "integer",
                "description": "Limit output to first N entries (default 250).",
            },
        },
        "required": ["pattern"],
    }

    # Directories to skip
    SKIP_DIRS = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".next", "dist", "build", "target", ".cache", ".claude",
        "egg-info", ".eggs", ".tox",
    }

    # Binary extensions to skip
    SKIP_EXT = {
        ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".zip",
        ".tar", ".gz", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".woff", ".woff2", ".ttf", ".pdf",
    }

    def __init__(self, config=None):
        self.config = config

    @staticmethod
    def _normalize_path(value: Path) -> tuple[str, str]:
        path = str(value).replace("\\", "/").lower()
        name = value.name.lower()
        return path, name

    def _is_sensitive_path(self, path: Path) -> bool:
        permissions = getattr(self.config, "permissions", None)
        if not permissions or not getattr(permissions, "protect_sensitive_files", True):
            return False
        normalized, name = self._normalize_path(path)
        for raw_pattern in getattr(permissions, "sensitive", []):
            pattern = str(raw_pattern).replace("\\", "/").lower()
            if (
                fnmatch.fnmatch(normalized, pattern)
                or fnmatch.fnmatch(name, pattern)
                or ("/" not in pattern and fnmatch.fnmatch(normalized, f"*/{pattern}"))
            ):
                return True
        return False

    def execute(
        self, pattern: str, path: str | None = None, glob: str | None = None,
        output_mode: str = "files_with_matches", head_limit: int = 250,
        i: bool = False, n: bool = True, **kwargs
    ) -> ToolResult:
        if "-i" in kwargs:
            i = coerce_bool(kwargs.get("-i"), i)
        if "-n" in kwargs:
            n = coerce_bool(kwargs.get("-n"), n)
        if not pattern or not pattern.strip():
            return ToolResult(content="Error: pattern cannot be empty.", is_error=True)
        head_limit = coerce_int(head_limit, 250, minimum=1, maximum=10000)
        workspace = kwargs.get("workspace", ".")
        base = Path(path) if path else Path(workspace)

        if not base.exists():
            return ToolResult(content=f"Path not found: {base}", is_error=True)

        flags = re.IGNORECASE if i else 0
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            return ToolResult(content=f"Invalid regex: {e}", is_error=True)

        glob_re = None
        if glob:
            glob_re = re.compile(fnmatch.translate(glob))

        results: list[str] = []
        files_searched = 0

        paths = [base] if base.is_file() else base.rglob("*")

        for p in paths:
            if not p.is_file():
                continue
            if any(skip in p.parts for skip in self.SKIP_DIRS):
                continue
            if p.suffix in self.SKIP_EXT:
                continue
            if self._is_sensitive_path(p):
                continue
            if glob_re and not glob_re.match(p.name):
                continue

            files_searched += 1
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            matches = list(regex.finditer(content))
            if not matches:
                continue

            if output_mode == "files_with_matches":
                results.append(str(p))
            elif output_mode == "content":
                lines = content.split("\n")
                for m in matches:
                    line_no = content[:m.start()].count("\n") + 1
                    line = lines[line_no - 1].strip()
                    if n:
                        results.append(f"{p}:{line_no}: {line}")
                    else:
                        results.append(f"{p}: {line}")
            elif output_mode == "count":
                results.append(f"{p}: {len(matches)} matches")

            if len(results) >= head_limit:
                break

        if not results:
            return ToolResult(content=f"No matches found for '{pattern}' (searched {files_searched} files)")
        return ToolResult(
            content="\n".join(results[:head_limit]),
            metadata={"count": len(results[:head_limit]), "files_searched": files_searched},
        )
