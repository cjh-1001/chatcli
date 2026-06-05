"""Read-only Git inspection tools."""

import subprocess
from pathlib import Path
from .base import Tool, ToolResult, get_workspace


def _run_git(args: list[str], cwd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _repo_root(cwd: str) -> str | None:
    try:
        proc = _run_git(["rev-parse", "--show-toplevel"], cwd, timeout=5)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


class GitStatusTool(Tool):
    name = "git_status"
    description = (
        "Inspect the current Git working tree. Returns branch, short status, "
        "and staged/unstaged diff stats. Read-only."
    )
    parameters = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    def execute(self, **kwargs) -> ToolResult:
        workspace = str(Path(get_workspace(kwargs)).resolve())
        root = _repo_root(workspace)
        if not root:
            return ToolResult(content="Error: not inside a Git repository.", is_error=True)

        status = _run_git(["status", "--short", "--branch"], root)
        unstaged = _run_git(["diff", "--stat"], root)
        staged = _run_git(["diff", "--cached", "--stat"], root)

        parts = ["# Git Status", "", status.stdout.strip() or "(clean)"]
        if staged.stdout.strip():
            parts.extend(["", "## Staged diff stat", staged.stdout.strip()])
        if unstaged.stdout.strip():
            parts.extend(["", "## Unstaged diff stat", unstaged.stdout.strip()])

        changed = [
            line for line in status.stdout.splitlines()
            if line.strip() and not line.startswith("##")
        ]
        return ToolResult(
            content="\n".join(parts),
            metadata={"repo": root, "changed": len(changed)},
        )


class GitDiffTool(Tool):
    name = "git_diff"
    description = (
        "Show Git diff for the working tree or staged changes. Read-only. "
        "Optionally restrict to a path."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Optional file or directory path to diff.",
            },
            "staged": {
                "type": "boolean",
                "description": "Show staged diff instead of unstaged diff.",
            },
            "max_chars": {
                "type": "integer",
                "description": "Maximum diff characters to return. Default 50000.",
            },
        },
        "required": [],
    }

    def execute(
        self, path: str | None = None, staged: bool = False,
        max_chars: int = 50000, **kwargs
    ) -> ToolResult:
        workspace = str(Path(get_workspace(kwargs)).resolve())
        root = _repo_root(workspace)
        if not root:
            return ToolResult(content="Error: not inside a Git repository.", is_error=True)

        args = ["diff"]
        if staged:
            args.append("--cached")
        if path:
            args.extend(["--", path])

        proc = _run_git(args, root, timeout=20)
        if proc.returncode != 0:
            return ToolResult(content=proc.stderr.strip() or "Error: git diff failed.", is_error=True)

        diff = proc.stdout
        if not diff.strip():
            return ToolResult(content="(no diff)", metadata={"repo": root, "staged": staged, "truncated": False})

        max_chars = min(max(1000, int(max_chars)), 200000)
        truncated = len(diff) > max_chars
        if truncated:
            diff = diff[:max_chars] + "\n... (diff truncated)"

        return ToolResult(
            content=diff,
            metadata={
                "repo": root,
                "staged": staged,
                "path": path or "",
                "chars": len(proc.stdout),
                "truncated": truncated,
            },
        )
