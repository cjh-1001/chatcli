"""Internal chatcli automation request tools."""

import json
from datetime import datetime
from pathlib import Path

from .base import Tool, ToolResult


class ChatcliAutoRequestTool(Tool):
    name = "chatcli_auto_request"
    description = (
        "Request a main-window chatcli automation after the current model turn. "
        "Use when auto mode is enabled and you need the CLI to spawn a child task, "
        "record or apply a reusable skill improvement, or clear chat history after "
        "the current turn. This records a structured request; the UI processes it."
    )
    parameters = {
        "type": "object",
        "properties": {
            "request_type": {
                "type": "string",
                "enum": ["child_task", "skill_improvement", "history_clear"],
                "description": "Automation request type.",
            },
            "name": {
                "type": "string",
                "description": "Child task name or short request name.",
            },
            "task": {
                "type": "string",
                "description": "Child task prompt when request_type is child_task.",
            },
            "skill_name": {
                "type": "string",
                "description": "Skill to improve when request_type is skill_improvement.",
            },
            "note": {
                "type": "string",
                "description": "Reusable lesson or improvement note.",
            },
            "apply": {
                "type": "boolean",
                "description": "For skill_improvement, spawn a child to apply the update. Default false.",
            },
            "reason": {
                "type": "string",
                "description": "Why this automation is useful now.",
            },
        },
        "required": ["request_type", "reason"],
    }

    def execute(
        self,
        request_type: str,
        reason: str,
        name: str = "",
        task: str = "",
        skill_name: str = "",
        note: str = "",
        apply: bool = False,
        workspace: str = ".",
        **kwargs,
    ) -> ToolResult:
        path = Path(workspace) / ".chatcli" / "auto_requests.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "request_type": request_type,
            "name": name,
            "task": task,
            "skill_name": skill_name,
            "note": note,
            "apply": bool(apply),
            "reason": reason,
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        return ToolResult(
            content=f"Auto request recorded: {request_type}",
            metadata={"path": str(path), "request_type": request_type},
        )
