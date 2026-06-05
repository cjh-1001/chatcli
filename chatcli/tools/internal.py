"""Internal chatcli automation request tools."""

import json
from datetime import datetime
from pathlib import Path

from .base import Tool, ToolResult, coerce_bool


class ChatcliAutoRequestTool(Tool):
    name = "chatcli_auto_request"
    description = (
        "Queue a main-window automation to run after the current turn. "
        "For malware/reverse analysis, use `request_type: child_task` to spawn "
        "parallel child windows for independent subtasks. Examples:\n"
        "- Decode XOR/base64 strings: {request_type:child_task, name:decode-strings, "
        "task:'Extract and decode all encoded strings from <path>, list IPs/domains'}\n"
        "- External tool scan: {request_type:child_task, name:capa-scan, "
        "task:'Run external_static_analyze on <path> and summarize capa/FLOSS findings'}\n"
        "- IDA deep-dive: {request_type:child_task, name:ida-focus, "
        "task:'Run ida_analyze on <path> targeting function at 0xADDR'}\n"
        "Children run in background; main window continues without waiting. "
        "Use `request_type: skill_improvement` to record reusable lessons. "
        "Use `request_type: history_clear` to clear context after archiving."
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
        _chatcli_task_id: str = "",
        _chatcli_agent_role: str = "",
        _chatcli_child_name: str = "",
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
            "apply": coerce_bool(apply, False),
            "reason": reason,
            "task_id": _chatcli_task_id,
            "source_role": _chatcli_agent_role,
            "source_child": _chatcli_child_name,
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        return ToolResult(
            content=f"Auto request recorded: {request_type}",
            metadata={"path": str(path), "request_type": request_type},
        )
