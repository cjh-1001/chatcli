"""Child-window local summaries and durable records."""

from datetime import datetime
import json
from pathlib import Path
import re

from .child_state import ChildWindow


class ChildRecordMixin:
    def _children_dir(self) -> Path:
        return Path(self.config.workspace) / ".chatcli" / "children"
    def _child_notes_path(self, child_name: str) -> Path:
        return self._children_dir() / f"{self._safe_child_name(child_name)}.md"
    def _shorten_child_text(self, text: str, limit: int = 160) -> str:
        cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
        if len(cleaned) <= limit:
            return cleaned
        return cleaned[: max(0, limit - 3)].rstrip() + "..."
    def _clean_child_lines(self, text: str) -> list[str]:
        lines = []
        for raw in str(text or "").splitlines():
            line = re.sub(r"\s+", " ", raw).strip()
            if not line:
                continue
            if line.lower().startswith(("usage:", "provider:", "model:", "api base:")):
                continue
            lines.append(line)
        return lines
    def _summarize_child_locally(self, child: ChildWindow) -> str:
        if child.error:
            return self._shorten_child_text(f"error: {child.error}", 220)
        lines = self._clean_child_lines(child.result)
        if not lines:
            lines = self._clean_child_lines(child.buffer.getvalue())[-20:]
        if not lines:
            return "(no output)"
        priority = (
            "child complete", "child blocked", "child error", "task complete",
            "summary", "finding", "findings", "blocker", "blocked", "error",
            "failed", "done", "changed", "modified",
            "结论", "总结", "发现", "阻塞", "失败", "完成", "修改", "验证",
        )
        picked = []
        for line in lines:
            lowered = line.lower()
            if any(key in lowered for key in priority):
                picked.append(line)
            if len(picked) >= 4:
                break
        if not picked:
            picked = lines[-4:]
        return self._shorten_child_text(" | ".join(picked), 420)
    def _write_child_record(self, child: ChildWindow) -> None:
        with self._children_lock:
            notes_path = self._child_notes_path(child.name)
            child.notes_path = str(notes_path)
            notes_path.parent.mkdir(parents=True, exist_ok=True)
            output_tail = "\n".join(child.buffer.getvalue().splitlines()[-80:])
            body = (
                f"# Child {child.name}\n\n"
                f"- Status: {child.status}\n"
                f"- Created: {child.created_at}\n"
                f"- Updated: {child.updated_at or child.created_at}\n"
                f"- Completed: {child.completed_at or ''}\n"
                f"- Task: {child.task}\n"
                f"- Summary: {child.summary or ''}\n\n"
                "## Result\n\n"
                f"{child.result or '(no final result yet)'}\n\n"
                "## Error\n\n"
                f"{child.error or '(none)'}\n\n"
                "## Output Tail\n\n"
                "```text\n"
                f"{output_tail}\n"
                "```\n"
            )
            notes_path.write_text(body, encoding="utf-8")

            index_path = notes_path.parent / "index.json"
            records = {}
            if index_path.exists():
                try:
                    loaded = json.loads(index_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        records = loaded
                except Exception:
                    records = {}
            records[child.name] = {
                "name": child.name,
                "status": child.status,
                "task": child.task,
                "summary": child.summary,
                "created_at": child.created_at,
                "updated_at": child.updated_at or child.created_at,
                "completed_at": child.completed_at,
                "notes_path": str(notes_path),
            }
            tmp = index_path.with_name(index_path.name + ".tmp")
            tmp.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(index_path)
    def _mark_child_finished(
        self,
        child: ChildWindow,
        status: str,
        result: str = "",
        error: str = "",
    ) -> None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._children_lock:
            child.result = result or ""
            child.error = error or ""
            child.status = status
            child.updated_at = now
            child.completed_at = now
            child.summary = self._summarize_child_locally(child)
            self._write_child_record(child)

