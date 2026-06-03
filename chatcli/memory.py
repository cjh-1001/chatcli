"""Persistent context memory — like Claude Code's memory system.

Memories are stored as markdown files in .chatcli/memory/, each with
YAML frontmatter. An index file MEMORY.md lists all memories.

Loaded automatically into the system prompt each session.
The model can create memories via write_file or the /memory command.
"""

import re
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional


def _memory_dir(workspace: str) -> Path:
    return Path(workspace) / ".chatcli" / "memory"


def _index_path(workspace: str) -> Path:
    return _memory_dir(workspace) / "MEMORY.md"


# ── Read ──────────────────────────────────────────────────────────


def load_memories(workspace: str) -> str:
    """Load all memories and return a formatted context block.

    Returns empty string if no memories exist.
    """
    mem_dir = _memory_dir(workspace)
    if not mem_dir.exists():
        return ""

    memories = []
    for f in sorted(mem_dir.glob("*.md")):
        if f.name == "MEMORY.md":
            continue
        try:
            content = f.read_text(encoding="utf-8")
            parsed = _parse_memory(content)
            if parsed:
                parsed["file"] = f.name
                memories.append(parsed)
        except Exception as e:
            import sys
            print(f"[chatcli] Warning: failed to load memory {f.name}: {e}", file=sys.stderr)
            continue

    if not memories:
        return ""

    lines = ["## Memory"]
    lines.append("The following facts and decisions have been saved from previous sessions:")
    lines.append("")
    for m in memories:
        name = m.get("title", m.get("file", "untitled"))
        desc = m.get("description", "")
        body = m.get("body", "").strip()
        tag = f"type={m.get('type', 'note')}"
        lines.append(f"### {name}")
        if desc:
            lines.append(f"> {desc}  [{tag}]")
        if body:
            lines.append("")
            lines.append(body)
        lines.append("")

    return "\n".join(lines)


def _parse_memory(raw: str) -> Optional[dict]:
    """Parse a memory file with YAML frontmatter."""
    # Match YAML frontmatter between --- markers
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)", raw, re.DOTALL)
    if not m:
        # No frontmatter — use entire file as body
        body = raw.strip()
        if not body:
            return None
        # Derive title from first line
        first_line = body.split("\n")[0].lstrip("#").strip()
        return {
            "title": first_line[:60],
            "body": body,
            "type": "note",
            "description": "",
        }

    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except Exception:
        meta = {}

    body = m.group(2).strip()
    title = meta.get("title") or meta.get("name", body.split("\n")[0].lstrip("#").strip()[:60])

    return {
        "title": title,
        "description": meta.get("description", ""),
        "type": meta.get("type", "note"),
        "body": body,
    }


# ── Write ─────────────────────────────────────────────────────────


def save_memory(workspace: str, filename: str, content: str) -> Path:
    """Save a memory file. Creates .chatcli/memory/ if needed."""
    mem_dir = _memory_dir(workspace)
    mem_dir.mkdir(parents=True, exist_ok=True)

    # Ensure .md extension
    if not filename.endswith(".md"):
        filename += ".md"

    # Sanitize filename
    filename = re.sub(r"[^\w\-.]", "-", filename)
    filepath = mem_dir / filename
    filepath.write_text(content, encoding="utf-8")

    # Rebuild index
    _rebuild_index(workspace)

    return filepath


def delete_memory(workspace: str, filename: str) -> bool:
    """Delete a memory file. Returns True if it existed."""
    filepath = _memory_dir(workspace) / filename
    if filepath.exists():
        filepath.unlink()
        _rebuild_index(workspace)
        return True
    return False


def list_memories(workspace: str) -> list[dict]:
    """List all memories with metadata."""
    mem_dir = _memory_dir(workspace)
    if not mem_dir.exists():
        return []

    results = []
    for f in sorted(mem_dir.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.name == "MEMORY.md":
            continue
        try:
            content = f.read_text(encoding="utf-8")
            parsed = _parse_memory(content)
            results.append({
                "file": f.name,
                "title": parsed.get("title", f.stem) if parsed else f.stem,
                "type": parsed.get("type", "note") if parsed else "note",
                "description": parsed.get("description", "") if parsed else "",
                "size": len(content),
                "mtime": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        except Exception as e:
            print(f"[chatcli] Warning: failed to list memory {f.name}: {e}", file=sys.stderr)
            continue

    return results


def _rebuild_index(workspace: str):
    """Rebuild MEMORY.md index from existing memory files."""
    memories = list_memories(workspace)
    lines = ["# Memory Index", ""]
    lines.append(f"_{len(memories)} memories — auto-generated_")
    lines.append("")

    for m in memories:
        lines.append(f"- [{m['title']}]({m['file']}) — {m.get('description', '')}")
        if m.get('type') != 'note':
            lines[-1] += f" `[{m['type']}]`"

    (_memory_dir(workspace) / "MEMORY.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
