"""Safe byte-level binary patching for authorized local files."""

import hashlib
from pathlib import Path

from .base import Tool, ToolResult, coerce_bool, coerce_int
from ..checkpoint import backup_file


MAX_PATCH_FILE_SIZE = 200 * 1024 * 1024


def _parse_hex(value: str, name: str) -> bytes:
    if value is None:
        return b""
    cleaned = "".join(str(value).replace("0x", "").replace("\\x", "").split())
    if not cleaned:
        return b""
    if len(cleaned) % 2:
        raise ValueError(f"{name} must contain an even number of hex digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"{name} is not valid hex: {e}") from e


def _parse_int(value, name: str) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "")
    try:
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError as e:
        raise ValueError(f"{name} must be a decimal integer or 0x-prefixed hex offset, got {value!r}") from e


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _default_output_path(path: Path) -> Path:
    candidate = path.with_name(f"{path.stem}.patched{path.suffix}")
    if not candidate.exists():
        return candidate
    for i in range(2, 1000):
        candidate = path.with_name(f"{path.stem}.patched{i}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError("Could not choose a unique patched output path")


class BinaryPatchTool(Tool):
    name = "binary_patch"
    description = (
        "Patch bytes in an authorized local binary without executing it. "
        "Supports replace_at_offset and find_replace modes using hex strings. "
        "By default writes a patched copy; in_place=true requires confirmation "
        "and backs up the original first. Does not assist with piracy, license "
        "bypass, credential theft, or unauthorized access."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the binary to patch.",
            },
            "mode": {
                "type": "string",
                "enum": ["replace_at_offset", "find_replace"],
                "description": "Patch mode.",
            },
            "offset": {
                "type": ["integer", "string"],
                "description": "File offset for replace_at_offset mode. Accepts decimal or 0x-prefixed hex.",
            },
            "old_hex": {
                "type": "string",
                "description": "Expected old bytes as hex. Required for find_replace; optional verification for offset mode.",
            },
            "new_hex": {
                "type": "string",
                "description": "Replacement bytes as hex. Must be same length as old_hex or verified offset span.",
            },
            "occurrence": {
                "type": "integer",
                "description": "1-based occurrence to patch in find_replace mode. Default 1.",
            },
            "output_path": {
                "type": "string",
                "description": "Optional patched copy path. Ignored when in_place=true.",
            },
            "in_place": {
                "type": "boolean",
                "description": "Patch the original file instead of writing a copy. Default false.",
            },
            "expected_sha256": {
                "type": "string",
                "description": "Optional expected SHA256 of the original before patching.",
            },
        },
        "required": ["file_path", "mode", "new_hex"],
    }

    def execute(
        self,
        file_path: str,
        mode: str,
        new_hex: str,
        offset: int | str | None = None,
        old_hex: str = "",
        occurrence: int = 1,
        output_path: str = "",
        in_place: bool = False,
        expected_sha256: str = "",
        **kwargs,
    ) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if path.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)
        size = path.stat().st_size
        if size > MAX_PATCH_FILE_SIZE:
            return ToolResult(
                content=f"Error: file too large ({size} bytes). Maximum is {MAX_PATCH_FILE_SIZE} bytes.",
                is_error=True,
            )

        try:
            old = _parse_hex(old_hex, "old_hex")
            new = _parse_hex(new_hex, "new_hex")
        except ValueError as e:
            return ToolResult(content=f"Error: {e}", is_error=True)
        if not new:
            return ToolResult(content="Error: new_hex cannot be empty.", is_error=True)

        data = path.read_bytes()
        before_sha = _sha256(data)
        in_place = coerce_bool(in_place, False)
        occurrence = coerce_int(occurrence, 1, minimum=1, maximum=1000)
        if expected_sha256 and expected_sha256.lower() != before_sha.lower():
            return ToolResult(
                content=(
                    "Error: expected_sha256 does not match original. "
                    f"expected={expected_sha256} actual={before_sha}"
                ),
                is_error=True,
            )

        mode = mode.strip().lower()
        if mode == "replace_at_offset":
            try:
                parsed_offset = _parse_int(offset, "offset") if offset is not None else -1
            except ValueError as e:
                return ToolResult(content=f"Error: {e}", is_error=True)
            if parsed_offset < 0:
                return ToolResult(content="Error: offset must be a non-negative integer.", is_error=True)
            if parsed_offset + len(new) > len(data):
                return ToolResult(content="Error: patch extends beyond end of file.", is_error=True)
            if old:
                current = data[parsed_offset:parsed_offset + len(old)]
                if current != old:
                    return ToolResult(
                        content=(
                            "Error: old_hex verification failed at offset "
                            f"0x{parsed_offset:x}. actual={current.hex(' ')}"
                        ),
                        is_error=True,
                    )
                if len(old) != len(new):
                    return ToolResult(
                        content="Error: old_hex and new_hex must be the same length.",
                        is_error=True,
                    )
            patch_offset = parsed_offset
            patch_len = len(new)
        elif mode == "find_replace":
            if not old:
                return ToolResult(content="Error: old_hex is required for find_replace mode.", is_error=True)
            if len(old) != len(new):
                return ToolResult(content="Error: old_hex and new_hex must be the same length.", is_error=True)
            matches = []
            start = 0
            while True:
                idx = data.find(old, start)
                if idx < 0:
                    break
                matches.append(idx)
                start = idx + 1
                if len(matches) > max(occurrence, 1000):
                    break
            if len(matches) < occurrence:
                return ToolResult(
                    content=f"Error: old_hex occurrence {occurrence} not found. matches={len(matches)}",
                    is_error=True,
                )
            patch_offset = matches[occurrence - 1]
            patch_len = len(old)
        else:
            return ToolResult(
                content="Error: mode must be replace_at_offset or find_replace.",
                is_error=True,
            )

        patched = bytearray(data)
        patched[patch_offset:patch_offset + patch_len] = new
        after_sha = _sha256(patched)
        if after_sha == before_sha:
            return ToolResult(content="No changes: replacement bytes are identical.")

        backup_id = None
        try:
            if in_place:
                try:
                    backup_id = backup_file(path)
                except Exception:
                    backup_id = None
                path.write_bytes(patched)
                out = path
            else:
                out = Path(output_path) if output_path else _default_output_path(path)
                if out.exists():
                    return ToolResult(
                        content=f"Error: output_path already exists: {out}",
                        is_error=True,
                    )
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(patched)
        except Exception as e:
            return ToolResult(content=f"Error writing patched binary: {e}", is_error=True)

        lines = [
            "# Binary Patch",
            f"Input: {path}",
            f"Output: {out}",
            f"Mode: {mode}",
            f"Offset: 0x{patch_offset:x}",
            f"Bytes changed: {patch_len}",
            f"Original SHA256: {before_sha}",
            f"Patched SHA256: {after_sha}",
        ]
        if backup_id:
            lines.append(f"Backup: {backup_id}")
        if not in_place:
            lines.append("Original file was not modified.")
        return ToolResult(
            content="\n".join(lines),
            metadata={
                "input": str(path),
                "output": str(out),
                "in_place": bool(in_place),
                "offset": patch_offset,
                "bytes_changed": patch_len,
                "original_sha256": before_sha,
                "patched_sha256": after_sha,
                "backup": backup_id,
            },
        )
