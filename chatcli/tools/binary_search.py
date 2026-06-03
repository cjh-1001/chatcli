"""Read-only binary search and hexdump helpers."""

from pathlib import Path

from .base import Tool, ToolResult


MAX_BINARY_READ_SIZE = 200 * 1024 * 1024


def _parse_hex(value: str) -> bytes:
    cleaned = "".join(str(value or "").replace("0x", "").replace("\\x", "").split())
    if not cleaned:
        return b""
    if len(cleaned) % 2:
        raise ValueError("query_hex must contain an even number of hex digits")
    return bytes.fromhex(cleaned)


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


def _load_binary(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(path)
    if path.is_dir():
        raise IsADirectoryError(path)
    size = path.stat().st_size
    if size > MAX_BINARY_READ_SIZE:
        raise ValueError(f"file too large ({size} bytes). Maximum is {MAX_BINARY_READ_SIZE} bytes")
    return path.read_bytes()


def _ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def _hexdump(data: bytes, base_offset: int, width: int = 16) -> str:
    lines = []
    for rel in range(0, len(data), width):
        chunk = data[rel:rel + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        lines.append(f"{base_offset + rel:08x}  {hex_part}  |{_ascii_preview(chunk)}|")
    return "\n".join(lines)


class BinaryFindTool(Tool):
    name = "binary_find"
    description = (
        "Find byte offsets in a local binary without executing it. Search by hex, "
        "ASCII, or UTF-16LE/wide string. Use this before binary_patch to locate "
        "candidate patch offsets."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the binary.",
            },
            "query_hex": {
                "type": "string",
                "description": "Hex bytes to search for, e.g. '75 0a' or '750a'.",
            },
            "query_ascii": {
                "type": "string",
                "description": "ASCII string to search for.",
            },
            "query_wide": {
                "type": "string",
                "description": "UTF-16LE string to search for.",
            },
            "start_offset": {
                "type": ["integer", "string"],
                "description": "Start searching at this file offset. Accepts decimal or 0x-prefixed hex. Default 0.",
            },
            "max_matches": {
                "type": "integer",
                "description": "Maximum matches to return. Default 50.",
            },
            "context_bytes": {
                "type": "integer",
                "description": "Bytes of hex/ascii context around each match. Default 16.",
            },
        },
        "required": ["file_path"],
    }

    def execute(
        self,
        file_path: str,
        query_hex: str = "",
        query_ascii: str = "",
        query_wide: str = "",
        start_offset: int | str = 0,
        max_matches: int = 50,
        context_bytes: int = 16,
        **kwargs,
    ) -> ToolResult:
        path = Path(file_path)
        try:
            data = _load_binary(path)
            needle = b""
            label = ""
            if query_hex:
                needle = _parse_hex(query_hex)
                label = f"hex:{needle.hex(' ')}"
            elif query_ascii:
                needle = query_ascii.encode("utf-8")
                label = f"ascii:{query_ascii}"
            elif query_wide:
                needle = query_wide.encode("utf-16le")
                label = f"wide:{query_wide}"
            else:
                return ToolResult(
                    content="Error: provide one of query_hex, query_ascii, or query_wide.",
                    is_error=True,
                )
        except Exception as e:
            return ToolResult(content=f"Error: {e}", is_error=True)

        if not needle:
            return ToolResult(content="Error: query cannot be empty.", is_error=True)
        try:
            start_offset = max(0, _parse_int(start_offset, "start_offset"))
            max_matches = max(1, min(_parse_int(max_matches, "max_matches") or 50, 1000))
            context_bytes = max(0, min(_parse_int(context_bytes, "context_bytes") or 16, 128))
        except ValueError as e:
            return ToolResult(content=f"Error: {e}", is_error=True)

        matches = []
        pos = start_offset
        while len(matches) < max_matches:
            idx = data.find(needle, pos)
            if idx < 0:
                break
            before = max(0, idx - context_bytes)
            after = min(len(data), idx + len(needle) + context_bytes)
            context = data[before:after]
            matches.append((idx, before, context))
            pos = idx + 1

        lines = [
            "# Binary Find",
            f"Path: {path}",
            f"Query: {label}",
            f"Matches returned: {len(matches)}",
        ]
        if not matches:
            lines.append("No matches.")
        for i, (idx, base, context) in enumerate(matches, 1):
            lines.extend([
                "",
                f"## Match {i}",
                f"Offset: 0x{idx:x} ({idx})",
                _hexdump(context, base),
            ])

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "path": str(path),
                "query": label,
                "matches": [idx for idx, _, _ in matches],
                "truncated": len(matches) >= max_matches,
            },
        )


class BinaryHexdumpTool(Tool):
    name = "binary_hexdump"
    description = (
        "Show a hexdump of a local binary around a file offset without executing it. "
        "Use with binary_find and binary_patch to verify exact bytes."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the binary.",
            },
            "offset": {
                "type": ["integer", "string"],
                "description": "File offset to start dumping from. Accepts decimal or 0x-prefixed hex.",
            },
            "length": {
                "type": "integer",
                "description": "Number of bytes to dump. Default 256, max 4096.",
            },
            "width": {
                "type": "integer",
                "description": "Bytes per row. Default 16.",
            },
        },
        "required": ["file_path", "offset"],
    }

    def execute(
        self,
        file_path: str,
        offset: int | str,
        length: int | str = 256,
        width: int | str = 16,
        **kwargs,
    ) -> ToolResult:
        path = Path(file_path)
        try:
            data = _load_binary(path)
        except Exception as e:
            return ToolResult(content=f"Error: {e}", is_error=True)

        try:
            offset = max(0, _parse_int(offset, "offset"))
            length = max(1, min(_parse_int(length, "length") or 256, 4096))
            width = max(4, min(_parse_int(width, "width") or 16, 32))
        except ValueError as e:
            return ToolResult(content=f"Error: {e}", is_error=True)
        if offset >= len(data):
            return ToolResult(content="Error: offset is beyond end of file.", is_error=True)

        chunk = data[offset:min(len(data), offset + length)]
        return ToolResult(
            content="\n".join([
                "# Binary Hexdump",
                f"Path: {path}",
                f"Offset: 0x{offset:x} ({offset})",
                f"Length: {len(chunk)}",
                "",
                _hexdump(chunk, offset, width),
            ]),
            metadata={
                "path": str(path),
                "offset": offset,
                "length": len(chunk),
            },
        )
