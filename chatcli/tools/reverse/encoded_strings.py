"""Static encoded-string extraction for local binaries and dumps."""

import base64
import binascii
import json
import re
from pathlib import Path

from ..base import Tool, ToolResult

MAX_STRING_FILE_SIZE = 200 * 1024 * 1024

def _extract_ascii_strings(data: bytes, min_len: int) -> list[tuple[int, str, str]]:
    out = []
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for match in ascii_re.finditer(data):
        out.append((match.start(), "ascii", match.group(0).decode("utf-8", errors="replace")))
    for match in wide_re.finditer(data):
        out.append((match.start(), "utf16le", match.group(0).decode("utf-16le", errors="replace")))
    return out


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    return good / len(data)


def _looks_interesting(text: str) -> int:
    score = 0
    if re.search(r"(flag|key|token|password|serial|license|decrypt|config|http|api|success|error|admin|auth)", text, re.I):
        score += 5
    if re.search(r"[A-Za-z]{4,}", text):
        score += 1
    if any(ch in text for ch in "{}_:/\\.-"):
        score += 1
    if len(text) >= 16:
        score += 1
    return score


def _decode_base64_and_hex(strings: list[tuple[int, str, str]], min_len: int) -> list[dict]:
    results = []
    seen = set()
    for off, kind, text in strings:
        compact = text.strip()
        if len(compact) < max(8, min_len):
            continue
        candidates = []
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", compact) and len(compact) % 4 in (0, 2, 3):
            candidates.append(("base64", compact.replace("-", "+").replace("_", "/")))
        if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{%d,}" % (min_len * 2), compact) and len(compact.replace("0x", "")) % 2 == 0:
            candidates.append(("hex", compact.replace("0x", "")))
        for enc, raw in candidates:
            try:
                decoded = base64.b64decode(raw + "=" * ((4 - len(raw) % 4) % 4), validate=False) if enc == "base64" else binascii.unhexlify(raw)
            except Exception:
                continue
            if len(decoded) < min_len or _printable_ratio(decoded) < 0.75:
                continue
            value = decoded.decode("utf-8", errors="replace").strip("\x00")
            key = (enc, off, value)
            if value and key not in seen:
                seen.add(key)
                results.append({"offset": off, "source_kind": kind, "encoding": enc, "value": value[:500], "score": _looks_interesting(value)})
    return results


def _xor_strings(data: bytes, min_len: int, keys: list[int], max_results: int) -> list[dict]:
    results = []
    seen = set()
    printable = set(range(32, 127)) | {9, 10, 13}
    for key in keys:
        run = bytearray()
        start = 0
        for idx, byte in enumerate(data):
            decoded = byte ^ key
            if decoded in printable:
                if not run:
                    start = idx
                run.append(decoded)
                continue
            if len(run) >= min_len:
                value = run.decode("utf-8", errors="replace").strip()
                if value and value not in seen and _looks_interesting(value) > 0:
                    seen.add(value)
                    results.append({"offset": start, "key": f"0x{key:02x}", "encoding": "xor_single_byte", "value": value[:500], "score": _looks_interesting(value)})
                    if len(results) >= max_results:
                        return results
            run = bytearray()
        if len(run) >= min_len:
            value = run.decode("utf-8", errors="replace").strip()
            if value and value not in seen and _looks_interesting(value) > 0:
                seen.add(value)
                results.append({"offset": start, "key": f"0x{key:02x}", "encoding": "xor_single_byte", "value": value[:500], "score": _looks_interesting(value)})
                if len(results) >= max_results:
                    return results
    return results


class EncodedStringExtractTool(Tool):
    name = "encoded_string_extract"
    description = (
        "Extract plaintext strings from a local binary or memory dump without executing it. "
        "Finds ASCII/UTF-16LE strings, decodes base64/hex-looking strings, and searches "
        "for likely single-byte XOR decoded strings."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to a binary or memory dump."},
            "min_length": {"type": "integer", "description": "Minimum decoded string length. Default 5."},
            "max_results": {"type": "integer", "description": "Maximum results per category. Default 200."},
            "xor": {"type": "boolean", "description": "Try single-byte XOR string extraction. Default true."},
            "xor_keys": {
                "type": "array",
                "description": "Optional XOR keys as integers 1..255. Default: all keys.",
                "items": {"type": "integer"},
            },
            "output_json_path": {"type": "string", "description": "Optional path to write full JSON results."},
        },
        "required": ["file_path"],
    }

    def execute(
        self,
        file_path: str,
        min_length: int = 5,
        max_results: int = 200,
        xor: bool = True,
        xor_keys: list[int] | None = None,
        output_json_path: str = "",
        **kwargs,
    ) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if path.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)
        size = path.stat().st_size
        if size > MAX_STRING_FILE_SIZE:
            return ToolResult(content=f"Error: file too large ({size} bytes). Maximum is {MAX_STRING_FILE_SIZE} bytes.", is_error=True)

        data = path.read_bytes()
        min_length = max(3, min(int(min_length or 5), 64))
        max_results = max(20, min(int(max_results or 200), 2000))
        raw_strings = _extract_ascii_strings(data, min_length)
        decoded = _decode_base64_and_hex(raw_strings[: max_results * 20], min_length)
        decoded = sorted(decoded, key=lambda x: x.get("score", 0), reverse=True)[:max_results]
        keys = [int(k) & 0xFF for k in xor_keys] if xor_keys else list(range(1, 256))
        keys = [k for k in keys if 1 <= k <= 255]
        xor_results = _xor_strings(data, min_length, keys, max_results) if xor else []
        xor_results = sorted(xor_results, key=lambda x: x.get("score", 0), reverse=True)[:max_results]

        plain = []
        seen_plain = set()
        for off, kind, text in sorted(raw_strings, key=lambda x: _looks_interesting(x[2]), reverse=True):
            if text in seen_plain:
                continue
            seen_plain.add(text)
            plain.append({"offset": off, "kind": kind, "value": text[:500], "score": _looks_interesting(text)})
            if len(plain) >= max_results:
                break

        result = {
            "path": str(path),
            "size": size,
            "plain_strings": plain,
            "decoded_strings": decoded,
            "xor_strings": xor_results,
        }
        if output_json_path:
            out = Path(output_json_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            out = None

        lines = [
            "# Encoded String Extract",
            "",
            f"Path: {path}",
            f"Size: {size} bytes",
            f"Plain strings returned: {len(plain)}",
            f"Base64/hex decoded strings: {len(decoded)}",
            f"XOR decoded strings: {len(xor_results)}",
        ]
        if out:
            lines.append(f"JSON output: {out}")
        lines.extend(["", "## Decoded Base64/Hex"])
        for item in decoded[:80]:
            lines.append(f"- 0x{item['offset']:x} {item['encoding']} score={item['score']}: {item['value']}")
        lines.extend(["", "## XOR Strings"])
        for item in xor_results[:80]:
            lines.append(f"- 0x{item['offset']:x} key={item['key']} score={item['score']}: {item['value']}")
        lines.extend(["", "## Plain Strings"])
        for item in plain[:120]:
            lines.append(f"- 0x{item['offset']:x} {item['kind']} score={item['score']}: {item['value']}")

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "path": str(path),
                "size": size,
                "plain_strings": len(plain),
                "decoded_strings": len(decoded),
                "xor_strings": len(xor_results),
                "output_json_path": str(out) if out else "",
            },
        )


