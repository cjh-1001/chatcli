"""Obfuscated data mapping for local reverse-engineering targets."""

import hashlib
import re
from pathlib import Path

from .base import Tool, ToolResult
from .binary_formats import _entropy, _read_pe, _hex


MAX_DATA_MAP_FILE_SIZE = 200 * 1024 * 1024

MAGIC_SIGNATURES = [
    (b"MZ", "PE/MZ"),
    (b"PK\x03\x04", "ZIP/JAR/APK"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"\x78\x01", "zlib"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"SQLite format 3\x00", "SQLite"),
]

AES_SBOX_PREFIX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
AES_INV_SBOX_PREFIX = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")
CRC32_PREFIX_LE = bytes.fromhex("00000000963007772c610eeeba510999")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(data)


def _merge_windows(windows: list[dict]) -> list[dict]:
    if not windows:
        return []
    ordered = sorted(windows, key=lambda x: x["offset"])
    first = ordered[0]
    merged = [{
        "offset": first["offset"],
        "end": first["end"],
        "size": first["size"],
        "max_entropy": first["entropy"],
        "min_printable_ratio": first["printable_ratio"],
        "windows": 1,
    }]
    for item in ordered[1:]:
        last = merged[-1]
        if item["offset"] <= last["end"]:
            last["end"] = max(last["end"], item["end"])
            last["size"] = last["end"] - last["offset"]
            last["max_entropy"] = max(last["max_entropy"], item["entropy"])
            last["min_printable_ratio"] = min(last["min_printable_ratio"], item["printable_ratio"])
            last["windows"] += 1
        else:
            merged.append({
                "offset": item["offset"],
                "end": item["end"],
                "size": item["size"],
                "max_entropy": item["entropy"],
                "min_printable_ratio": item["printable_ratio"],
                "windows": 1,
            })
    return merged


def _scan_magic(data: bytes, max_hits: int) -> list[dict]:
    hits = []
    for magic, name in MAGIC_SIGNATURES:
        start = 0
        while len(hits) < max_hits:
            idx = data.find(magic, start)
            if idx < 0:
                break
            hits.append({"offset": idx, "kind": name, "encoding": "plain", "magic": magic.hex(" ")})
            start = idx + 1
    return sorted(hits, key=lambda x: x["offset"])[:max_hits]


def _scan_xor_magic(data: bytes, max_hits: int) -> list[dict]:
    hits = []
    seen = set()
    if not data:
        return hits
    for magic, name in MAGIC_SIGNATURES:
        if not magic:
            continue
        if len(magic) < 4:
            continue
        for key in range(1, 256):
            encoded = bytes(b ^ key for b in magic)
            start = 0
            while len(hits) < max_hits:
                off = data.find(encoded, start)
                if off < 0:
                    break
                item_key = (off, key, name)
                if item_key in seen:
                    start = off + 1
                    continue
                seen.add(item_key)
                hits.append({
                    "offset": off,
                    "kind": name,
                    "encoding": "xor_single_byte",
                    "key": f"0x{key:02x}",
                    "magic": magic.hex(" "),
                })
                if len(hits) >= max_hits:
                    return hits
                start = off + 1
    return hits


def _scan_constants(data: bytes) -> list[dict]:
    constants = []
    for needle, name in (
        (AES_SBOX_PREFIX, "AES S-box prefix"),
        (AES_INV_SBOX_PREFIX, "AES inverse S-box prefix"),
        (CRC32_PREFIX_LE, "CRC32 table prefix"),
    ):
        idx = data.find(needle)
        if idx >= 0:
            constants.append({"offset": idx, "name": name, "bytes": needle.hex(" ")})
    return constants


def _scan_base64_runs(data: bytes, min_len: int, max_hits: int) -> list[dict]:
    hits = []
    pattern = re.compile(rb"[A-Za-z0-9+/=]{%d,}" % max(16, min_len))
    for match in pattern.finditer(data):
        value = match.group(0)
        if len(value) % 4 == 0:
            hits.append({"offset": match.start(), "size": len(value), "sample": value[:120].decode("ascii", errors="replace")})
            if len(hits) >= max_hits:
                break
    return hits


class ObfuscatedDataMapTool(Tool):
    name = "obfuscated_data_map"
    description = (
        "Build a read-only map of obfuscated/encrypted-looking data in a local binary "
        "or memory dump. Finds high-entropy regions, suspicious PE sections, raw and "
        "single-byte-XOR hidden file/compression magic, base64-like blobs, and common "
        "crypto/checksum constants. Use when IDA cannot make sense of data or code."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to a binary or memory dump."},
            "window_size": {"type": "integer", "description": "Entropy window size. Default 4096."},
            "stride": {"type": "integer", "description": "Window stride. Default equals window_size."},
            "entropy_threshold": {"type": "number", "description": "High entropy threshold. Default 7.2."},
            "max_hits": {"type": "integer", "description": "Maximum hits per category. Default 80."},
        },
        "required": ["file_path"],
    }

    def execute(
        self,
        file_path: str,
        window_size: int = 4096,
        stride: int | None = None,
        entropy_threshold: float = 7.2,
        max_hits: int = 80,
        **kwargs,
    ) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if path.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)
        size = path.stat().st_size
        if size > MAX_DATA_MAP_FILE_SIZE:
            return ToolResult(content=f"Error: file too large ({size} bytes). Maximum is {MAX_DATA_MAP_FILE_SIZE} bytes.", is_error=True)

        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        window_size = max(256, min(int(window_size or 4096), 1024 * 1024))
        stride = max(128, min(int(stride or window_size), window_size))
        entropy_threshold = max(0.0, min(float(entropy_threshold), 8.0))
        max_hits = max(10, min(int(max_hits or 80), 500))

        pe = _read_pe(data)
        suspicious_sections = []
        for sec in pe.get("sections", []) if pe else []:
            ent = sec.get("entropy")
            name = sec.get("name", "")
            raw_size = sec.get("raw_size", 0)
            virtual_size = sec.get("virtual_size", 0)
            if ent is not None and ent >= entropy_threshold or re.search(r"[^A-Za-z0-9_.$]", name or ""):
                suspicious_sections.append({
                    "name": name,
                    "raw_ptr": sec.get("raw_ptr", 0),
                    "raw_size": raw_size,
                    "virtual_address": sec.get("virtual_address", 0),
                    "virtual_size": virtual_size,
                    "entropy": ent,
                    "reason": "high_entropy" if ent is not None and ent >= entropy_threshold else "unusual_name",
                })

        windows = []
        for off in range(0, len(data), stride):
            chunk = data[off:off + window_size]
            if len(chunk) < max(64, window_size // 8):
                continue
            ent = _entropy(chunk)
            printable = _printable_ratio(chunk)
            if ent >= entropy_threshold and printable < 0.35:
                windows.append({
                    "offset": off,
                    "end": off + len(chunk),
                    "size": len(chunk),
                    "entropy": ent,
                    "printable_ratio": printable,
                })
        high_entropy_regions = _merge_windows(windows)[:max_hits]
        magic_hits = _scan_magic(data, max_hits)
        xor_magic_hits = _scan_xor_magic(data, max_hits)
        constants = _scan_constants(data)
        base64_runs = _scan_base64_runs(data, 32, max_hits)

        actions = []
        if suspicious_sections or high_entropy_regions:
            actions.append("Treat high-entropy/unusual sections as packed or encrypted data; map xrefs to their RVA/file offsets in IDA before decompiling.")
        if xor_magic_hits:
            actions.append("Try single-byte XOR decode around the XOR-magic offsets, then run encoded_string_extract on the decoded dump.")
        if magic_hits:
            actions.append("Extract plain embedded blobs at magic offsets and inspect/decompress them separately.")
        if constants:
            actions.append("Crypto/checksum constants found; locate xrefs to constants to identify decrypt/hash routines.")
        if base64_runs:
            actions.append("Decode base64-like blobs, then inspect entropy/strings of decoded output.")
        actions.append("If static xrefs do not reveal plaintext, use runtime_string_hooks on the suspected decrypt function/API and feed dumps back into encoded_string_extract.")

        lines = [
            "# Obfuscated Data Map",
            "",
            f"Path: {path}",
            f"Size: {size} bytes",
            f"SHA256: {sha256}",
            f"Window: {window_size} stride={stride} entropy_threshold={entropy_threshold:.2f}",
        ]
        if suspicious_sections:
            lines.extend(["", "## Suspicious PE Sections"])
            for sec in suspicious_sections[:max_hits]:
                ent = sec.get("entropy")
                ent_text = f"{ent:.2f}" if ent is not None else "n/a"
                lines.append(
                    f"- {sec['name']}: rva={_hex(sec['virtual_address'])} raw={_hex(sec['raw_ptr'])} "
                    f"raw_size={_hex(sec['raw_size'])} entropy={ent_text} reason={sec['reason']}"
                )
        if high_entropy_regions:
            lines.extend(["", "## High-Entropy Regions"])
            for region in high_entropy_regions[:max_hits]:
                lines.append(
                    f"- offset={_hex(region['offset'])} size={_hex(region['size'])} "
                    f"max_entropy={region['max_entropy']:.2f} min_printable={region['min_printable_ratio']:.2f} "
                    f"windows={region['windows']}"
                )
        if magic_hits:
            lines.extend(["", "## Plain Magic Hits"])
            for hit in magic_hits[:max_hits]:
                lines.append(f"- {_hex(hit['offset'])} {hit['kind']} magic={hit['magic']}")
        if xor_magic_hits:
            lines.extend(["", "## XOR Magic Hits"])
            for hit in xor_magic_hits[:max_hits]:
                lines.append(f"- {_hex(hit['offset'])} {hit['kind']} key={hit['key']} magic={hit['magic']}")
        if constants:
            lines.extend(["", "## Crypto / Checksum Constants"])
            for item in constants:
                lines.append(f"- {_hex(item['offset'])} {item['name']}")
        if base64_runs:
            lines.extend(["", "## Base64-Like Runs"])
            for item in base64_runs[:max_hits]:
                lines.append(f"- {_hex(item['offset'])} size={item['size']} sample={item['sample']}")
        lines.extend(["", "## Recommended Next Actions"])
        for action in actions:
            lines.append(f"- {action}")

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "path": str(path),
                "size": size,
                "sha256": sha256,
                "suspicious_sections": len(suspicious_sections),
                "high_entropy_regions": len(high_entropy_regions),
                "magic_hits": len(magic_hits),
                "xor_magic_hits": len(xor_magic_hits),
                "constants": len(constants),
                "base64_runs": len(base64_runs),
            },
        )
