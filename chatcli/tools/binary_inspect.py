"""Static binary triage helpers."""

import hashlib
from pathlib import Path

from .base import Tool, ToolResult
from .binary_formats import (
    _entropy,
    _extract_strings,
    _hex,
    _packer_clues,
    _read_elf,
    _read_macho,
    _read_pe,
)


MAX_BINARY_SIZE = 200 * 1024 * 1024


class BinaryInspectTool(Tool):
    name = "binary_inspect"
    description = (
        "Static triage for a local binary without executing it. Computes hashes, "
        "detects PE/ELF/Mach-O metadata, reports section entropy and packer clues, "
        "and extracts printable strings."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the binary to inspect.",
            },
            "min_string_length": {
                "type": "integer",
                "description": "Minimum printable string length. Default 5.",
            },
            "max_strings": {
                "type": "integer",
                "description": "Maximum strings to include. Default 200.",
            },
        },
        "required": ["file_path"],
    }

    def execute(
        self, file_path: str, min_string_length: int = 5,
        max_strings: int = 200, **kwargs
    ) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if path.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)
        size = path.stat().st_size
        if size > MAX_BINARY_SIZE:
            return ToolResult(
                content=f"Error: file too large ({size} bytes). Maximum is {MAX_BINARY_SIZE} bytes.",
                is_error=True,
            )

        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        pe = _read_pe(data)
        elf = _read_elf(data)
        macho = _read_macho(data)
        file_entropy = _entropy(data)
        strings = _extract_strings(
            data,
            max(3, min(int(min_string_length), 32)),
            max(20, min(int(max_strings), 2000)),
        )
        packer_clues = _packer_clues(data, pe, elf, macho)

        lines = [
            "# Binary Inspect",
            "",
            f"Path: {path}",
            f"Size: {size} bytes",
            f"SHA256: {sha256}",
            f"MD5: {md5}",
            f"Magic: {data[:16].hex(' ')}",
            f"Entropy: {file_entropy:.2f}",
        ]
        if packer_clues:
            lines.extend(["", "## Packer / Obfuscation Clues"])
            for clue in packer_clues[:40]:
                lines.append(f"- {clue}")
        if pe:
            lines.extend([
                "",
                "## PE",
                f"Format: {pe.get('format')}",
            ])
            if "pe_error" in pe:
                lines.append(f"Error: {pe['pe_error']}")
            else:
                lines.extend([
                    f"Machine: {pe.get('machine')}",
                    f"Subsystem: {pe.get('subsystem')}",
                    f"COFF timestamp: {pe.get('timestamp')}",
                    f"Image base: {_hex(pe.get('image_base', 0))}",
                    f"Entry RVA: {_hex(pe.get('entry_rva', 0))}",
                    f"Entry VA: {_hex(pe.get('entry_va', 0))}",
                    "",
                    "## Sections",
                ])
                for s in pe.get("sections", []):
                    entropy = s.get("entropy")
                    entropy_text = f" entropy={entropy:.2f}" if entropy is not None else ""
                    lines.append(
                        f"- {s['name']}: va={_hex(s['virtual_address'])} "
                        f"vsize={_hex(s['virtual_size'])} raw={_hex(s['raw_size'])}"
                        f"{entropy_text}"
                    )
                lines.extend(["", "## Imports"])
                for imp in pe.get("imports", [])[:80]:
                    funcs = ", ".join(imp["functions"][:40])
                    more = "" if len(imp["functions"]) <= 40 else f" ... (+{len(imp['functions']) - 40})"
                    lines.append(f"- {imp['dll']}: {funcs}{more}")

        if elf:
            lines.extend(["", "## ELF", f"Format: {elf.get('format')}"])
            if "elf_error" in elf:
                lines.append(f"Error: {elf['elf_error']}")
            else:
                lines.extend([
                    f"Machine: {elf.get('machine')}",
                    f"Type: {elf.get('type')}",
                    f"Endianness: {elf.get('endianness')}",
                    f"Entry: {_hex(elf.get('entry', 0))}",
                    "",
                    "## ELF Sections",
                ])
                for s in elf.get("sections", [])[:120]:
                    entropy = s.get("entropy")
                    entropy_text = f" entropy={entropy:.2f}" if entropy is not None else ""
                    lines.append(
                        f"- {s.get('name') or '(unnamed)'}: type={s.get('type_name')} "
                        f"addr={_hex(s.get('address', 0))} off={_hex(s.get('offset', 0))} "
                        f"size={_hex(s.get('size', 0))}{entropy_text}"
                    )

        if macho:
            lines.extend(["", "## Mach-O", f"Format: {macho.get('format')}"])
            if "macho_error" in macho:
                lines.append(f"Error: {macho['macho_error']}")
            else:
                lines.extend([
                    f"Machine: {macho.get('machine')}",
                    f"Type: {macho.get('type', '')}",
                    f"Endianness: {macho.get('endianness', '')}",
                ])
                if macho.get("entry_file_offset") is not None:
                    lines.append(f"Entry file offset: {_hex(macho.get('entry_file_offset', 0))}")
                if macho.get("segments"):
                    lines.extend(["", "## Mach-O Segments"])
                    for s in macho.get("segments", [])[:80]:
                        entropy = s.get("entropy")
                        entropy_text = f" entropy={entropy:.2f}" if entropy is not None else ""
                        lines.append(
                            f"- {s.get('name') or '(unnamed)'}: vmaddr={_hex(s.get('vmaddr', 0))} "
                            f"vmsize={_hex(s.get('vmsize', 0))} fileoff={_hex(s.get('fileoff', 0))} "
                            f"filesize={_hex(s.get('filesize', 0))}{entropy_text}"
                        )

        lines.extend(["", "## Strings"])
        for s in strings:
            lines.append(f"- {s[:300]}")

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "path": str(path),
                "size": size,
                "sha256": sha256,
                "format": (
                    pe.get("format")
                    or elf.get("format")
                    or macho.get("format")
                    or "unknown"
                ),
                "entropy": file_entropy,
                "packer_clues": packer_clues,
                "strings": len(strings),
                "imports": sum(len(i.get("functions", [])) for i in pe.get("imports", [])) if pe else 0,
            },
        )
