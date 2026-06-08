"""Shared static-analysis tool configuration."""

from __future__ import annotations

SUPPORTED_STATIC_ANALYZERS: dict[str, dict[str, object]] = {
    "capa": {
        "exe": "capa",
        "module": "capa.main",
        "args": lambda target: ["capa", str(target)],
        "description": "Mandiant capa capability detection",
    },
    "die": {
        "exe": "diec",
        "args": lambda target: ["diec", str(target)],
        "description": "Detect It Easy file identification",
    },
    "floss": {
        "exe": "floss",
        "module": "floss",
        "args": lambda target: ["floss", str(target)],
        "description": "FLOSS string extraction",
    },
    "exiftool": {
        "exe": "exiftool",
        "args": lambda target: ["exiftool", str(target)],
        "description": "ExifTool metadata extraction",
    },
}

STATIC_ANALYZER_CONFIG_ATTRS = {
    "capa": "capa_path",
    "die": "die_path",
    "floss": "floss_path",
    "exiftool": "exiftool_path",
}

TOOL_CONFIG_ATTRS = {
    **STATIC_ANALYZER_CONFIG_ATTRS,
    "upx": "upx_path",
    "yara": "yara_path",
    "sysmon": "sysmon_path",
    "x64dbg": "x64dbg_path",
}

PYTHON_TOOL_FALLBACKS = {
    "capa": {
        "package": "flare-capa",
        "module": "capa",
        "path": "python -m capa.main",
    },
    "floss": {
        "package": "flare-floss",
        "module": "floss",
        "path": "python -m floss",
    },
}

YARA_PYTHON_PACKAGE = {"package": "yara-python", "module": "yara"}
