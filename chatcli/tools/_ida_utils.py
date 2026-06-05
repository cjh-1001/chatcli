"""Shared IDA helper functions used by ida.py, ghidra.py, ida_focus.py, and reverse tools."""

import json
import os
import hashlib
import re
import shutil
import tempfile
from pathlib import Path

def _safe_cache_name(value: str, fallback: str = "target") -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (name or fallback)[:80]


def _target_cache_key(target: Path, extra: str = "") -> str:
    try:
        resolved = str(target.resolve())
    except Exception:
        resolved = str(target)
    try:
        stat = target.stat()
        identity = f"{resolved}|{stat.st_size}|{stat.st_mtime_ns}|{extra}"
    except Exception:
        identity = f"{resolved}|{extra}"
    return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:16]


def _default_ida_json_path(
    target: Path,
    prefix: str,
    workspace: str | None = None,
    extra: str = "",
) -> Path:
    if workspace:
        root = Path(workspace) / ".chatcli" / "tmp" / "ida"
    else:
        root = Path(tempfile.gettempdir()) / "chatcli-ida-cache"
    key = _target_cache_key(target, extra)
    return root / f"{prefix}-{_safe_cache_name(target.stem)}-{key}.json"


def _load_reusable_json(output_path: Path, target: Path) -> dict | None:
    if not output_path.exists():
        return None
    try:
        if output_path.stat().st_mtime_ns < target.stat().st_mtime_ns:
            return None
        data = json.loads(output_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _cleanup_paths(*paths: Path) -> None:
    for path in paths:
        try:
            path.unlink()
        except Exception:
            pass


def _headless_siblings(path: Path) -> list[Path]:
    return [path / name for name in ("idat64.exe", "idat.exe", "idat64", "idat")]


def _common_ida_locations() -> list[Path]:
    roots: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value))
    roots.extend([Path("C:/Program Files"), Path("C:/Program Files (x86)"), Path("C:/IDA"), Path("C:/IDA Pro")])

    candidates: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        for pattern in ("IDA*", "Hex-Rays*", "IDA Pro*"):
            for path in root.glob(pattern):
                key = str(path).lower()
                if key in seen:
                    continue
                seen.add(key)
                candidates.extend(_headless_siblings(path))
                candidates.extend([path / "ida64.exe", path / "ida.exe"])
    return candidates


def _ida_not_found_message() -> str:
    return (
        "IDA executable not found. Install IDA Pro/Free and configure one of: "
        "IDA_PATH, IDAT64_PATH, IDAT_PATH, IDA64_PATH, PATH, or pass ida_path. "
        "ida_path may point to idat64/idat (headless CLI) or to an IDA install directory. "
        "Run ida_probe for diagnostics. Continue without IDA using binary_inspect, "
        "encoded_string_extract, obfuscated_data_map, binary_find, and binary_hexdump."
    )


def _find_ida(explicit: str | None = None) -> str | None:
    candidates = []

    def add_candidate(value: str) -> None:
        path = Path(value)
        if path.exists() and path.is_dir():
            candidates.extend(str(p) for p in _headless_siblings(path))
            candidates.extend(str(path / name) for name in ("ida64.exe", "ida.exe", "ida64", "ida"))
            return
        if path.name.lower() in {"ida.exe", "ida64.exe", "ida", "ida64"}:
            for sibling in ("idat64.exe", "idat.exe", "idat64", "idat"):
                headless = path.parent / sibling
                if headless.exists() and headless.is_file():
                    candidates.append(str(headless))
            return
        candidates.append(value)

    if explicit:
        add_candidate(explicit)
    for env_name in ("IDA_PATH", "IDAT64_PATH", "IDAT_PATH", "IDA64_PATH"):
        value = os.environ.get(env_name)
        if value:
            add_candidate(value)
    for name in ("idat64", "idat", "ida64", "ida"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    candidates.extend(str(path) for path in _common_ida_locations())

    for candidate in candidates:
        path = Path(candidate)
        if path.exists() and path.is_file():
            return str(path)
        found = shutil.which(candidate)
        if found:
            return found
    return None
