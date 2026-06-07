#!/usr/bin/env python3
"""Standalone chatcli Guest Agent for remote analysis servers.

This file is intended to be copied to a Tencent Cloud Windows server by itself.
It does not import the local chatcli package.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse


BASE_DIR = Path(os.environ.get("CHATCLI_AGENT_DIR", "C:/analysis"))
CASES_DIR = BASE_DIR / "cases"
OUTBOX_DIR = BASE_DIR / "outbox"
TOKEN_ENV = "CHATCLI_GUEST_AGENT_TOKEN"
AGENT_TOKEN = os.environ.get(TOKEN_ENV, "").strip()

app = FastAPI(title="chatcli-guest-agent-standalone", version="0.2.0")


def _auth(authorization: str | None = Header(None)) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(503, detail=f"server token env var {TOKEN_ENV} is not set")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, detail="missing bearer token")
    if authorization.removeprefix("Bearer ").strip() != AGENT_TOKEN:
        raise HTTPException(401, detail="invalid bearer token")


def _case_dir(case_id: str) -> Path:
    return CASES_DIR / case_id


def _read_state(case_id: str) -> dict[str, Any]:
    state_file = _case_dir(case_id) / "case_state.json"
    if state_file.is_file():
        return json.loads(state_file.read_text(encoding="utf-8"))
    return {}


def _write_state(case_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    case_dir = _case_dir(case_id)
    case_dir.mkdir(parents=True, exist_ok=True)
    state = _read_state(case_id)
    state.update(updates)
    state["updated_at"] = time.time()
    tmp = case_dir / "case_state.tmp"
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(case_dir / "case_state.json")
    return state


def _resolve_ida_command() -> str:
    for env_name in ("CHATCLI_TOOL_IDA", "IDA_PATH", "IDAT64_PATH", "IDAT_PATH", "IDA64_PATH"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value

    candidates = [
        r"C:\Program Files\IDA Professional 9.0\idat64.exe",
        r"C:\Program Files\IDA Professional 9.0\idat.exe",
        r"C:\Program Files\IDA Pro 9.0\idat64.exe",
        r"C:\Program Files\IDA Pro 9.0\idat.exe",
    ]
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env_name, "").strip()
        if not root:
            continue
        root_path = Path(root)
        candidates.extend(str(path / exe) for path in root_path.glob("IDA*") for exe in ("idat64.exe", "idat.exe"))
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    return "idat64"


def _resolve_ghidra_command() -> str:
    for env_name in ("CHATCLI_TOOL_GHIDRA", "GHIDRA_HEADLESS_PATH", "GHIDRA_HOME"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return "analyzeHeadless"


def _resolve_tool_paths() -> dict[str, str]:
    defaults = {
        "python": sys.executable,
        "ida": _resolve_ida_command(),
        "ghidra": _resolve_ghidra_command(),
        "powershell": "powershell",
        "wevtutil": "wevtutil",
        "dumpcap": "dumpcap",
        "tshark": "tshark",
        "zeek": "zeek",
        "suricata": "suricata",
        "sysmon": r"C:\Sysmon\Sysmon64.exe",
        "procmon": r"C:\Tools\Procmon64.exe",
        "diec": "diec",
        "yara": "yara",
        "exiftool": "exiftool",
        "upx": "upx",
    }
    return {
        name: (os.environ.get(f"CHATCLI_TOOL_{name.upper()}", "").strip() or default)
        for name, default in defaults.items()
    }


def _split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def _tool_available(command: str) -> bool:
    raw = str(command or "").strip().strip('"')
    if raw:
        raw_path = Path(raw)
        if raw_path.is_file():
            return True
        if raw_path.is_dir():
            for candidate in (
                raw_path / "support" / "analyzeHeadless.bat",
                raw_path / "support" / "analyzeHeadless",
                raw_path / "idat64.exe",
                raw_path / "idat.exe",
            ):
                if candidate.is_file():
                    return True
    argv = _split_command(command)
    exe_str = argv[0].strip('"') if argv else command
    exe = Path(exe_str)
    return exe.is_file() if exe.is_absolute() else shutil.which(exe_str) is not None


def _python_package_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _tool_inventory() -> dict[str, dict[str, Any]]:
    paths = _resolve_tool_paths()
    tools: dict[str, dict[str, Any]] = {}
    for name, command in sorted(paths.items()):
        if name in {"dumpcap", "tshark", "sysmon", "procmon"}:
            kind = "collector"
        elif name == "ida":
            kind = "headless_reverse"
        elif name in {"ghidra"}:
            kind = "headless_reverse"
        elif name in {"diec", "yara", "exiftool", "upx"}:
            kind = "static_external"
        else:
            kind = "external"
        tools[name] = {
            "kind": kind,
            "path": command,
            "available": _tool_available(command),
        }
    python_analyzers = {
        "capa": {
            "package": "flare-capa",
            "module": "capa",
            "command": f'"{sys.executable}" -m capa.main <sample> -j',
        },
        "floss": {
            "package": "flare-floss",
            "module": "floss",
            "command": f'"{sys.executable}" -m floss <sample>',
        },
        "yara-python": {
            "package": "yara-python",
            "module": "yara",
            "command": "import yara; yara.compile(...).match(<sample>)",
        },
    }
    for name, spec in python_analyzers.items():
        tools[name] = {
            "kind": "analysis_python",
            "package": spec["package"],
            "module": spec["module"],
            "command": spec["command"],
            "available": _python_package_available(spec["module"]),
        }
    tools["binary_inspect"] = {
        "kind": "built_in_static",
        "available": True,
        "description": "Built-in hash, size, PE marker, and sampled strings metadata.",
    }
    tools["strings"] = {
        "kind": "built_in_static",
        "available": True,
        "description": "Built-in printable ASCII string extraction.",
    }
    yara_rules = os.environ.get("CHATCLI_YARA_RULES", "").strip()
    tools["yara_rules"] = {
        "kind": "analysis_config",
        "path": yara_rules,
        "available": bool(yara_rules and Path(yara_rules).is_file()),
    }
    return tools


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _sample_metadata(sample_path: str) -> dict[str, Any]:
    if not sample_path:
        return {}
    path = Path(sample_path).expanduser()
    meta: dict[str, Any] = {
        "sample_path": str(path),
        "sample_exists": path.is_file(),
    }
    if path.is_file():
        meta.update({
            "sample_filename": path.name,
            "sample_sha256": _sha256_file(path),
            "sample_size_bytes": path.stat().st_size,
        })
    return meta


def _write_job_file(case_id: str) -> dict[str, Any]:
    state = _read_state(case_id)
    job = {
        "job_id": case_id,
        "analysis_plan": state.get("analysis_plan", {"static": True}),
        "dynamic_config": state.get("dynamic_config", {}),
    }
    if state.get("sample_path"):
        job["sample_path"] = state["sample_path"]
    job_path = _case_dir(case_id) / "job.json"
    job_path.write_text(json.dumps(job, indent=2, ensure_ascii=False), encoding="utf-8")
    return job


def _run_probe(command: str, timeout: int = 10) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, min(timeout, 30)),
            cwd=str(BASE_DIR),
        )
        return {
            "command": command,
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[:12000],
            "stderr": (proc.stderr or "")[:4000],
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except Exception as exc:
        return {
            "command": command,
            "exit_code": -2,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": int((time.time() - started) * 1000),
        }


def _disk_snapshot(path: Path) -> dict[str, int]:
    try:
        usage = shutil.disk_usage(path)
    except Exception:
        usage = shutil.disk_usage(Path.cwd())
    return {
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
    }


def _server_status(include_probes: bool = False) -> dict[str, Any]:
    tools = _tool_inventory()
    cases = []
    if CASES_DIR.is_dir():
        for case_dir in sorted(CASES_DIR.iterdir()):
            if case_dir.is_dir():
                state = _read_state(case_dir.name)
                cases.append({
                    "case_id": case_dir.name,
                    "status": state.get("status", "unknown"),
                    "sample_sha256": state.get("sample_sha256", ""),
                    "updated_at": state.get("updated_at", 0),
                })
    data: dict[str, Any] = {
        "status": "ok",
        "timestamp": time.time(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "pid": os.getpid(),
        "workdir": str(BASE_DIR),
        "cases_dir": str(CASES_DIR),
        "outbox_dir": str(OUTBOX_DIR),
        "disk": _disk_snapshot(BASE_DIR),
        "tool_count": len(tools),
        "tools_available": sum(1 for info in tools.values() if info.get("available")),
        "tools": tools,
        "cases": cases[-20:],
    }
    if include_probes:
        probes = {
            "whoami": _run_probe("whoami", 5),
            "hostname": _run_probe("hostname", 5),
        }
        if os.name == "nt":
            probes.update({
                "ipconfig": _run_probe("ipconfig", 8),
                "netstat": _run_probe("netstat -ano", 10),
                "tasklist": _run_probe("tasklist", 10),
            })
        else:
            probes.update({
                "ip_addr": _run_probe("ip addr", 8),
                "ss": _run_probe("ss -tunap", 10),
                "ps": _run_probe("ps aux", 10),
            })
        data["probes"] = probes
    return data


def _security_status() -> dict[str, Any]:
    recent_results = []
    if OUTBOX_DIR.is_dir():
        for case_dir in sorted(OUTBOX_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not case_dir.is_dir():
                continue
            recent_results.append({
                "case_id": case_dir.name,
                "done": (case_dir / "_DONE").exists(),
                "failed": (case_dir / "_FAILED").exists(),
                "mtime": case_dir.stat().st_mtime,
            })
            if len(recent_results) >= 20:
                break

    probes = {
        "network_connections": _run_probe("netstat -ano" if os.name == "nt" else "ss -tunap", 10),
        "processes": _run_probe("tasklist" if os.name == "nt" else "ps aux", 10),
    }
    if os.name == "nt":
        probes.update({
            "services": _run_probe("sc query state= all", 12),
            "scheduled_tasks": _run_probe("schtasks /query /fo LIST", 15),
            "recent_system_events": _run_probe("wevtutil qe System /c:30 /f:text", 15),
        })
    else:
        probes.update({
            "services": _run_probe("systemctl --no-pager --type=service --state=running", 12),
            "cron": _run_probe("crontab -l", 8),
            "recent_logs": _run_probe("journalctl -n 50 --no-pager", 15),
        })

    failed_jobs = [item for item in recent_results if item["failed"]]
    findings = []
    if failed_jobs:
        findings.append({
            "severity": "medium",
            "title": "Recent analysis jobs failed",
            "detail": f"{len(failed_jobs)} recent outbox case(s) have _FAILED markers.",
        })
    return {
        "status": "collected",
        "timestamp": time.time(),
        "hostname": platform.node(),
        "risk_level": "review" if findings else "unknown",
        "findings": findings,
        "recent_results": recent_results,
        "probes": probes,
    }


def _latest_dynamic_status(case_id: str = "") -> dict[str, Any]:
    candidates: list[Path] = []
    if case_id:
        candidates.append(OUTBOX_DIR / case_id / "dynamic" / "dynamic_status.json")
    elif OUTBOX_DIR.is_dir():
        candidates = sorted(
            OUTBOX_DIR.glob("*/dynamic/dynamic_status.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    for path in candidates:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                data["status_file"] = str(path)
                return data
            except Exception as exc:
                return {"status": "unreadable", "status_file": str(path), "error": str(exc)}
    return {}


def _recent_file_activity(case_id: str = "", limit: int = 30) -> list[dict[str, Any]]:
    roots: list[Path] = []
    if case_id:
        roots.extend([CASES_DIR / case_id, OUTBOX_DIR / case_id])
    configured = os.environ.get("CHATCLI_MONITOR_PATHS", "").strip()
    if configured:
        roots.extend(Path(item).expanduser() for item in configured.split(os.pathsep) if item.strip())
    if not roots:
        roots.extend([OUTBOX_DIR, CASES_DIR])

    seen: set[Path] = set()
    files: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists() or root in seen:
            continue
        seen.add(root)
        scanned = 0
        paths = root.rglob("*") if root.is_dir() else [root]
        for path in paths:
            scanned += 1
            if scanned > 3000:
                break
            if not path.is_file():
                continue
            try:
                stat = path.stat()
                files.append({
                    "path": str(path),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                })
            except OSError:
                continue
    return sorted(files, key=lambda item: item["mtime"], reverse=True)[:limit]


def _monitor_snapshot(case_id: str = "", include_probes: bool = True) -> dict[str, Any]:
    probes: dict[str, Any] = {}
    if include_probes:
        probes["processes"] = _run_probe("tasklist /fo csv /nh" if os.name == "nt" else "ps aux", 10)
        probes["network_connections"] = _run_probe("netstat -ano" if os.name == "nt" else "ss -tunap", 10)
        if os.name == "nt":
            probes.update({
                "registry_run_hkcu": _run_probe(r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"', 8),
                "registry_run_hklm": _run_probe(r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"', 8),
                "scheduled_tasks": _run_probe("schtasks /query /fo LIST /v", 15),
                "services": _run_probe("sc query state= all", 12),
            })
        else:
            probes.update({
                "scheduled_tasks": _run_probe("crontab -l", 8),
                "services": _run_probe("systemctl --no-pager --type=service --state=running", 12),
            })

    dynamic_status = _latest_dynamic_status(case_id)
    pcap_path = Path(dynamic_status.get("outputs", {}).get("network_pcap", "")) if dynamic_status else Path()
    pcap_bytes = pcap_path.stat().st_size if pcap_path.is_file() else 0
    file_activity = _recent_file_activity(case_id)

    def probe_state(name: str) -> str:
        if name not in probes:
            return "not_collected"
        return "ok" if probes[name].get("exit_code") == 0 else "review"

    observer_agents = [
        {
            "name": "process-observer",
            "role": "process_tree",
            "status": probe_state("processes"),
            "summary": "Process snapshot collected; use raw probe output for PID/name review.",
        },
        {
            "name": "network-observer",
            "role": "live_network",
            "status": "collecting" if dynamic_status.get("status") in {"collecting", "collected"} else probe_state("network_connections"),
            "summary": f"Live connections probed; capture file bytes={pcap_bytes}.",
        },
        {
            "name": "registry-observer",
            "role": "registry_persistence",
            "status": probe_state("registry_run_hkcu") if os.name == "nt" else "not_applicable",
            "summary": "Windows Run key probes collected." if os.name == "nt" else "Registry probes are Windows-only.",
        },
        {
            "name": "persistence-observer",
            "role": "scheduled_tasks_services",
            "status": probe_state("scheduled_tasks"),
            "summary": "Scheduled task and service probes collected.",
        },
        {
            "name": "filesystem-observer",
            "role": "file_activity",
            "status": "ok",
            "summary": f"{len(file_activity)} recent file entries tracked.",
        },
    ]

    return {
        "status": "collected",
        "timestamp": time.time(),
        "hostname": platform.node(),
        "case_id": case_id,
        "dynamic_status": dynamic_status,
        "traffic_capture": {
            "pcap_path": str(pcap_path) if str(pcap_path) != "." else "",
            "pcap_bytes": pcap_bytes,
            "active": dynamic_status.get("status") in {"collecting", "collected"},
        },
        "file_activity": file_activity,
        "observer_agents": observer_agents,
        "probes": probes,
    }


def _resolve_sample(case_id: str, job: dict[str, Any]) -> Path:
    configured = str(job.get("sample_path", "") or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"Configured sample_path not found: {path}")
        return path
    sample_dir = _case_dir(case_id) / "sample"
    samples = list(sample_dir.glob("*")) if sample_dir.is_dir() else []
    if not samples:
        raise FileNotFoundError("No sample found. Provide sample_path or upload a sample.")
    return samples[0]


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _run_static(case_id: str, outbox: Path, sample: Path, mode: str) -> tuple[list[str], list[str]]:
    done: list[str] = []
    failed: list[str] = []
    static_dir = outbox / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

    if mode == "dry_run":
        done.extend(["static.binary_inspect (dry_run)", "static.strings (dry_run)"])
        return done, failed

    data = sample.read_bytes()
    strings = [
        s.decode("ascii", "replace")
        for s in re.findall(rb"[\x20-\x7e]{4,}", data)[:2000]
    ]
    _write_json(static_dir / "binary_inspect.json", {
        "path": str(sample),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "is_pe": data[:2] == b"MZ",
        "string_count_sampled": len(strings),
    })
    (static_dir / "strings.txt").write_text("\n".join(strings), encoding="utf-8", errors="replace")
    done.extend(["static.binary_inspect", "static.strings"])

    tools = _resolve_tool_paths()
    optional = {
        "capa": ([sys.executable, "-m", "capa.main", str(sample), "-j"], "capa.json", "capa", {0}),
        "floss": ([sys.executable, "-m", "floss", str(sample)], "floss.txt", "floss", {0}),
        "diec": (_split_command(tools["diec"]) + [str(sample)], "diec.txt", "", {0}),
        "exiftool": (_split_command(tools["exiftool"]) + [str(sample)], "exiftool.txt", "", {0}),
        "upx": (_split_command(tools["upx"]) + ["-l", str(sample)], "upx_list.txt", "", {0, 1, 2}),
    }
    for name, (command, output_name, module_name, ok_codes) in optional.items():
        if module_name:
            available = _python_package_available(module_name)
        else:
            available = _tool_available(tools[name])
        if not available:
            failed.append(f"static.{name} (not available)")
            continue
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )
            (static_dir / output_name).write_text(proc.stdout or proc.stderr or "", encoding="utf-8", errors="replace")
            (done if proc.returncode in ok_codes else failed).append(
                f"static.{name}" + (f" (exit={proc.returncode})" if proc.returncode else "")
            )
        except subprocess.TimeoutExpired:
            failed.append(f"static.{name} (timeout)")
        except Exception as exc:
            failed.append(f"static.{name} ({type(exc).__name__}: {exc})")

    yara_rules = os.environ.get("CHATCLI_YARA_RULES", "").strip()
    if yara_rules and Path(yara_rules).is_file():
        if _python_package_available("yara"):
            try:
                import yara

                rules = yara.compile(filepath=yara_rules)
                matches = rules.match(str(sample))
                _write_json(static_dir / "yara_matches.json", {
                    "rules": yara_rules,
                    "matches": [
                        {
                            "rule": match.rule,
                            "namespace": match.namespace,
                            "tags": list(match.tags),
                            "meta": dict(match.meta),
                        }
                        for match in matches
                    ],
                })
                done.append("static.yara-python")
            except Exception as exc:
                failed.append(f"static.yara-python ({type(exc).__name__}: {exc})")
        else:
            failed.append("static.yara-python (not available)")
    return done, failed


def _run_dynamic_placeholder(
    outbox: Path,
    mode: str,
    sample: Path,
    dynamic_config: dict[str, Any] | None = None,
) -> list[str]:
    dynamic_dir = outbox / "dynamic"
    dynamic_dir.mkdir(parents=True, exist_ok=True)
    tools = _resolve_tool_paths()
    cfg = dynamic_config or {}
    timeout_seconds = int(cfg.get("timeout_seconds") or 60)
    collectors = set(cfg.get("collectors") or ["procmon", "pcap", "tshark"])
    interface = str(cfg.get("network_interface") or cfg.get("interface") or "1")
    network_pcap = dynamic_dir / "network.pcapng"
    procmon_pml = dynamic_dir / "procmon.pml"
    events: list[dict[str, Any]] = []
    availability = {
        "procmon": _tool_available(tools.get("procmon", "")),
        "dumpcap": _tool_available(tools.get("dumpcap", "")),
        "tshark": _tool_available(tools.get("tshark", "")),
    }

    def record(event: str, **kwargs: Any) -> None:
        item = {"event": event, "timestamp": time.time()}
        item.update(kwargs)
        events.append(item)

    def write_status(status: str, **kwargs: Any) -> None:
        payload = {
            "status": status,
            "mode": mode,
            "sample_path": str(sample),
            "timeout_seconds": timeout_seconds,
            "collectors": sorted(collectors),
            "tool_availability": availability,
            "events": events,
            "outputs": {
                "procmon_pml": str(procmon_pml),
                "network_pcap": str(network_pcap),
                "network_summary": str(dynamic_dir / "network_summary.txt"),
                "dns": str(dynamic_dir / "dns.txt"),
                "http": str(dynamic_dir / "http.txt"),
                "conversations": str(dynamic_dir / "conversations.txt"),
            },
        }
        payload.update(kwargs)
        _write_json(dynamic_dir / "dynamic_status.json", payload)

    if mode == "dry_run":
        record("would_start_packet_capture", before_sample=True, tool=tools.get("dumpcap", ""), interface=interface)
        record("would_start_procmon", before_sample=True, tool=tools.get("procmon", ""))
        record("would_execute_sample", sample=str(sample), timeout_seconds=timeout_seconds)
        record("would_stop_collectors", after_sample=True)
        record("would_parse_pcap", tool=tools.get("tshark", ""))
        write_status("dry_run")
        return ["dynamic.collectors (dry_run)"]

    capture_enabled = "pcap" in collectors and availability["dumpcap"]
    procmon_enabled = "procmon" in collectors and availability["procmon"]
    if not capture_enabled and not procmon_enabled:
        note = "Dynamic analysis skipped: no configured collector is available."
        (dynamic_dir / "_SKIPPED").write_text(note, encoding="utf-8")
        record("skipped_no_collectors", reason=note)
        write_status("skipped", reason=note)
        return ["dynamic.skipped"]

    dumpcap_proc: subprocess.Popen | None = None
    try:
        if capture_enabled:
            cmd = [tools["dumpcap"], "-i", interface, "-w", str(network_pcap)]
            dumpcap_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            record("packet_capture_started", before_sample=True, command=cmd, pid=dumpcap_proc.pid)
            write_status("collecting")
            time.sleep(2.0)

        if procmon_enabled:
            cmd = [tools["procmon"], "/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", str(procmon_pml)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            record("procmon_started", before_sample=True, command=cmd, exit_code=proc.returncode, stderr=(proc.stderr or "")[:1000])
            write_status("collecting")
            time.sleep(1.0)

        sample_proc = subprocess.Popen([str(sample)], cwd=str(sample.parent), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        record("sample_started", pid=sample_proc.pid, timeout_seconds=timeout_seconds)
        write_status("collecting")
        try:
            sample_proc.wait(timeout=max(1, timeout_seconds))
            record("sample_exited", exit_code=sample_proc.returncode)
        except subprocess.TimeoutExpired:
            sample_proc.terminate()
            try:
                sample_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sample_proc.kill()
                sample_proc.wait(timeout=5)
            record("sample_timeout_terminated", exit_code=sample_proc.returncode)
    finally:
        if procmon_enabled:
            try:
                cmd = [tools["procmon"], "/Terminate"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                record("procmon_stopped", after_sample=True, command=cmd, exit_code=proc.returncode, stderr=(proc.stderr or "")[:1000])
            except Exception as exc:
                record("procmon_stop_failed", error=f"{type(exc).__name__}: {exc}")
        if dumpcap_proc is not None:
            dumpcap_proc.terminate()
            try:
                _, stderr = dumpcap_proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                dumpcap_proc.kill()
                _, stderr = dumpcap_proc.communicate(timeout=10)
            record("packet_capture_stopped", after_sample=True, exit_code=dumpcap_proc.returncode, stderr=(stderr or "")[:1000])
        write_status("collecting")

    if "tshark" in collectors and availability["tshark"] and network_pcap.exists():
        for output_name, cmd in [
            ("network_summary.txt", [tools["tshark"], "-r", str(network_pcap), "-q", "-z", "conv,ip"]),
            ("dns.txt", [tools["tshark"], "-r", str(network_pcap), "-Y", "dns"]),
            ("http.txt", [tools["tshark"], "-r", str(network_pcap), "-Y", "http"]),
            ("conversations.txt", [tools["tshark"], "-r", str(network_pcap), "-q", "-z", "conv,tcp"]),
        ]:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            (dynamic_dir / output_name).write_text(
                (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else ""),
                encoding="utf-8",
                errors="replace",
            )
            record("pcap_parsed", command=cmd, output=str(dynamic_dir / output_name), exit_code=proc.returncode)

    write_status("collected")
    return ["dynamic.collectors"]


def _find_ida_executable() -> str | None:
    candidates: list[str] = []
    for env_name in ("IDA_PATH", "IDAT64_PATH", "IDAT_PATH", "IDA64_PATH"):
        value = os.environ.get(env_name, "").strip()
        if value:
            candidates.append(value)
    candidates.append(_resolve_tool_paths().get("ida", ""))
    candidates.extend(["idat64", "idat", "ida64", "ida"])

    expanded: list[str] = []
    for value in candidates:
        if not value:
            continue
        path = Path(value.strip('"'))
        if path.is_dir():
            for name in ("idat64.exe", "idat.exe", "idat64", "idat"):
                expanded.append(str(path / name))
        else:
            expanded.append(str(path))

    for value in expanded:
        path = Path(value)
        if path.is_file():
            return str(path)
        found = shutil.which(value)
        if found:
            return found
    return None


def _find_ghidra_executable() -> str | None:
    candidates: list[str] = []
    for env_name in ("CHATCLI_TOOL_GHIDRA", "GHIDRA_HEADLESS_PATH", "GHIDRA_HOME"):
        value = os.environ.get(env_name, "").strip()
        if value:
            candidates.append(value)
    candidates.append(_resolve_tool_paths().get("ghidra", ""))
    candidates.append("analyzeHeadless")

    expanded: list[str] = []
    for value in candidates:
        if not value:
            continue
        path = Path(value.strip('"'))
        if path.is_dir():
            for name in ("support/analyzeHeadless.bat", "support/analyzeHeadless"):
                expanded.append(str(path / name))
        else:
            expanded.append(str(path))

    for value in expanded:
        path = Path(value)
        if path.is_file():
            return str(path)
        found = shutil.which(value)
        if found:
            return found
    return None


IDA_EXTRACT_SCRIPT = r'''
import json
import sys

import idaapi
import idautils
import idc

out_path = sys.argv[1]
idaapi.auto_wait()

def hx(value):
    try:
        return hex(int(value))
    except Exception:
        return str(value)

data = {
    "input_file": idc.get_input_file_path(),
    "imagebase": hx(idaapi.get_imagebase()),
    "processor": idaapi.get_idp_name(),
    "functions": [],
    "imports": [],
    "strings": [],
}

for index, ea in enumerate(idautils.Functions()):
    if index >= 500:
        break
    func = idaapi.get_func(ea)
    data["functions"].append({
        "ea": hx(ea),
        "name": idc.get_func_name(ea),
        "start": hx(func.start_ea) if func else hx(ea),
        "end": hx(func.end_ea) if func else "",
    })

for mod_index in range(idaapi.get_import_module_qty()):
    mod_name = idaapi.get_import_module_name(mod_index) or ""
    def cb(ea, name, ordinal):
        data["imports"].append({
            "module": mod_name,
            "ea": hx(ea),
            "name": name or "",
            "ordinal": ordinal,
        })
        return True
    idaapi.enum_import_names(mod_index, cb)
    if len(data["imports"]) >= 2000:
        break

strings = idautils.Strings()
strings.setup(strtypes=[0, 1], minlen=4)
for index, item in enumerate(strings):
    if index >= 2000:
        break
    try:
        value = str(item)
    except Exception:
        value = ""
    data["strings"].append({
        "ea": hx(item.ea),
        "value": value[:500],
    })

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

idc.qexit(0)
'''


def _run_ida_headless(outbox: Path, sample: Path, mode: str) -> tuple[list[str], list[str]]:
    reverse_dir = outbox / "reverse"
    reverse_dir.mkdir(parents=True, exist_ok=True)
    if mode == "dry_run":
        return ["reverse.ida_headless (dry_run)"], []

    ida = _find_ida_executable()
    if not ida:
        return [], ["reverse.ida_headless (IDA executable not found; set IDA_PATH or IDAT_PATH)"]

    tmp_dir = BASE_DIR / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    script_path = tmp_dir / "chatcli_ida_extract.py"
    output_path = reverse_dir / "ida_headless.json"
    script_path.write_text(IDA_EXTRACT_SCRIPT, encoding="utf-8")
    script_arg = f'-S"{script_path}" "{output_path}"'
    command = [ida, "-A", script_arg, str(sample)]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
            cwd=str(tmp_dir),
        )
        (reverse_dir / "ida_headless.stdout.txt").write_text(proc.stdout or "", encoding="utf-8", errors="replace")
        (reverse_dir / "ida_headless.stderr.txt").write_text(proc.stderr or "", encoding="utf-8", errors="replace")
        if proc.returncode == 0 and output_path.is_file():
            return ["reverse.ida_headless"], []
        return [], [f"reverse.ida_headless (exit={proc.returncode})"]
    except subprocess.TimeoutExpired:
        return [], ["reverse.ida_headless (timeout)"]
    except Exception as exc:
        return [], [f"reverse.ida_headless ({type(exc).__name__}: {exc})"]


def _run_ghidra_headless(outbox: Path, sample: Path, mode: str) -> tuple[list[str], list[str]]:
    reverse_dir = outbox / "reverse"
    reverse_dir.mkdir(parents=True, exist_ok=True)
    if mode == "dry_run":
        return ["reverse.ghidra_headless (dry_run)"], []

    ghidra = _find_ghidra_executable()
    if not ghidra:
        return [], ["reverse.ghidra_headless (Ghidra analyzeHeadless not found)"]

    project_root = BASE_DIR / "tmp" / "ghidra_projects"
    project_root.mkdir(parents=True, exist_ok=True)
    project_name = f"chatcli_{sample.stem}_{int(time.time())}"
    command = [
        ghidra,
        str(project_root),
        project_name,
        "-import",
        str(sample),
        "-deleteProject",
    ]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
            cwd=str(project_root),
        )
        output = (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
        (reverse_dir / "ghidra_headless.txt").write_text(output, encoding="utf-8", errors="replace")
        if proc.returncode == 0:
            return ["reverse.ghidra_headless"], []
        return [], [f"reverse.ghidra_headless (exit={proc.returncode})"]
    except subprocess.TimeoutExpired:
        return [], ["reverse.ghidra_headless (timeout)"]
    except Exception as exc:
        return [], [f"reverse.ghidra_headless ({type(exc).__name__}: {exc})"]


def _run_verify(outbox: Path, case_id: str, sample: Path, sample_sha256: str, mode: str) -> list[str]:
    verify_dir = outbox / "verify"
    verify_dir.mkdir(parents=True, exist_ok=True)
    data = _security_status()
    data.update({
        "job_id": case_id,
        "sample_path": str(sample),
        "sample_sha256": sample_sha256,
        "mode": mode,
    })
    _write_json(verify_dir / "server_status_after.json", data)
    return ["verify.server_status"]


def _run_job(case_id: str, mode: str) -> dict[str, Any]:
    case_dir = _case_dir(case_id)
    job_file = case_dir / "job.json"
    if not job_file.is_file():
        raise FileNotFoundError(f"job.json not found for {case_id}")
    job = json.loads(job_file.read_text(encoding="utf-8"))
    plan = job.get("analysis_plan", {"static": True})
    sample = _resolve_sample(case_id, job)
    sample_sha256 = _sha256_file(sample)
    outbox = OUTBOX_DIR / case_id
    outbox.mkdir(parents=True, exist_ok=True)

    steps_done: list[str] = []
    steps_failed: list[str] = []
    _write_json(outbox / "status.json", {
        "job_id": case_id,
        "status": "running",
        "sample_sha256": sample_sha256,
        "started_at": time.time(),
    })

    if plan.get("static", True):
        done, failed = _run_static(case_id, outbox, sample, mode)
        steps_done.extend(done)
        steps_failed.extend(failed)
    if plan.get("ida", False) or plan.get("reverse", False):
        done, failed = _run_ida_headless(outbox, sample, mode)
        steps_done.extend(done)
        steps_failed.extend(failed)
    if plan.get("ghidra", False):
        done, failed = _run_ghidra_headless(outbox, sample, mode)
        steps_done.extend(done)
        steps_failed.extend(failed)
    if plan.get("dynamic", False):
        steps_done.extend(_run_dynamic_placeholder(outbox, mode, sample, job.get("dynamic_config", {})))
    if plan.get("network", False):
        (outbox / "dynamic").mkdir(parents=True, exist_ok=True)
        (outbox / "dynamic" / "_NETWORK_NOTE").write_text(
            "Network capture will be produced by the dynamic collector when implemented.",
            encoding="utf-8",
        )
        steps_done.append("network.placeholder")
    if plan.get("verify", False):
        steps_done.extend(_run_verify(outbox, case_id, sample, sample_sha256, mode))

    status = "done"
    _write_json(outbox / "status.json", {
        "job_id": case_id,
        "status": status,
        "sample_sha256": sample_sha256,
        "steps_completed": steps_done,
        "steps_failed": steps_failed,
        "completed_at": time.time(),
    })
    (outbox / "_DONE").touch()
    failed_marker = outbox / "_FAILED"
    if failed_marker.exists():
        failed_marker.unlink()
    return {
        "case_id": case_id,
        "status": status,
        "steps_completed": steps_done,
        "steps_failed": steps_failed,
    }


@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy",
        "version": "0.2.0",
        "cases_dir": str(CASES_DIR),
        "outbox_dir": str(OUTBOX_DIR),
        "auth_configured": bool(AGENT_TOKEN),
    }


@app.get("/api/v1/tools")
async def tools(authorization: str | None = Header(None)):
    _auth(authorization)
    return {"tools": _tool_inventory()}


@app.get("/api/v1/status")
async def status(probes: bool = False, authorization: str | None = Header(None)):
    _auth(authorization)
    return _server_status(include_probes=probes)


@app.get("/api/v1/security/status")
async def security_status(authorization: str | None = Header(None)):
    _auth(authorization)
    return _security_status()


@app.get("/api/v1/monitor/snapshot")
async def monitor_snapshot(case_id: str = "", probes: bool = True, authorization: str | None = Header(None)):
    _auth(authorization)
    return _monitor_snapshot(case_id=case_id, include_probes=probes)


@app.post("/api/v1/exec")
async def exec_command(body: dict[str, Any], authorization: str | None = Header(None)):
    _auth(authorization)
    command = (body or {}).get("command", "")
    if not command:
        raise HTTPException(400, detail="command is required")
    return _run_probe(
        command,
        timeout=int((body or {}).get("timeout", 300) or 300),
    )


@app.post("/api/v1/cases/prepare")
async def prepare_case(body: dict[str, Any], authorization: str | None = Header(None)):
    _auth(authorization)
    case_id = str(body.get("case_id") or f"case-{uuid.uuid4().hex[:12]}")
    case_dir = _case_dir(case_id)
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "sample").mkdir(exist_ok=True)

    updates = {
        "case_id": case_id,
        "status": "prepared",
        "analysis_plan": body.get("analysis_plan", {"static": True}),
        "dynamic_config": body.get("dynamic_config", {}),
        "created_at": time.time(),
    }
    sample_path = str(body.get("sample_path", "") or "").strip()
    if sample_path:
        updates.update(_sample_metadata(sample_path))
    _write_state(case_id, updates)
    _write_job_file(case_id)
    return {
        "case_id": case_id,
        "status": "prepared",
        "case_dir": str(case_dir),
        "sample_path": sample_path,
        "sample_exists": bool(updates.get("sample_exists", False)),
    }


@app.post("/api/v1/cases/{case_id}/sample")
async def upload_sample(case_id: str, file: UploadFile, authorization: str | None = Header(None)):
    _auth(authorization)
    case_dir = _case_dir(case_id)
    if not case_dir.is_dir():
        raise HTTPException(404, detail=f"Case {case_id} not found")
    content = await file.read()
    sample_path = case_dir / "sample" / (file.filename or "sample.bin")
    sample_path.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()
    _write_state(case_id, {
        "sample_filename": sample_path.name,
        "sample_sha256": sha256,
        "sample_size_bytes": len(content),
        "sample_uploaded_at": time.time(),
    })
    _write_job_file(case_id)
    return {
        "case_id": case_id,
        "filename": sample_path.name,
        "sha256": sha256,
        "size_bytes": len(content),
    }


@app.post("/api/v1/cases/{case_id}/run")
async def run_case(case_id: str, body: dict[str, Any] | None = None, authorization: str | None = Header(None)):
    _auth(authorization)
    if not _case_dir(case_id).is_dir():
        raise HTTPException(404, detail=f"Case {case_id} not found")
    state = _read_state(case_id)
    if state.get("status") == "running":
        return {"case_id": case_id, "status": "already_running"}

    body = body or {}
    updates: dict[str, Any] = {}
    if body.get("analysis_plan"):
        updates["analysis_plan"] = body["analysis_plan"]
    if body.get("dynamic_config"):
        updates["dynamic_config"] = body["dynamic_config"]
    if str(body.get("sample_path", "") or "").strip():
        updates.update(_sample_metadata(str(body["sample_path"]).strip()))
    if updates:
        _write_state(case_id, updates)
    _write_job_file(case_id)

    mode = str(body.get("mode", "real") or "real")
    _write_state(case_id, {"status": "running", "started_at": time.time()})
    try:
        result = _run_job(case_id, mode=mode)
        _write_state(case_id, {
            "status": result["status"],
            "completed_at": time.time(),
            "steps_completed": result["steps_completed"],
            "steps_failed": result["steps_failed"],
        })
        return result
    except Exception as exc:
        outbox = OUTBOX_DIR / case_id
        outbox.mkdir(parents=True, exist_ok=True)
        (outbox / "_FAILED").write_text(str(exc), encoding="utf-8")
        _write_state(case_id, {"status": "failed", "error": str(exc)})
        return {"case_id": case_id, "status": "failed", "error": str(exc)}


@app.get("/api/v1/cases/{case_id}/status")
async def case_status(case_id: str, authorization: str | None = Header(None)):
    _auth(authorization)
    if not _case_dir(case_id).is_dir():
        raise HTTPException(404, detail=f"Case {case_id} not found")
    state = _read_state(case_id)
    outbox = OUTBOX_DIR / case_id
    done = (outbox / "_DONE").exists()
    failed = (outbox / "_FAILED").exists()
    files = []
    if outbox.is_dir():
        for path in outbox.rglob("*"):
            if path.is_file() and not path.name.startswith("."):
                files.append({"path": str(path.relative_to(outbox)), "size": path.stat().st_size})
    return {
        "case_id": case_id,
        **state,
        "done_marker": done,
        "failed_marker": failed,
        "outbox_files": files,
    }


@app.get("/api/v1/cases/{case_id}/results")
async def download_results(case_id: str, authorization: str | None = Header(None)):
    _auth(authorization)
    outbox = OUTBOX_DIR / case_id
    if not outbox.is_dir():
        raise HTTPException(404, detail=f"No results for case {case_id}")
    tmp_dir = Path(tempfile.mkdtemp())
    zip_base = tmp_dir / f"{case_id}_results"
    shutil.make_archive(str(zip_base), "zip", outbox)
    return FileResponse(
        str(zip_base) + ".zip",
        media_type="application/zip",
        filename=f"{case_id}_results.zip",
    )


@app.get("/api/v1/cases")
async def list_cases(authorization: str | None = Header(None)):
    _auth(authorization)
    cases = []
    if CASES_DIR.is_dir():
        for case_dir in sorted(CASES_DIR.iterdir()):
            if case_dir.is_dir():
                state = _read_state(case_dir.name)
                cases.append({
                    "case_id": case_dir.name,
                    "status": state.get("status", "unknown"),
                    "sample_sha256": state.get("sample_sha256", ""),
                    "created_at": state.get("created_at", 0),
                })
    return {"cases": cases, "total": len(cases)}


@app.on_event("startup")
async def _startup():
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    tools = _resolve_tool_paths()
    inventory = _tool_inventory()
    available = sum(1 for info in inventory.values() if info.get("available"))
    print("chatcli standalone Guest Agent")
    print(f"  Base:  {BASE_DIR}")
    print(f"  Cases: {CASES_DIR}")
    print(f"  Tools: {available}/{len(inventory)} available")
    print(f"  Auth:  {'configured' if AGENT_TOKEN else 'MISSING'}")


def main() -> None:
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="chatcli standalone Guest Agent")
    parser.add_argument("--host", default=os.environ.get("CHATCLI_AGENT_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CHATCLI_AGENT_PORT", "8443")))
    args = parser.parse_args()
    uvicorn.run("__main__:app", host=args.host, port=args.port, reload=False, log_level="info")


if __name__ == "__main__":
    main()
