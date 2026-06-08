"""Guest Agent — HTTP server running on Tencent Cloud analysis machine.

FastAPI server that manages analysis cases: receive samples, trigger
static/dynamic analysis, report status, and serve results. Writes file
signals (_DONE / _FAILED) for completion detection.

Ported from Cloud-AV-Agent-Lab guest_agent_server/app.py.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import csv
import io
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse

from chatcli.remote.tool_inventory import tool_inventory

from .auth import TOKEN_ENV, load_required_token, verify_bearer_token

DEFAULT_WORKDIR = Path(os.environ.get("CHATCLI_AGENT_DIR", "C:/analysis"))
DEFAULT_CASES_DIR = DEFAULT_WORKDIR / "cases"
EXEC_STDOUT_LIMIT = 60000
EXEC_STDERR_LIMIT = 12000

# ── Token loading (env vars only, never config files) ────────────

try:
    _AGENT_TOKEN = load_required_token()
except Exception:
    _AGENT_TOKEN = ""


async def _startup_check():
    if not _AGENT_TOKEN:
        print(
            f"\n*** WARNING: {TOKEN_ENV} is not set. "
            "All endpoints requiring auth will fail. ***\n"
        )
    DEFAULT_CASES_DIR.mkdir(parents=True, exist_ok=True)
    (DEFAULT_WORKDIR / "outbox").mkdir(parents=True, exist_ok=True)
    print(f"Cases dir: {DEFAULT_CASES_DIR}")
    print("Agent ready.")


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    await _startup_check()
    yield


app = FastAPI(title="chatcli-guest-agent", version="0.1.0", lifespan=_lifespan)


def _truncate_text(value: Any, limit: int) -> tuple[str, bool, int]:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text, False, len(text)
    return (
        text[:limit] + f"\n[TRUNCATED: output was {len(text)} chars, limit {limit}]",
        True,
        len(text),
    )


def _authorize(authorization: str | None = Header(None)) -> None:
    verify_bearer_token(authorization, _AGENT_TOKEN)


# ── Case metadata helpers ────────────────────────────────────────


def _case_dir(case_id: str) -> Path:
    return DEFAULT_CASES_DIR / case_id


def _read_case_state(case_id: str) -> dict[str, Any]:
    state_file = _case_dir(case_id) / "case_state.json"
    if state_file.is_file():
        return json.loads(state_file.read_text(encoding="utf-8"))
    return {}


def _write_case_state(case_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    case_dir = _case_dir(case_id)
    case_dir.mkdir(parents=True, exist_ok=True)
    state = _read_case_state(case_id)
    state.update(updates)
    state["updated_at"] = time.time()
    tmp = case_dir / "case_state.tmp"
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(case_dir / "case_state.json")
    return state


def _sample_metadata(sample_path: str) -> dict[str, Any]:
    if not sample_path:
        return {}
    path = Path(sample_path).expanduser()
    meta: dict[str, Any] = {
        "sample_path": str(path),
        "sample_exists": path.is_file(),
    }
    if not path.is_file():
        return meta
    import hashlib
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    meta.update({
        "sample_filename": path.name,
        "sample_sha256": sha256.hexdigest(),
        "sample_size_bytes": path.stat().st_size,
    })
    return meta


def _write_job_file(case_id: str, updates: dict[str, Any] | None = None) -> dict[str, Any]:
    """Persist the job_runner input file for uploaded or remote-path samples."""
    case_dir = _case_dir(case_id)
    state = _read_case_state(case_id)
    if updates:
        state.update(updates)
    job = {
        "job_id": case_id,
        "analysis_plan": state.get("analysis_plan", {"static": True}),
        "dynamic_config": state.get("dynamic_config", {}),
    }
    if state.get("sample_path"):
        job["sample_path"] = state["sample_path"]
    job_path = case_dir / "job.json"
    job_path.write_text(json.dumps(job, indent=2, ensure_ascii=False), encoding="utf-8")
    return job


def _run_case_subprocess(case_id: str, case_dir: Path, mode: str) -> dict[str, Any]:
    """Run job_runner and persist final case state."""
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "chatcli.remote.job_runner",
                str(case_dir),
                "--mode", mode,
                "--outbox", str(case_dir.parent.parent / "outbox"),
            ],
            capture_output=True,
            text=True,
            timeout=1800,
        )

        if result.returncode == 0:
            _write_case_state(case_id, {
                "status": "done",
                "completed_at": time.time(),
            })
            return {"case_id": case_id, "status": "done"}

        error = result.stderr[:500] if result.stderr else f"exit={result.returncode}"
        _write_case_state(case_id, {
            "status": "failed",
            "error": error,
        })
        return {"case_id": case_id, "status": "failed", "error": error}

    except subprocess.TimeoutExpired:
        _write_case_state(case_id, {"status": "timeout"})
        return {"case_id": case_id, "status": "timeout"}
    except Exception as exc:
        _write_case_state(case_id, {"status": "failed", "error": str(exc)})
        raise


def _run_case_subprocess_background(case_id: str, case_dir: Path, mode: str) -> None:
    try:
        _run_case_subprocess(case_id, case_dir, mode)
    except Exception:
        pass


def _run_probe(command: str, timeout: int = 5) -> dict[str, Any]:
    started = time.time()
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, min(timeout, 30)),
            cwd=str(DEFAULT_WORKDIR),
        )
        return {
            "command": command,
            "exit_code": result.returncode,
            "stdout": (result.stdout or "")[:12000],
            "stderr": (result.stderr or "")[:4000],
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


def _disk_snapshot(path: Path) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
    except Exception:
        usage = shutil.disk_usage(Path.cwd())
    return {
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
    }


def _server_status_snapshot(include_probes: bool = False) -> dict[str, Any]:
    tools = tool_inventory()
    cases = []
    if DEFAULT_CASES_DIR.is_dir():
        for case_dir in sorted(DEFAULT_CASES_DIR.iterdir()):
            if case_dir.is_dir():
                state = _read_case_state(case_dir.name)
                cases.append({
                    "case_id": case_dir.name,
                    "status": state.get("status", "unknown"),
                    "sample_sha256": state.get("sample_sha256", ""),
                    "updated_at": state.get("updated_at", 0),
                })
    snapshot: dict[str, Any] = {
        "status": "ok",
        "timestamp": time.time(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "pid": os.getpid(),
        "workdir": str(DEFAULT_WORKDIR),
        "cases_dir": str(DEFAULT_CASES_DIR),
        "outbox_dir": str(DEFAULT_WORKDIR / "outbox"),
        "disk": _disk_snapshot(DEFAULT_WORKDIR),
        "tool_count": len(tools),
        "tools_available": sum(1 for info in tools.values() if info.get("available")),
        "tools": tools,
        "cases": cases[-20:],
    }
    if include_probes:
        snapshot["probes"] = {
            "whoami": _run_probe("whoami", timeout=5),
            "hostname": _run_probe("hostname", timeout=5),
        }
        if os.name == "nt":
            snapshot["probes"].update({
                "ipconfig": _run_probe("ipconfig", timeout=8),
                "netstat": _run_probe("netstat -ano", timeout=10),
                "tasklist": _run_probe("tasklist", timeout=10),
            })
        else:
            snapshot["probes"].update({
                "ip_addr": _run_probe("ip addr", timeout=8),
                "ss": _run_probe("ss -tunap", timeout=10),
                "ps": _run_probe("ps aux", timeout=10),
            })
    return snapshot


def _security_status_snapshot() -> dict[str, Any]:
    """Collect a defensive post-analysis snapshot for manual review."""
    outbox = DEFAULT_WORKDIR / "outbox"
    recent_results = []
    if outbox.is_dir():
        for case_dir in sorted(outbox.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
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

    probes: dict[str, Any] = {
        "network_connections": _run_probe("netstat -ano" if os.name == "nt" else "ss -tunap", timeout=10),
        "processes": _run_probe("tasklist" if os.name == "nt" else "ps aux", timeout=10),
    }
    if os.name == "nt":
        probes.update({
            "services": _run_probe("sc query state= all", timeout=12),
            "scheduled_tasks": _run_probe("schtasks /query /fo LIST", timeout=15),
            "recent_system_events": _run_probe("wevtutil qe System /c:30 /f:text", timeout=15),
        })
    else:
        probes.update({
            "services": _run_probe("systemctl --no-pager --type=service --state=running", timeout=12),
            "cron": _run_probe("crontab -l", timeout=8),
            "recent_logs": _run_probe("journalctl -n 50 --no-pager", timeout=15),
        })

    failed_jobs = [item for item in recent_results if item["failed"]]
    findings = []
    if failed_jobs:
        findings.append({
            "severity": "medium",
            "title": "Recent analysis jobs failed",
            "detail": f"{len(failed_jobs)} recent outbox case(s) have _FAILED markers.",
        })
    if probes["network_connections"]["exit_code"] != 0:
        findings.append({
            "severity": "low",
            "title": "Network connection probe failed",
            "detail": probes["network_connections"]["stderr"][:300],
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
    outbox_root = DEFAULT_WORKDIR / "outbox"
    candidates: list[Path] = []
    if case_id:
        candidates.append(outbox_root / case_id / "dynamic" / "dynamic_status.json")
    elif outbox_root.is_dir():
        candidates = sorted(
            outbox_root.glob("*/dynamic/dynamic_status.json"),
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
        roots.extend([DEFAULT_CASES_DIR / case_id, DEFAULT_WORKDIR / "outbox" / case_id])
    configured = os.environ.get("CHATCLI_MONITOR_PATHS", "").strip()
    if configured:
        roots.extend(Path(item).expanduser() for item in configured.split(os.pathsep) if item.strip())
    if not roots:
        roots.extend([DEFAULT_WORKDIR / "outbox", DEFAULT_CASES_DIR])

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


def _process_metrics(process_probe: dict[str, Any] | None) -> dict[str, Any]:
    probe = process_probe or {}
    if not probe:
        return {"status": "not_collected", "count": 0, "sample": []}
    if probe.get("exit_code") != 0:
        return {"status": "error", "count": 0, "sample": [], "error": (probe.get("stderr") or "")[:300]}

    stdout = probe.get("stdout") or ""
    sample: list[dict[str, Any]] = []
    if os.name == "nt":
        for row in csv.reader(io.StringIO(stdout)):
            if len(row) < 5:
                continue
            name, pid, session_name, session_id, memory = row[:5]
            try:
                memory_kb = int("".join(ch for ch in memory if ch.isdigit()) or "0")
            except ValueError:
                memory_kb = 0
            sample.append({
                "name": name,
                "pid": pid,
                "session": session_name,
                "session_id": session_id,
                "memory_kb": memory_kb,
            })
    else:
        for line in stdout.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            sample.append({
                "user": parts[0],
                "pid": parts[1],
                "cpu_percent": parts[2],
                "memory_percent": parts[3],
                "command": parts[10],
            })

    top_memory = sorted(
        [item for item in sample if isinstance(item.get("memory_kb"), int)],
        key=lambda item: item.get("memory_kb", 0),
        reverse=True,
    )[:10]
    return {
        "status": "ok",
        "count": len(sample),
        "sample": sample[:25],
        "top_memory": top_memory,
    }


def _monitor_snapshot(case_id: str = "", include_probes: bool = True) -> dict[str, Any]:
    probes: dict[str, Any] = {}
    if include_probes:
        probes["processes"] = _run_probe("tasklist /fo csv /nh" if os.name == "nt" else "ps aux", timeout=10)
        probes["network_connections"] = _run_probe("netstat -ano" if os.name == "nt" else "ss -tunap", timeout=10)
        if os.name == "nt":
            probes.update({
                "registry_run_hkcu": _run_probe(r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"', timeout=8),
                "registry_run_hklm": _run_probe(r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"', timeout=8),
                "scheduled_tasks": _run_probe("schtasks /query /fo LIST /v", timeout=15),
                "services": _run_probe("sc query state= all", timeout=12),
            })
        else:
            probes.update({
                "scheduled_tasks": _run_probe("crontab -l", timeout=8),
                "services": _run_probe("systemctl --no-pager --type=service --state=running", timeout=12),
            })

    dynamic_status = _latest_dynamic_status(case_id)
    pcap_path = Path(dynamic_status.get("outputs", {}).get("network_pcap", "")) if dynamic_status else Path()
    pcap_bytes = pcap_path.stat().st_size if pcap_path.is_file() else 0
    file_activity = _recent_file_activity(case_id)
    process_metrics = _process_metrics(probes.get("processes"))

    def probe_state(name: str) -> str:
        if name not in probes:
            return "not_collected"
        return "ok" if probes[name].get("exit_code") == 0 else "review"

    observer_agents = [
        {
            "name": "process-observer",
            "role": "process_tree",
            "status": probe_state("processes"),
            "summary": f"Process snapshot collected; processes={process_metrics.get('count', 0)}.",
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
        "process_metrics": process_metrics,
        "file_activity": file_activity,
        "observer_agents": observer_agents,
        "probes": probes,
    }


# ── Health ────────────────────────────────────────────────────────


@app.get("/api/v1/health")
async def health():
    """Public health check — no auth required."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "cases_dir": str(DEFAULT_CASES_DIR),
        "auth_configured": bool(_AGENT_TOKEN),
    }


@app.get("/api/v1/tools")
async def list_tools(authorization: str | None = Header(None)):
    """Return configured remote tool paths and availability."""
    _authorize(authorization)
    return {"tools": tool_inventory()}


@app.get("/api/v1/status")
async def server_status(
    probes: bool = False,
    authorization: str | None = Header(None),
):
    """Return server metrics, tool availability, and recent case status."""
    _authorize(authorization)
    return _server_status_snapshot(include_probes=probes)


@app.get("/api/v1/security/status")
async def security_status(authorization: str | None = Header(None)):
    """Return a defensive post-analysis snapshot for compromise review."""
    _authorize(authorization)
    return _security_status_snapshot()


@app.get("/api/v1/monitor/snapshot")
async def monitor_snapshot(
    case_id: str = "",
    probes: bool = True,
    authorization: str | None = Header(None),
):
    """Return live host telemetry and observer-agent summaries for dashboards."""
    _authorize(authorization)
    return _monitor_snapshot(case_id=case_id, include_probes=probes)


@app.post("/api/v1/exec")
async def exec_command(
    body: dict[str, Any],
    authorization: str | None = Header(None),
):
    """Execute a diagnostic or analysis command on the remote server."""
    _authorize(authorization)
    command = (body or {}).get("command", "")
    if not command:
        raise HTTPException(status_code=400, detail="command is required")
    timeout = max(1, min(int((body or {}).get("timeout", 300) or 300), 1800))
    workdir = (body or {}).get("workdir", str(DEFAULT_WORKDIR))
    started = time.time()
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=workdir if Path(workdir).is_dir() else str(DEFAULT_WORKDIR),
        )
        stdout, stdout_truncated, stdout_chars = _truncate_text(result.stdout, EXEC_STDOUT_LIMIT)
        stderr, stderr_truncated, stderr_chars = _truncate_text(result.stderr, EXEC_STDERR_LIMIT)
        return {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "stdout_chars": stdout_chars,
            "stderr_chars": stderr_chars,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
            "elapsed_ms": int((time.time() - started) * 1000),
        }


# ── Case management ──────────────────────────────────────────────


@app.post("/api/v1/cases/prepare")
async def prepare_case(
    body: dict[str, Any],
    authorization: str | None = Header(None),
):
    """Create a new analysis case. Returns case_id."""
    _authorize(authorization)

    case_id = body.get("case_id", "")
    if not case_id:
        import uuid
        case_id = f"case-{uuid.uuid4().hex[:12]}"

    analysis_plan = body.get("analysis_plan", {"static": True})
    dynamic_config = body.get("dynamic_config", {})
    sample_path = str(body.get("sample_path", "")).strip()

    case_dir = _case_dir(case_id)
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "sample").mkdir(exist_ok=True)

    updates = {
        "case_id": case_id,
        "status": "prepared",
        "analysis_plan": analysis_plan,
        "dynamic_config": dynamic_config,
        "created_at": time.time(),
        "steps": [],
    }
    if sample_path:
        updates.update(_sample_metadata(sample_path))
    _write_case_state(case_id, updates)
    _write_job_file(case_id)

    return {
        "case_id": case_id,
        "status": "prepared",
        "case_dir": str(case_dir),
        "sample_path": sample_path,
        "sample_exists": bool(updates.get("sample_exists", False)),
    }


@app.post("/api/v1/cases/{case_id}/sample")
async def upload_sample(
    case_id: str,
    file: UploadFile,
    authorization: str | None = Header(None),
):
    """Upload a sample file to an existing case."""
    _authorize(authorization)

    case_dir = _case_dir(case_id)
    if not case_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    sample_dir = case_dir / "sample"
    sample_dir.mkdir(exist_ok=True)

    # Read file
    content = await file.read()
    sample_path = sample_dir / (file.filename or "sample.bin")
    sample_path.write_bytes(content)

    # Compute hash
    import hashlib
    sha256 = hashlib.sha256(content).hexdigest()

    _write_case_state(case_id, {
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
async def run_analysis(
    case_id: str,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(None),
):
    """Trigger analysis for a case. Runs job_runner as subprocess."""
    _authorize(authorization)

    case_dir = _case_dir(case_id)
    if not case_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    state = _read_case_state(case_id)
    if state.get("status") == "running":
        return {"case_id": case_id, "status": "already_running"}

    body = body or {}
    mode = body.get("mode", "real")
    updates: dict[str, Any] = {}
    if body.get("analysis_plan"):
        updates["analysis_plan"] = body["analysis_plan"]
    if body.get("dynamic_config"):
        updates["dynamic_config"] = body["dynamic_config"]
    if str(body.get("sample_path", "")).strip():
        updates.update(_sample_metadata(str(body["sample_path"]).strip()))
    if updates:
        _write_case_state(case_id, updates)
    _write_job_file(case_id)

    _write_case_state(case_id, {"status": "running", "started_at": time.time()})

    if bool(body.get("background", False)):
        thread = threading.Thread(
            target=_run_case_subprocess_background,
            args=(case_id, case_dir, mode),
            daemon=True,
        )
        thread.start()
        return {"case_id": case_id, "status": "running", "background": True}

    try:
        return _run_case_subprocess(case_id, case_dir, mode)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/cases/{case_id}/status")
async def case_status(
    case_id: str,
    authorization: str | None = Header(None),
):
    """Get case state including analysis progress."""
    _authorize(authorization)

    case_dir = _case_dir(case_id)
    if not case_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    state = _read_case_state(case_id)

    # Check for file signals in outbox
    outbox_dir = DEFAULT_WORKDIR / "outbox" / case_id
    done = (outbox_dir / "_DONE").exists()
    failed = (outbox_dir / "_FAILED").exists()

    if done and state.get("status") != "done":
        state["status"] = "done"
    elif failed and state.get("status") != "failed":
        error_msg = ""
        if (outbox_dir / "_FAILED").is_file():
            error_msg = (outbox_dir / "_FAILED").read_text(encoding="utf-8")[:200]
        state["status"] = "failed"
        state["error"] = error_msg

    # List available result files
    files = []
    if outbox_dir.is_dir():
        for p in outbox_dir.rglob("*"):
            if p.is_file() and not p.name.startswith("."):
                files.append({
                    "path": str(p.relative_to(outbox_dir)),
                    "size": p.stat().st_size,
                })

    return {
        "case_id": case_id,
        **state,
        "outbox_files": files,
        "done_marker": done,
        "failed_marker": failed,
    }


@app.get("/api/v1/cases/{case_id}/results")
async def download_results(
    case_id: str,
    authorization: str | None = Header(None),
):
    """Download all results as a ZIP file."""
    _authorize(authorization)

    outbox_dir = DEFAULT_WORKDIR / "outbox" / case_id
    if not outbox_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"No results for case {case_id}")

    import shutil
    import tempfile

    tmp_dir = Path(tempfile.mkdtemp())
    zip_path = tmp_dir / f"{case_id}_results"

    try:
        shutil.make_archive(str(zip_path), "zip", outbox_dir)
        zip_file = tmp_dir / f"{case_id}_results.zip"
        return FileResponse(
            zip_file,
            media_type="application/zip",
            filename=f"{case_id}_results.zip",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/cases")
async def list_cases(
    authorization: str | None = Header(None),
):
    """List all cases with status summary."""
    _authorize(authorization)

    cases = []
    for case_dir in sorted(DEFAULT_CASES_DIR.iterdir()):
        if not case_dir.is_dir():
            continue
        state = _read_case_state(case_dir.name)
        cases.append({
            "case_id": case_dir.name,
            "status": state.get("status", "unknown"),
            "sample_sha256": state.get("sample_sha256", ""),
            "created_at": state.get("created_at", 0),
        })

    return {"cases": cases, "total": len(cases)}
