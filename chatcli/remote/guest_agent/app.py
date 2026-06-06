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
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse

from chatcli.remote.tool_inventory import tool_inventory

from .auth import TOKEN_ENV, load_required_token, verify_bearer_token

DEFAULT_WORKDIR = Path(os.environ.get("CHATCLI_AGENT_DIR", "C:/analysis"))
DEFAULT_CASES_DIR = DEFAULT_WORKDIR / "cases"

app = FastAPI(title="chatcli-guest-agent", version="0.1.0")

# ── Token loading (env vars only, never config files) ────────────

try:
    _AGENT_TOKEN = load_required_token()
except Exception:
    _AGENT_TOKEN = ""


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
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
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

    # Run job_runner as subprocess
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
        else:
            _write_case_state(case_id, {
                "status": "failed",
                "error": result.stderr[:500] if result.stderr else f"exit={result.returncode}",
            })
            return {"case_id": case_id, "status": "failed", "error": result.stderr[:500]}

    except subprocess.TimeoutExpired:
        _write_case_state(case_id, {"status": "timeout"})
        return {"case_id": case_id, "status": "timeout"}
    except Exception as exc:
        _write_case_state(case_id, {"status": "failed", "error": str(exc)})
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


# ── Startup check ────────────────────────────────────────────────

@app.on_event("startup")
async def _startup_check():
    if not _AGENT_TOKEN:
        print(
            f"\n*** WARNING: {TOKEN_ENV} is not set. "
            "All endpoints requiring auth will fail. ***\n"
        )
    DEFAULT_CASES_DIR.mkdir(parents=True, exist_ok=True)
    (DEFAULT_WORKDIR / "outbox").mkdir(parents=True, exist_ok=True)
    print(f"Cases dir: {DEFAULT_CASES_DIR}")
    print(f"Agent ready.")
