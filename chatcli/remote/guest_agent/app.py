"""Guest Agent — HTTP server running on Tencent Cloud analysis machine.

FastAPI server that manages analysis cases: receive samples, trigger
static/dynamic analysis, report status, and serve results. Writes file
signals (_DONE / _FAILED) for completion detection.

Ported from Cloud-AV-Agent-Lab guest_agent_server/app.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse

from .auth import TOKEN_ENV, load_required_token, verify_bearer_token

DEFAULT_WORKDIR = Path("C:/analysis")
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

    case_dir = _case_dir(case_id)
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "sample").mkdir(exist_ok=True)

    _write_case_state(case_id, {
        "case_id": case_id,
        "status": "prepared",
        "analysis_plan": analysis_plan,
        "created_at": time.time(),
        "steps": [],
    })

    return {
        "case_id": case_id,
        "status": "prepared",
        "case_dir": str(case_dir),
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

    mode = (body or {}).get("mode", "real")
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
