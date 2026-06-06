#!/usr/bin/env python3
"""
chatcli Remote Agent — 单文件零依赖部署（只需 fastapi + uvicorn）
==============================================================

从零部署（腾讯云 Windows 服务器，只需 Python 3.10+）:

    pip install fastapi uvicorn python-multipart
    curl -O https://raw.githubusercontent.com/cjh-1001/chatcli/master/chatcli/remote/standalone_agent.py
    $env:CHATCLI_GUEST_AGENT_TOKEN = "你的强随机Token"
    python standalone_agent.py --host 0.0.0.0 --port 8443

chatcli 侧连接:
    remote:
      enabled: true
      base_url: "http://<腾讯云IP>:8443"
      guest_agent_token: "你的强随机Token"

API:
    GET  /api/v1/health              # 公开
    POST /api/v1/cases/prepare       # 创建分析 case（需 auth）
    POST /api/v1/cases/{id}/sample   # 上传样本
    POST /api/v1/cases/{id}/run      # 触发分析（后台子进程执行 job_runner）
    GET  /api/v1/cases/{id}/status   # 查询进度 + 结果文件列表
    GET  /api/v1/cases/{id}/results  # 下载结果 ZIP
    GET  /api/v1/cases               # 列出所有 case
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────

BASE_DIR = Path(os.environ.get("CHATCLI_AGENT_DIR", "C:/analysis"))
CASES_DIR = BASE_DIR / "cases"
OUTBOX_DIR = BASE_DIR / "outbox"
TOKEN_ENV = "CHATCLI_GUEST_AGENT_TOKEN"
AGENT_PORT = int(os.environ.get("CHATCLI_AGENT_PORT", "8443"))
AGENT_HOST = os.environ.get("CHATCLI_AGENT_HOST", "0.0.0.0")

CASES_DIR.mkdir(parents=True, exist_ok=True)
OUTBOX_DIR.mkdir(parents=True, exist_ok=True)

AGENT_TOKEN = os.environ.get(TOKEN_ENV, "").strip()

if not AGENT_TOKEN:
    print(f"[WARN] {TOKEN_ENV} not set! All auth endpoints will reject requests.")
    print(f"       Set with: $env:{TOKEN_ENV} = 'your-strong-random-token'")


# ── Tool path configuration ────────────────────────────────────────
# Each tool defaults to its command name (assumed on PATH).
# Override with env var CHATCLI_TOOL_<NAME>, e.g.:
#   $env:CHATCLI_TOOL_CAPA = "F:\reverseTools\capa.exe"
#   $env:CHATCLI_TOOL_YARA = "F:\reverseTools\yara64.exe"

def _resolve_tool_paths() -> dict[str, str]:
    """Read tool paths from environment variables, falling back to defaults."""
    defaults = {
        "python": sys.executable,
        "ida": r"C:\Program Files\IDA Professional 9.0\idat.exe",
        "capa": f"\"{sys.executable}\" -m capa",
        "floss": f"\"{sys.executable}\" -m floss",
        "yara": r"C:\Program Files\reverseTools\yara64.exe",
        "diec": r"C:\Program Files\reverseTools\diec.exe",
        "exiftool": r"C:\Program Files\reverseTools\exiftool.exe",
        "upx": r"C:\Program Files\reverseTools\upx.exe",
        "binary_inspect": "binary_inspect",
    }
    resolved = {}
    for name, default in defaults.items():
        env_key = f"CHATCLI_TOOL_{name.upper()}"
        resolved[name] = os.environ.get(env_key, default)
    return resolved

TOOL_PATHS = _resolve_tool_paths()

# ── Static analysis tool definitions ──────────────────────────────

STATIC_TOOLS = [
    {
        "name": "binary_inspect",
        "output": "binary_inspect.json",
        "cmd": lambda t: [sys.executable, "-c",
            "import json,sys,hashlib,struct,re;"
            "data=open(sys.argv[1],'rb').read();"
            "h=hashlib.sha256(data).hexdigest();"
            "m=hashlib.md5(data).hexdigest();"
            "pe=bytes(data[:2])==b'MZ';"
            "strings=re.findall(rb'[\\x20-\\x7e]{4,}',data);"
            "info={'sha256':h,'md5':m,'size':len(data),'is_pe':pe,'string_count':len(strings),"
            "'strings':[s.decode('ascii','replace') for s in strings[:500]]};"
            "print(json.dumps(info,indent=2))",
            str(t)],
    },
    {
        "name": "strings_dump",
        "output": "strings.txt",
        "cmd": lambda t: [sys.executable, "-c",
            "import re,sys;data=open(sys.argv[1],'rb').read();"
            "strings=re.findall(rb'[\\x20-\\x7e]{4,}',data);"
            "for s in strings[:3000]:print(s.decode('ascii','replace'))",
            str(t)],
    },
]


# ── HTTP App ───────────────────────────────────────────────────────

from fastapi import FastAPI, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(title="chatcli-remote-agent", version="1.0.0")


# ── Auth ───────────────────────────────────────────────────────────

def _auth(authorization: str | None = Header(None)):
    if not AGENT_TOKEN:
        raise HTTPException(503, detail="server not configured: token not set")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, detail="missing bearer token")
    if authorization.removeprefix("Bearer ").strip() != AGENT_TOKEN:
        raise HTTPException(401, detail="invalid bearer token")


# ── Helpers ────────────────────────────────────────────────────────

def _case_dir(case_id: str) -> Path:
    return CASES_DIR / case_id

def _read_state(case_id: str) -> dict:
    sf = _case_dir(case_id) / "case_state.json"
    return json.loads(sf.read_text(encoding="utf-8")) if sf.is_file() else {}

def _write_state(case_id: str, updates: dict) -> dict:
    d = _case_dir(case_id)
    d.mkdir(parents=True, exist_ok=True)
    state = _read_state(case_id)
    state.update(updates)
    state["updated_at"] = time.time()
    tmp = d / "case_state.tmp"
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(d / "case_state.json")
    return state


# ── Endpoints ──────────────────────────────────────────────────────

@app.get("/api/v1/tools")
async def tools_list(authorization: str | None = Header(None)):
    """Return configured tool paths and availability (which tools exist on disk)."""
    _auth(authorization)
    tools = {}
    for name, path in sorted(TOOL_PATHS.items()):
        # Split out executable part for commands with args (e.g. "py -3 -m capa")
        parts = path.split(None, 1)
        exe_str = parts[0].strip('\"')
        exe = Path(exe_str)
        available = exe.is_file() if exe.is_absolute() else shutil.which(exe_str) is not None
        tools[name] = {"path": path, "available": available}
    return {"tools": tools}


@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy" if AGENT_TOKEN else "no_token",
        "version": "1.0.0",
        "python": sys.version,
        "cases_dir": str(CASES_DIR),
        "outbox_dir": str(OUTBOX_DIR),
        "tool_count": len(TOOL_PATHS),
    }


@app.post("/api/v1/cases/prepare")
async def prepare(body: dict, authorization: str | None = Header(None)):
    _auth(authorization)
    cid = body.get("case_id", "") or f"case-{hashlib.sha256(os.urandom(16)).hexdigest()[:12]}"
    plan = body.get("analysis_plan", {"static": True})
    d = _case_dir(cid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "sample").mkdir(exist_ok=True)
    _write_state(cid, {"case_id": cid, "status": "prepared", "analysis_plan": plan, "created_at": time.time()})
    return {"case_id": cid, "status": "prepared"}


@app.post("/api/v1/cases/{case_id}/sample")
async def upload(case_id: str, file: UploadFile, authorization: str | None = Header(None)):
    _auth(authorization)
    d = _case_dir(case_id)
    if not d.is_dir():
        raise HTTPException(404, f"case {case_id} not found. Call /cases/prepare first.")
    content = await file.read()
    sp = d / "sample" / (file.filename or "sample.bin")
    sp.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    _write_state(case_id, {"sample_filename": sp.name, "sample_sha256": sha, "sample_size": len(content)})
    return {"case_id": case_id, "filename": sp.name, "sha256": sha, "size_bytes": len(content)}


@app.post("/api/v1/cases/{case_id}/run")
async def run(case_id: str, body: dict | None = None, authorization: str | None = Header(None)):
    _auth(authorization)
    d = _case_dir(case_id)
    if not d.is_dir():
        raise HTTPException(404, f"case {case_id} not found")
    state = _read_state(case_id)
    if state.get("status") == "running":
        return {"case_id": case_id, "status": "already_running"}

    mode = (body or {}).get("mode", "real")
    plan = state.get("analysis_plan", {"static": True})
    _write_state(case_id, {"status": "running", "started_at": time.time()})

    # ── Execute analysis inline (simple static-only for now) ──
    outbox = OUTBOX_DIR / case_id
    outbox.mkdir(parents=True, exist_ok=True)

    sample_dir = d / "sample"
    samples = list(sample_dir.glob("*"))
    if not samples:
        _write_state(case_id, {"status": "failed", "error": "no sample uploaded"})
        return {"case_id": case_id, "status": "failed", "error": "no sample"}

    target = samples[0]
    steps_done = []
    steps_failed = []

    try:
        # Static analysis
        if plan.get("static", True):
            sd = outbox / "static"
            sd.mkdir(parents=True, exist_ok=True)
            for tool in STATIC_TOOLS:
                if mode == "dry_run":
                    steps_done.append(f"static.{tool['name']} (dry_run)")
                    continue
                try:
                    r = subprocess.run(tool["cmd"](target), capture_output=True, text=True, timeout=300)
                    (sd / tool["output"]).write_text(r.stdout or r.stderr or "", encoding="utf-8", errors="replace")
                    (steps_done if r.returncode == 0 else steps_failed).append(
                        f"static.{tool['name']}" + (f" (exit={r.returncode})" if r.returncode else "")
                    )
                except subprocess.TimeoutExpired:
                    steps_failed.append(f"static.{tool['name']} (timeout)")
                except Exception as e:
                    steps_failed.append(f"static.{tool['name']} ({e})")

        # Mark completion
        if not steps_failed:
            (outbox / "_DONE").touch()
            _write_state(case_id, {"status": "done", "steps_done": steps_done, "completed_at": time.time()})
            return {"case_id": case_id, "status": "done", "steps": steps_done}
        else:
            (outbox / "_FAILED").write_text("; ".join(steps_failed), encoding="utf-8")
            _write_state(case_id, {"status": "failed", "steps_done": steps_done, "steps_failed": steps_failed})
            return {"case_id": case_id, "status": "failed", "steps_done": steps_done, "steps_failed": steps_failed}

    except Exception as e:
        (outbox / "_FAILED").write_text(str(e), encoding="utf-8")
        _write_state(case_id, {"status": "failed", "error": str(e)})
        return {"case_id": case_id, "status": "failed", "error": str(e)}


@app.get("/api/v1/cases/{case_id}/status")
async def status(case_id: str, authorization: str | None = Header(None)):
    _auth(authorization)
    d = _case_dir(case_id)
    if not d.is_dir():
        raise HTTPException(404, f"case {case_id} not found")
    state = _read_state(case_id)
    ob = OUTBOX_DIR / case_id
    done = (ob / "_DONE").exists()
    failed = (ob / "_FAILED").exists()
    if done and state.get("status") != "done":
        state["status"] = "done"
    if failed and state.get("status") != "failed":
        state["status"] = "failed"
        state["error"] = (ob / "_FAILED").read_text(encoding="utf-8")[:500] if (ob / "_FAILED").is_file() else ""
    files = []
    if ob.is_dir():
        for p in ob.rglob("*"):
            if p.is_file() and not p.name.startswith("."):
                files.append({"path": str(p.relative_to(ob)), "size": p.stat().st_size})
    return {"case_id": case_id, **state, "done_marker": done, "failed_marker": failed, "files": files, "file_count": len(files)}


@app.get("/api/v1/cases/{case_id}/results")
async def results(case_id: str, authorization: str | None = Header(None)):
    _auth(authorization)
    ob = OUTBOX_DIR / case_id
    if not ob.is_dir():
        raise HTTPException(404, f"no results for {case_id}")
    tmp = Path(tempfile.mkdtemp())
    zp = tmp / case_id
    shutil.make_archive(str(zp), "zip", ob)
    return FileResponse(str(zp) + ".zip", media_type="application/zip", filename=f"{case_id}_results.zip")


@app.get("/api/v1/cases")
async def list_cases(authorization: str | None = Header(None)):
    _auth(authorization)
    cases = []
    for d in sorted(CASES_DIR.iterdir()) if CASES_DIR.is_dir() else []:
        if d.is_dir():
            s = _read_state(d.name)
            cases.append({"case_id": d.name, "status": s.get("status", "unknown"), "sha256": s.get("sample_sha256", ""), "created": s.get("created_at", 0)})
    return {"cases": cases, "total": len(cases)}


@app.post("/api/v1/exec")
async def exec_cmd(body: dict, authorization: str | None = Header(None)):
    """Execute an analysis command on the remote server. Returns stdout/stderr/exit_code."""
    _auth(authorization)
    cmd = (body or {}).get("command", "")
    if not cmd:
        raise HTTPException(400, "command is required")
    timeout = int((body or {}).get("timeout", 300))
    workdir = (body or {}).get("workdir", str(BASE_DIR))
    started = time.time()
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout, cwd=workdir)
        return {"exit_code": r.returncode, "stdout": r.stdout, "stderr": r.stderr,
                "elapsed_ms": int((time.time() - started) * 1000)}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"timeout after {timeout}s",
                "elapsed_ms": int((time.time() - started) * 1000)}


@app.on_event("startup")
async def _startup():
    for d in [CASES_DIR, OUTBOX_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    def _tool_available(tool_path: str) -> bool:
        parts = tool_path.split(None, 1)
        exe_str = parts[0].strip('"')
        exe = Path(exe_str)
        return exe.is_file() if exe.is_absolute() else shutil.which(exe_str) is not None
    available = sum(1 for t in TOOL_PATHS.values() if _tool_available(t))
    print(f"chatcli Remote Agent v1.1.0")
    print(f"  Listening: {AGENT_HOST}:{AGENT_PORT}")
    print(f"  Cases:     {CASES_DIR}")
    print(f"  Outbox:    {OUTBOX_DIR}")
    print(f"  Tools:     {available}/{len(TOOL_PATHS)} configured")
    print(f"  Auth:      {'configured' if AGENT_TOKEN else 'MISSING — set ' + TOKEN_ENV}")


# ── Entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="chatcli Remote Agent")
    p.add_argument("--host", default=AGENT_HOST)
    p.add_argument("--port", type=int, default=AGENT_PORT)
    args = p.parse_args()
    import uvicorn
    uvicorn.run("__main__:app", host=args.host, port=args.port, reload=False, log_level="info")
