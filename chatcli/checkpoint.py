"""Safety net for self-modification — file backups + crash detection.

Why: when chatcli edits its own source code, a bad edit can break the tool
mid-conversation. This module provides:

1. Auto-backup before modifying any file in chatcli's own source tree
2. Crash detection — knows if the last session ended abnormally
3. /checkpoint command — manual save/restore points
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

BACKUP_DIR = Path.home() / ".chatcli" / "backups"
RUNNING_MARKER = Path.home() / ".chatcli" / ".running"
MAX_BACKUPS = 30

# Files that, when modified, trigger auto-backup
_OWN_PACKAGE_ROOT = Path(__file__).resolve().parent  # chatcli/ package dir


def running_marker_for_workspace(workspace: str | Path | None = None) -> Path:
    if workspace:
        return Path(workspace).resolve() / ".chatcli" / ".running"
    return RUNNING_MARKER


def _is_own_source(file_path: str | Path) -> bool:
    """Check if a file belongs to chatcli's own source tree."""
    try:
        resolved = Path(file_path).resolve()
        return str(resolved).startswith(str(_OWN_PACKAGE_ROOT))
    except Exception:
        return False


def backup_file(file_path: str | Path) -> Optional[str]:
    """Backup a file before modification. Returns backup ID or None."""
    src = Path(file_path)
    if not src.exists():
        return None

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_id = f"{ts}_{src.name}"

    dest_dir = BACKUP_DIR / backup_id
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Copy file
    shutil.copy2(str(src), str(dest_dir / src.name))

    # Save metadata
    meta = {
        "id": backup_id,
        "file": str(src),
        "time": datetime.now().isoformat(),
    }
    (dest_dir / "backup.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    return backup_id


def restore_backup(backup_id: str) -> bool:
    """Restore a file from backup. Returns True on success."""
    backup_path = BACKUP_DIR / backup_id
    meta_file = backup_path / "backup.json"
    if not meta_file.exists():
        return False

    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        src_file = Path(meta["file"])
        backup_file_path = backup_path / src_file.name

        if not backup_file_path.exists():
            return False

        # Restore
        src_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(backup_file_path), str(src_file))
        return True
    except Exception:
        return False


def list_backups() -> list[dict]:
    """List recent backups, newest first."""
    if not BACKUP_DIR.exists():
        return []

    backups = []
    for d in sorted(BACKUP_DIR.iterdir(), reverse=True):
        meta_file = d / "backup.json"
        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                backups.append(meta)
            except Exception:
                import sys
                print(f"[chatcli] Warning: corrupt backup {d.name}", file=sys.stderr)

    return backups[:50]


def prune_old_backups():
    """Remove oldest backups beyond MAX_BACKUPS."""
    if not BACKUP_DIR.exists():
        return
    dirs = sorted(BACKUP_DIR.iterdir(), key=lambda d: d.stat().st_mtime)
    to_remove = dirs[:-MAX_BACKUPS] if len(dirs) > MAX_BACKUPS else []
    for d in to_remove:
        try:
            shutil.rmtree(d)
        except Exception as e:
            print(f"[chatcli] Warning: failed to prune backup {d.name}: {e}", file=sys.stderr)


# ── Crash detection ──────────────────────────────────────────────


def mark_running(workspace: str | Path | None = None):
    """Mark that a chatcli session is currently running."""
    marker = running_marker_for_workspace(workspace)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps({
            "pid": os.getpid(),
            "started": datetime.now().isoformat(),
            "workspace": str(Path(workspace).resolve()) if workspace else "",
        }),
        encoding="utf-8",
    )


def mark_clean(workspace: str | Path | None = None):
    """Mark that the session exited cleanly."""
    try:
        running_marker_for_workspace(workspace).unlink(missing_ok=True)
    except Exception:
        pass


def was_crashed(workspace: str | Path | None = None) -> bool:
    """Check if the last session crashed (didn't exit cleanly)."""
    return running_marker_for_workspace(workspace).exists()


def get_crash_info(workspace: str | Path | None = None) -> Optional[dict]:
    """Get info about the crashed session, if any."""
    marker = running_marker_for_workspace(workspace)
    if not marker.exists():
        return None
    try:
        return json.loads(marker.read_text(encoding="utf-8"))
    except Exception:
        return None
