"""Rich Live Dashboard — real-time remote job and observer status.

Displays a split-panel dashboard showing:
- Remote Guest Agent health
- Active job status (inbox → running → done)
- Observer child agent progress
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def _safe_str(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else ""
    return s[:max_len]


def _status_icon(status: str) -> str:
    icons = {
        "done": "✅", "completed": "✅",
        "running": "⏳", "in_progress": "⏳",
        "failed": "❌", "error": "❌", "timeout": "⏰",
        "queued": "⏸", "pending": "⏸",
        "blocked": "🚫",
    }
    return icons.get(status, "❓")


class Dashboard:
    """Real-time Rich Live dashboard for remote analysis monitoring.

    Usage:
        dash = Dashboard(get_remote_status, get_child_status)
        dash.run()  # blocks until interrupted
    """

    def __init__(
        self,
        remote_status_fn: Callable[[], dict] | None = None,
        child_status_fn: Callable[[], list[dict]] | None = None,
        refresh_seconds: float = 3.0,
        case_id: str = "",
    ):
        self._remote_fn = remote_status_fn or (lambda: {})
        self._child_fn = child_status_fn or (lambda: [])
        self.refresh_seconds = refresh_seconds
        self.case_id = case_id
        self._running = False

    def run(self):
        """Start the live dashboard. Blocks until KeyboardInterrupt."""
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
        )
        layout["body"].split_column(
            Layout(name="remote", ratio=1),
            Layout(name="monitor", ratio=2),
            Layout(name="children", ratio=2),
        )

        self._running = True
        try:
            with Live(layout, refresh_per_second=4, screen=True) as live:
                while self._running:
                    layout["header"].update(self._render_header())
                    layout["remote"].update(self._render_remote())
                    layout["monitor"].update(self._render_monitor())
                    layout["children"].update(self._render_children())
                    time.sleep(self.refresh_seconds)
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False

    def stop(self):
        self._running = False

    def _render_header(self) -> Panel:
        text = Text("chatcli Analysis Monitor", style="bold cyan")
        if self.case_id:
            text.append(f"  │  case {self.case_id}", style="green")
        text.append(f"  │  {time.strftime('%H:%M:%S')}", style="dim")
        return Panel(text, box=box.SIMPLE)

    def _render_remote(self) -> Panel:
        try:
            data = self._remote_fn()
        except Exception:
            data = {}

        table = Table(title="Remote Server", box=box.SIMPLE, show_header=False)
        table.add_column("Key", style="cyan", width=16)
        table.add_column("Value")

        health = data.get("health", {})
        if health:
            table.add_row("Status", health.get("status", "?"))
            table.add_row("Version", health.get("version", "?"))

        cases = data.get("cases", [])
        counts = {"done": 0, "running": 0, "failed": 0, "pending": 0}
        for c in cases:
            s = c.get("status", "pending")
            counts[s] = counts.get(s, 0) + 1

        table.add_row("Cases", (
            f"{_status_icon('done')} {counts['done']} done  "
            f"{_status_icon('running')} {counts['running']} running  "
            f"{_status_icon('failed')} {counts['failed']} failed"
        ))

        return Panel(table, title="Remote Server", border_style="blue")

    def _render_monitor(self) -> Panel:
        try:
            data = self._remote_fn()
        except Exception:
            data = {}

        monitor = data.get("monitor", {})
        agents = monitor.get("observer_agents", [])
        traffic = monitor.get("traffic_capture", {})
        dynamic_status = monitor.get("dynamic_status", {})
        process_metrics = monitor.get("process_metrics", {})
        events = dynamic_status.get("events", []) if isinstance(dynamic_status, dict) else []

        table = Table(title="Remote Telemetry", box=box.SIMPLE)
        table.add_column("Observer", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Summary")

        if not monitor:
            table.add_row("monitor", "unavailable", "Guest Agent monitor endpoint did not return data")
        else:
            table.add_row(
                "dynamic",
                dynamic_status.get("status", "none"),
                f"case={monitor.get('case_id') or '(latest)'}; "
                f"pcap={traffic.get('pcap_bytes', 0)} bytes; "
                f"events={len(events)}; processes={process_metrics.get('count', 0)}; "
                f"files={len(monitor.get('file_activity', []))}",
            )
            for agent in agents:
                status = agent.get("status", "?")
                table.add_row(
                    agent.get("name", "?"),
                    f"{_status_icon(status)} {status}",
                    _safe_str(agent.get("summary", ""), 90),
                )

        return Panel(table, title="Telemetry", border_style="yellow")

    def _render_children(self) -> Panel:
        try:
            children = self._child_fn()
        except Exception:
            children = []

        table = Table(title="Observer Agents", box=box.SIMPLE)
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Role", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Summary")

        if not children:
            table.add_row("—", "no observers", "—", "Run /observe to spawn")

        for c in children:
            status = c.get("status", "?")
            table.add_row(
                c.get("name", "?"),
                c.get("role", "?"),
                f"{_status_icon(status)} {status}",
                _safe_str(c.get("summary", ""), 80),
            )

        return Panel(table, title="Observers", border_style="green")


def build_dashboard_callbacks(
    remote_base_url: str = "",
    remote_token: str = "",
    children_dict: dict | None = None,
    case_id: str = "",
    include_probes: bool = True,
) -> tuple[Callable[[], dict], Callable[[], list[dict]]]:
    """Build callback functions for the Dashboard from chatcli state.

    Args:
        remote_base_url: Guest Agent base URL
        remote_token: Guest Agent token
        children_dict: Reference to REPL.children dict (updated by REPL)

    Returns (remote_status_fn, child_status_fn)
    """

    def remote_status() -> dict:
        if not remote_base_url:
            return {"health": {"status": "not configured"}}
        try:
            import httpx
            r = httpx.get(
                f"{remote_base_url}/api/v1/health",
                timeout=5,
            )
            health = r.json() if r.status_code == 200 else {"status": str(r.status_code)}

            if remote_token:
                r2 = httpx.get(
                    f"{remote_base_url}/api/v1/cases",
                    headers={"Authorization": f"Bearer {remote_token}"},
                    timeout=5,
                )
                cases = r2.json().get("cases", []) if r2.status_code == 200 else []
                params = {"probes": "true" if include_probes else "false"}
                if case_id:
                    params["case_id"] = case_id
                r3 = httpx.get(
                    f"{remote_base_url}/api/v1/monitor/snapshot",
                    params=params,
                    headers={"Authorization": f"Bearer {remote_token}"},
                    timeout=8,
                )
                monitor = r3.json() if r3.status_code == 200 else {}
            else:
                cases = []
                monitor = {}

            return {"health": health, "cases": cases, "monitor": monitor}
        except Exception as exc:
            return {"health": {"status": f"error: {exc}"}}

    def child_status() -> list[dict]:
        if children_dict is None:
            return []
        result = []
        for name, child in children_dict.items():
            role = getattr(child, "_observer_role", "")
            result.append({
                "name": name,
                "role": role,
                "status": child.status,
                "summary": child.summary or child.task or "",
            })
        return sorted(result, key=lambda x: x["name"])

    return remote_status, child_status
