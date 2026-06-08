"""Shared helpers for Tencent Cloud Guest Agent clients."""

from __future__ import annotations

from typing import Any


def remote_base_url(remote: Any) -> str:
    """Return the configured Guest Agent base URL from RemoteConfig-like data."""
    if remote is None:
        return ""
    configured = str(getattr(remote, "base_url", "") or "").strip()
    if configured:
        return configured.rstrip("/")
    host = str(getattr(remote, "host", "") or "").strip()
    if not host:
        return ""
    port = int(getattr(remote, "guest_agent_port", 8443) or 8443)
    return f"http://{host}:{port}"


def guest_agent_token(remote: Any) -> str:
    return str(getattr(remote, "guest_agent_token", "") or "").strip()


def build_guest_agent_client(config: Any, timeout: float = 300.0):
    """Build a GuestAgentClient from chatcli config with consistent validation."""
    remote = getattr(config, "remote", None) if config else None
    if remote is None or not getattr(remote, "enabled", False):
        raise ValueError("Remote server is not configured")

    base_url = remote_base_url(remote)
    if not base_url:
        raise ValueError("Remote base_url or host is not set")

    token = guest_agent_token(remote)
    if not token:
        raise ValueError(
            "Guest Agent token is not set. Set CHATCLI_GUEST_AGENT_TOKEN "
            "or remote.guest_agent_token in config."
        )

    from chatcli.remote.guest_client import GuestAgentClient

    return GuestAgentClient(base_url=base_url, token=token, timeout=timeout)
