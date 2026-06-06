"""Guest Agent entry point — starts uvicorn server.

Usage:
    python -m chatcli.remote.guest_agent.main [--host 0.0.0.0] [--port 8443]

Token must be set in environment before starting:
    $env:CHATCLI_GUEST_AGENT_TOKEN = "your-strong-random-token"

Ported from Cloud-AV-Agent-Lab guest_agent_server/main.py.
"""

from __future__ import annotations

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="chatcli Guest Agent — remote analysis server"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Bind address (default: 0.0.0.0 for remote access)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Listen port (default: 8443)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (development only)",
    )
    args = parser.parse_args()

    import uvicorn

    print(f"chatcli Guest Agent starting on {args.host}:{args.port}")
    uvicorn.run(
        "chatcli.remote.guest_agent.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
