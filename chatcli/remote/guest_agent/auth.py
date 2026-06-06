"""Guest Agent auth — token validation, never from config files.

Ported from Cloud-AV-Agent-Lab guest_agent_server/auth.py.
All tokens are loaded from environment variables only.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from fastapi import HTTPException, status

TOKEN_ENV = "CHATCLI_GUEST_AGENT_TOKEN"
UPLOAD_TOKEN_ENV = "CHATCLI_GUEST_AGENT_UPLOAD_TOKEN"


class GuestAgentConfigError(RuntimeError):
    """Raised when the Guest Agent cannot start safely."""


def load_required_token(
    env: Mapping[str, str] | None = None,
    token_env: str = TOKEN_ENV,
) -> str:
    """Load a required token from environment variable. Fails if not set."""
    values = env if env is not None else os.environ
    token = values.get(token_env, "").strip()
    if not token:
        raise GuestAgentConfigError(
            f"Guest Agent token env var {token_env!r} is not set. "
            f"Set it before starting the agent: "
            f"$env:{token_env} = 'your-strong-random-token'"
        )
    return token


def verify_bearer_token(
    authorization: str | None,
    expected_token: str,
) -> None:
    """Validate Bearer token from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
        )
    provided = authorization.removeprefix("Bearer ").strip()
    if not provided or provided != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
        )
