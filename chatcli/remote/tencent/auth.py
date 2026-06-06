"""Tencent Cloud auth resolution — env vars > config, secrets never in files.

Adapted from Cloud-AV-Agent-Lab auth.py.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from .models import TencentCloudAuth


def resolve_tencent_cloud_auth(
    secret_id: str = "",
    secret_key: str = "",
    region: str = "ap-guangzhou",
    env: Mapping[str, str] | None = None,
) -> TencentCloudAuth:
    """Resolve Tencent Cloud credentials with env-var priority.

    Priority: TENCENTCLOUD_SECRET_ID/KEY/REGION env vars > passed values.
    """
    values = env if env is not None else os.environ
    sid, sid_src = _env_or_config(values, "TENCENTCLOUD_SECRET_ID", secret_id)
    skey, skey_src = _env_or_config(values, "TENCENTCLOUD_SECRET_KEY", secret_key)
    reg, reg_src = _env_or_config(values, "TENCENTCLOUD_REGION", region)
    return TencentCloudAuth(
        secret_id=sid,
        secret_key=skey,
        region=reg,
        secret_id_source=sid_src,
        secret_key_source=skey_src,
        region_source=reg_src,
    )


def _env_or_config(
    env: Mapping[str, str],
    key: str,
    config_value: str,
) -> tuple[str, str]:
    env_value = env.get(key, "")
    if env_value:
        return env_value, "env"
    return config_value, "config"
