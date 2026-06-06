"""Tencent Cloud Lighthouse adapter — VM lifecycle management via TC3-HMAC-SHA256 API.

Adapted from Cloud-AV-Agent-Lab (tencent_lighthouse adapter).
"""
from .adapter import LighthouseAdapter
from .auth import resolve_tencent_cloud_auth
from .errors import TencentCloudApiError, TencentCloudConfigError
from .models import LighthouseInstanceStatus, TencentCloudAuth

__all__ = [
    "LighthouseAdapter",
    "LighthouseInstanceStatus",
    "TencentCloudApiError",
    "TencentCloudAuth",
    "TencentCloudConfigError",
    "resolve_tencent_cloud_auth",
]
