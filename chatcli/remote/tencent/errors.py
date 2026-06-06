"""Tencent Cloud adapter errors."""

from __future__ import annotations


class TencentCloudError(RuntimeError):
    """Base error for Tencent Cloud adapter."""


class TencentCloudConfigError(TencentCloudError):
    """Raised when Tencent Cloud adapter configuration is invalid."""


class TencentCloudApiError(TencentCloudError):
    """Raised when Tencent Cloud returns an API error response."""

    def __init__(self, code: str, message: str, request_id: str = "") -> None:
        self.code = code
        self.request_id = request_id
        detail = f"{code}: {message}"
        if request_id:
            detail = f"{detail} (RequestId: {request_id})"
        super().__init__(detail)
