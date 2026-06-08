"""Shared remote analysis plan defaults."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


STATIC_IDA_VERIFY_PLAN: dict[str, Any] = {
    "static": True,
    "ida": True,
    "ghidra": False,
    "dynamic": False,
    "network": False,
    "verify": True,
}

DYNAMIC_IDA_VERIFY_PLAN: dict[str, Any] = {
    "static": True,
    "ida": True,
    "ghidra": False,
    "dynamic": True,
    "network": True,
    "verify": True,
}

DEFAULT_DYNAMIC_CONFIG: dict[str, Any] = {
    "timeout_seconds": 300,
    "collectors": ["pcap", "procmon", "tshark"],
}


def static_ida_verify_plan() -> dict[str, Any]:
    return deepcopy(STATIC_IDA_VERIFY_PLAN)


def dynamic_ida_verify_plan() -> dict[str, Any]:
    return deepcopy(DYNAMIC_IDA_VERIFY_PLAN)


def default_dynamic_config() -> dict[str, Any]:
    return deepcopy(DEFAULT_DYNAMIC_CONFIG)
