"""Base classes for the tool system."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    content: str
    is_error: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


def coerce_bool(value: Any, default: bool = False) -> bool:
    """Parse bool-like values from native JSON or text-tool fallbacks."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off", ""}:
        return False
    return default


def coerce_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    """Parse integer-like values and clamp them when bounds are provided."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def coerce_str_list(value: Any) -> list[str]:
    """Normalize list-like text-tool values into a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.replace("\r", "\n").replace(",", "\n").splitlines()
        return [part.strip() for part in parts if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


class Tool:
    """Base class for all tools."""

    name: str = ""
    description: str = ""
    parameters: dict = {}

    def execute(self, **kwargs) -> ToolResult:
        raise NotImplementedError

    def to_schema(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }

    # For OpenAI format
    def to_openai_schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": self.parameters.get("properties", {}),
                    "required": self.parameters.get("required", []),
                },
            },
        }


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[Tool]:
        return list(self._tools.values())

    def to_schemas(self) -> list[dict]:
        return [t.to_schema() for t in self._tools.values()]

    def to_openai_schemas(self) -> list[dict]:
        return [t.to_openai_schema() for t in self._tools.values()]

    def execute(self, name: str, params: dict) -> ToolResult:
        tool = self._tools.get(name)
        if not tool:
            return ToolResult(content=f"Unknown tool: {name}", is_error=True)

        # Validate required parameters against the tool's schema before calling
        required = tool.parameters.get("required", [])
        missing = [k for k in required if k not in params or params[k] is None]
        if missing:
            return ToolResult(
                content=(
                    f"Error: missing required parameters for '{name}': {', '.join(missing)}. "
                    f"Required: {required}. Provided: {list(params.keys())}."
                ),
                is_error=True,
            )

        try:
            return tool.execute(**params)
        except Exception as e:
            return ToolResult(content=f"Tool error: {e}", is_error=True)
