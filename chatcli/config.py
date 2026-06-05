"""Configuration loader for chatcli."""

import os
from pathlib import Path
from dataclasses import dataclass, field

import yaml


def _bool_value(value, default: bool = False) -> bool:
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


DEFAULT_AUTO_TOOLS = [
    "read_file", "glob", "grep", "list_dir", "web_search",
    "web_fetch", "ip_lookup", "json_extract", "ioc_quality_classifier",
    "detection_rule_lint", "git_status", "git_diff", "binary_inspect",
    "binary_find", "binary_hexdump", "encoded_string_extract",
    "obfuscated_data_map", "behavior_capability_map",
    "attack_chain_builder", "evidence_graph",
    "behavior_claim_validator", "behavior_coverage_matrix",
    "command_capability_map", "attack_technique_mapper",
    "reverse_technique_map", "reverse_evidence_map",
]
DEFAULT_ASK_TOOLS = [
    "bash", "write_file", "edit_file", "multi_edit", "ida_analyze",
    "ida_focus_decompile", "ida_deobfuscate", "ida_mcp_ensure", "ida_mcp_probe",
    "ida_mcp_list_tools", "ida_mcp_call", "runtime_string_hooks", "external_static_analyze",
    "ghidra_analyze", "angr_triage", "yara_scan", "upx_unpack", "binary_patch",
    "malware_share_package", "chatcli_auto_request",
]
BUILTIN_AUTO_TOOLS = (
    "ip_lookup", "json_extract", "ioc_quality_classifier", "detection_rule_lint",
    "git_status", "git_diff", "binary_inspect", "binary_find",
    "binary_hexdump", "encoded_string_extract", "obfuscated_data_map",
    "behavior_capability_map", "attack_chain_builder",
    "evidence_graph", "behavior_claim_validator", "behavior_coverage_matrix",
    "command_capability_map", "attack_technique_mapper",
    "reverse_technique_map", "reverse_evidence_map",
)
BUILTIN_ASK_TOOLS = (
    "multi_edit", "ida_analyze", "ida_focus_decompile", "ida_deobfuscate",
    "ida_mcp_ensure", "ida_mcp_probe", "ida_mcp_list_tools", "ida_mcp_call", "runtime_string_hooks",
    "external_static_analyze", "ghidra_analyze", "angr_triage", "yara_scan", "upx_unpack", "binary_patch",
    "malware_share_package", "chatcli_auto_request",
)
CONFIG_FILENAMES = ("config.yaml", "config.yml")

BUILTIN_SENSITIVE_PATTERNS = (
    ".chatcli/config.yaml",
    ".chatcli/config.yml",
    "chatcli/config.yaml",
    "chatcli/config.yml",
)


@dataclass
class ProviderConfig:
    provider: str = "anthropic"  # anthropic | openai | openai-compatible
    model: str = "claude-sonnet-4-6"
    api_key: str = ""
    api_base: str = ""
    max_tokens: int = 8192
    thinking: bool = True
    thinking_budget: int = 4096


@dataclass
class PermissionConfig:
    auto: list[str] = field(default_factory=lambda: list(DEFAULT_AUTO_TOOLS))
    ask: list[str] = field(default_factory=lambda: list(DEFAULT_ASK_TOOLS))
    deny: list[str] = field(default_factory=list)
    mode: str = "default"  # default | ask | accept_edits | dont_ask | auto
    protect_sensitive_files: bool = True
    sensitive: list[str] = field(default_factory=lambda: [
        ".env", ".env.*", "*.pem", "*.key", "*_rsa", "*_dsa",
        "id_rsa", "id_dsa", "credentials.*", "secrets.*",
        ".chatcli/config.yaml", ".chatcli/config.yml",
    ])
    # Claude Code-style permission rules with path patterns:
    # e.g. {"tool": "write_file", "path": "*.md"} auto-approves writes to markdown files
    path_rules: list[dict] = field(default_factory=list)


@dataclass
class Config:
    provider: ProviderConfig = field(default_factory=ProviderConfig)
    permissions: PermissionConfig = field(default_factory=PermissionConfig)
    max_tool_rounds: int = 50
    self_correction: bool = True
    max_self_correction_rounds: int = 3
    max_work_cycles: int = 20
    smart_work: bool = True
    confirm_plan: bool = True
    show_diffs: bool = True
    max_diff_lines: int = 80
    tool_preview_lines: int = 0
    tool_preview_chars: int = 800
    search_backend: str = "auto"
    ida_path: str = ""
    ghidra_path: str = ""
    die_path: str = ""
    exiftool_path: str = ""
    upx_path: str = ""
    ida_mcp_url: str = ""
    ida_mcp_start_command: str = ""
    ida_mcp_auto_prepare: bool = False
    ida_mcp_auto_start: bool = False
    ida_mcp_tool_limit: int = 80
    auto_resume: bool = False
    auto_compress: bool = True
    compress_threshold: int = 80000  # trigger compression when context exceeds this many tokens
    max_retries: int = 3             # retry failed API calls with backoff
    request_timeout: float = 120.0   # API request timeout in seconds
    max_tool_output_chars: int = 40000  # max chars per tool result fed into history (prevents context blowup)
    temp_script_dir: str = ".chatcli/tmp"
    temp_script_name: str = "scratch.py"
    enforce_temp_script_iteration: bool = True
    workspace: str = ""
    context_file: str = ".chatcli/context.md"

    @classmethod
    def find_config_file(cls, path: str | None = None) -> Path | None:
        """Return the first config file that would be loaded."""
        for p in cls._candidate_paths(path):
            if p and Path(p).exists():
                return Path(p)
        return None

    @classmethod
    def find_workspace_config_file(cls) -> Path | None:
        """Return a config from the current directory or one of its parents."""
        for p in cls._workspace_candidate_paths():
            if p.exists():
                return p
        return None

    @classmethod
    def default_config_file(cls) -> Path:
        """Return where first-run setup should create a project config."""
        if os.environ.get("CHATCLI_CONFIG"):
            return Path(os.environ["CHATCLI_CONFIG"]).expanduser()
        return Path.cwd() / ".chatcli" / "config.yaml"

    @classmethod
    def global_config_file(cls) -> Path:
        """Return the user-level config path shared by all workspaces."""
        return Path.home() / ".chatcli" / "config.yaml"

    @classmethod
    def local_config_file(cls) -> Path:
        """Return the current workspace config path."""
        return Path.cwd() / ".chatcli" / "config.yaml"

    @staticmethod
    def _workspace_candidate_paths() -> list[Path]:
        cwd = Path.cwd().resolve()
        home = Path.home().resolve()
        return [
            parent / ".chatcli" / filename
            for parent in (cwd, *cwd.parents)
            if parent != home or cwd == home
            for filename in CONFIG_FILENAMES
        ]

    @staticmethod
    def _candidate_paths(path: str | None = None) -> list[str | Path | None]:
        return [
            path,
            os.environ.get("CHATCLI_CONFIG"),
            *Config._workspace_candidate_paths(),
            *(Path.home() / ".chatcli" / filename for filename in CONFIG_FILENAMES),
        ]

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        """Load config from file, with env var overrides."""
        cfg = cls()

        config_file = None
        for p in cls._candidate_paths(path):
            if p and Path(p).exists():
                config_file = p
                break

        if config_file:
            with open(config_file, encoding="utf-8") as f:
                try:
                    data = yaml.safe_load(f) or {}
                except yaml.YAMLError as exc:
                    # YAML parse errors are commonly caused by unescaped
                    # backslashes in Windows paths inside double-quoted strings.
                    # Give the user a clear, actionable error message.
                    note = getattr(exc, "note", "")
                    problem_mark = getattr(exc, "problem_mark", None)
                    if problem_mark:
                        loc = f"line {problem_mark.line + 1}, column {problem_mark.column + 1}"
                    else:
                        loc = "unknown location"
                    msg = (
                        f"\n{'=' * 60}\n"
                        f"  YAML parse error in config file:\n"
                        f"    {config_file}\n"
                        f"  Location: {loc}\n"
                    )
                    if note:
                        msg += f"  Detail: {note}\n"
                    msg += (
                        "\n"
                        "  Common cause: Windows paths inside YAML double-quoted strings.\n"
                        '  The backslash (\\) is a YAML escape character, so\n'
                        '    C:\\Users\\...   is treated as an escape sequence.\n'
                        "\n"
                        "  How to fix:\n"
                        "    1. Use single quotes for paths (backslashes are literal):\n"
                        "       ida_path: 'C:\\IDA Pro\\idat.exe'\n"
                        "    2. Or use forward slashes:\n"
                        "       ida_path: C:/IDA Pro/idat.exe\n"
                        "    3. Or escape every backslash with \\\\ in double quotes:\n"
                        '       ida_path: "C:\\\\IDA Pro\\\\idat.exe"\n'
                        f"{'=' * 60}\n"
                    )
                    raise yaml.YAMLError(msg) from exc
            cls._apply_yaml(cfg, data)
            cls._ensure_builtin_permissions(cfg)

        # Env var overrides. CHATCLI_API_KEY is an explicit override; provider
        # env vars only fill an empty config value so local project configs are
        # not accidentally shadowed by a stale global OPENAI_API_KEY.
        explicit_api_key = os.environ.get("CHATCLI_API_KEY")
        if explicit_api_key:
            cfg.provider.api_key = explicit_api_key
        elif not cfg.provider.api_key:
            provider_name = cfg.provider.provider.lower()
            api_base = cfg.provider.api_base.lower()
            if provider_name == "anthropic":
                cfg.provider.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            elif "xiaomimimo.com" in api_base:
                cfg.provider.api_key = (
                    os.environ.get("MIMO_API_KEY", "")
                    or os.environ.get("OPENAI_API_KEY", "")
                )
            else:
                cfg.provider.api_key = os.environ.get("OPENAI_API_KEY", "")
        if os.environ.get("CHATCLI_MODEL"):
            cfg.provider.model = os.environ["CHATCLI_MODEL"]
        if os.environ.get("CHATCLI_PROVIDER"):
            cfg.provider.provider = os.environ["CHATCLI_PROVIDER"]
        if os.environ.get("CHATCLI_API_BASE"):
            cfg.provider.api_base = os.environ["CHATCLI_API_BASE"]
        if os.environ.get("IDA_PATH"):
            cfg.ida_path = os.environ["IDA_PATH"]
        if os.environ.get("GHIDRA_HEADLESS_PATH"):
            cfg.ghidra_path = os.environ["GHIDRA_HEADLESS_PATH"]
        elif os.environ.get("GHIDRA_HOME"):
            cfg.ghidra_path = os.environ["GHIDRA_HOME"]
        if os.environ.get("DIE_PATH"):
            cfg.die_path = os.environ["DIE_PATH"]
        if os.environ.get("EXIFTOOL_PATH"):
            cfg.exiftool_path = os.environ["EXIFTOOL_PATH"]
        if os.environ.get("UPX_PATH"):
            cfg.upx_path = os.environ["UPX_PATH"]
        if os.environ.get("IDA_MCP_URL"):
            cfg.ida_mcp_url = os.environ["IDA_MCP_URL"]
        if os.environ.get("IDA_MCP_START_COMMAND"):
            cfg.ida_mcp_start_command = os.environ["IDA_MCP_START_COMMAND"]
        if os.environ.get("IDA_MCP_AUTO_PREPARE"):
            cfg.ida_mcp_auto_prepare = _bool_value(os.environ["IDA_MCP_AUTO_PREPARE"], cfg.ida_mcp_auto_prepare)
        if os.environ.get("IDA_MCP_AUTO_START"):
            cfg.ida_mcp_auto_start = _bool_value(os.environ["IDA_MCP_AUTO_START"], cfg.ida_mcp_auto_start)
        if os.environ.get("IDA_MCP_TOOL_LIMIT"):
            try:
                cfg.ida_mcp_tool_limit = int(os.environ["IDA_MCP_TOOL_LIMIT"])
            except ValueError:
                pass

        if not cfg.workspace:
            cfg.workspace = os.getcwd()

        return cfg

    @staticmethod
    def _ensure_builtin_permissions(cfg: "Config") -> None:
        """Add new built-in tools to old configs unless explicitly configured."""
        def known(tool: str) -> bool:
            return (
                tool in cfg.permissions.auto
                or tool in cfg.permissions.ask
                or tool in cfg.permissions.deny
            )

        for tool in BUILTIN_AUTO_TOOLS:
            if not known(tool):
                cfg.permissions.auto.append(tool)
        for tool in BUILTIN_ASK_TOOLS:
            if not known(tool):
                cfg.permissions.ask.append(tool)
        for pattern in BUILTIN_SENSITIVE_PATTERNS:
            if pattern not in cfg.permissions.sensitive:
                cfg.permissions.sensitive.append(pattern)

    @staticmethod
    def _apply_yaml(cfg: "Config", data: dict) -> None:
        if "provider" in data:
            p = data["provider"]
            cfg.provider.provider = p.get("provider", cfg.provider.provider)
            cfg.provider.model = p.get("model", cfg.provider.model)
            cfg.provider.api_key = p.get("api_key", cfg.provider.api_key)
            cfg.provider.api_base = p.get("api_base", cfg.provider.api_base)
            cfg.provider.max_tokens = p.get("max_tokens", cfg.provider.max_tokens)
            cfg.provider.thinking = p.get("thinking", cfg.provider.thinking)
            cfg.provider.thinking_budget = p.get("thinking_budget", cfg.provider.thinking_budget)

        if "permissions" in data:
            perm = data["permissions"]
            cfg.permissions.auto = perm.get("auto", cfg.permissions.auto)
            cfg.permissions.ask = perm.get("ask", cfg.permissions.ask)
            cfg.permissions.deny = perm.get("deny", cfg.permissions.deny)
            cfg.permissions.mode = perm.get("mode", cfg.permissions.mode)
            cfg.permissions.protect_sensitive_files = perm.get(
                "protect_sensitive_files", cfg.permissions.protect_sensitive_files
            )
            cfg.permissions.sensitive = perm.get("sensitive", cfg.permissions.sensitive)
            cfg.permissions.path_rules = perm.get("path_rules", cfg.permissions.path_rules)

        # ── Flat fields ──────────────────────────────────────────
        for key in (
            "max_tool_rounds", "self_correction", "max_self_correction_rounds",
            "max_work_cycles", "smart_work", "confirm_plan", "show_diffs",
            "max_diff_lines", "tool_preview_lines", "tool_preview_chars",
            "search_backend", "ida_path", "ghidra_path", "die_path",
            "exiftool_path", "upx_path", "ida_mcp_url", "ida_mcp_start_command",
            "auto_resume", "auto_compress", "compress_threshold", "max_retries",
            "temp_script_dir", "temp_script_name", "enforce_temp_script_iteration",
            "workspace", "context_file",
        ):
            if key in data:
                setattr(cfg, key, data[key])

        for key in ("request_timeout",):
            if key in data:
                setattr(cfg, key, float(data[key]))
        for key in ("max_tool_output_chars",):
            if key in data:
                setattr(cfg, key, int(data[key]))
        for key in ("ida_mcp_auto_prepare", "ida_mcp_auto_start"):
            if key in data:
                setattr(cfg, key, _bool_value(data[key], getattr(cfg, key)))
        if "ida_mcp_tool_limit" in data:
            try:
                cfg.ida_mcp_tool_limit = int(data["ida_mcp_tool_limit"])
            except (TypeError, ValueError):
                pass

        # ── Legacy ``reverse:`` sub-section ───────────────────────
        reverse = data.get("reverse")
        if isinstance(reverse, dict):
            for key in ("ida_path", "ghidra_path", "die_path", "exiftool_path",
                        "upx_path", "ida_mcp_url", "ida_mcp_start_command"):
                if key in reverse:
                    setattr(cfg, key, reverse[key])
            for key in ("ida_mcp_auto_prepare", "ida_mcp_auto_start"):
                if key in reverse:
                    setattr(cfg, key, _bool_value(reverse[key], getattr(cfg, key)))
            if "ida_mcp_tool_limit" in reverse:
                try:
                    cfg.ida_mcp_tool_limit = int(reverse["ida_mcp_tool_limit"])
                except (TypeError, ValueError):
                    pass
