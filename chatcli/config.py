"""Configuration loader for chatcli."""

import os
from pathlib import Path
from dataclasses import dataclass, field

import yaml


DEFAULT_AUTO_TOOLS = [
    "read_file", "glob", "grep", "list_dir", "web_search",
    "web_fetch", "git_status", "git_diff", "binary_inspect",
    "binary_find", "binary_hexdump", "encoded_string_extract",
    "obfuscated_data_map", "reverse_technique_map", "reverse_evidence_map",
]
DEFAULT_ASK_TOOLS = [
    "bash", "write_file", "edit_file", "multi_edit", "ida_analyze",
    "ida_focus_decompile", "ida_deobfuscate", "runtime_string_hooks", "external_static_analyze",
    "yara_scan", "upx_unpack", "binary_patch", "chatcli_auto_request",
]
BUILTIN_AUTO_TOOLS = (
    "git_status", "git_diff", "binary_inspect", "binary_find",
    "binary_hexdump", "encoded_string_extract", "obfuscated_data_map",
    "reverse_technique_map", "reverse_evidence_map",
)
BUILTIN_ASK_TOOLS = (
    "multi_edit", "ida_analyze", "ida_focus_decompile", "ida_deobfuscate", "runtime_string_hooks",
    "external_static_analyze", "yara_scan", "upx_unpack", "binary_patch",
    "chatcli_auto_request",
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
    thinking_budget: int = 16000


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

        if "max_tool_rounds" in data:
            cfg.max_tool_rounds = data["max_tool_rounds"]
        if "self_correction" in data:
            cfg.self_correction = data["self_correction"]
        if "max_self_correction_rounds" in data:
            cfg.max_self_correction_rounds = data["max_self_correction_rounds"]
        if "max_work_cycles" in data:
            cfg.max_work_cycles = data["max_work_cycles"]
        if "smart_work" in data:
            cfg.smart_work = data["smart_work"]
        if "confirm_plan" in data:
            cfg.confirm_plan = data["confirm_plan"]
        if "show_diffs" in data:
            cfg.show_diffs = data["show_diffs"]
        if "max_diff_lines" in data:
            cfg.max_diff_lines = data["max_diff_lines"]
        if "tool_preview_lines" in data:
            cfg.tool_preview_lines = data["tool_preview_lines"]
        if "tool_preview_chars" in data:
            cfg.tool_preview_chars = data["tool_preview_chars"]
        if "search_backend" in data:
            cfg.search_backend = data["search_backend"]
        if "ida_path" in data:
            cfg.ida_path = data["ida_path"]
        if "reverse" in data and isinstance(data["reverse"], dict):
            cfg.ida_path = data["reverse"].get("ida_path", cfg.ida_path)
        if "auto_resume" in data:
            cfg.auto_resume = data["auto_resume"]
        if "auto_compress" in data:
            cfg.auto_compress = data["auto_compress"]
        if "compress_threshold" in data:
            cfg.compress_threshold = data["compress_threshold"]
        if "max_retries" in data:
            cfg.max_retries = data["max_retries"]
        if "request_timeout" in data:
            cfg.request_timeout = float(data["request_timeout"])
        if "max_tool_output_chars" in data:
            cfg.max_tool_output_chars = int(data["max_tool_output_chars"])
        if "temp_script_dir" in data:
            cfg.temp_script_dir = data["temp_script_dir"]
        if "temp_script_name" in data:
            cfg.temp_script_name = data["temp_script_name"]
        if "enforce_temp_script_iteration" in data:
            cfg.enforce_temp_script_iteration = data["enforce_temp_script_iteration"]
        if "workspace" in data:
            cfg.workspace = data["workspace"]
        if "context_file" in data:
            cfg.context_file = data["context_file"]
