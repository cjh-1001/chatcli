"""chatcli - Give any chat LLM local CLI superpowers.

Usage:
    chatcli              # Interactive REPL
    chatcli "query"      # Single-shot query
    chatcli --print "query"  # Single-shot query for scripts
    chatcli --setup      # Create local project config
    chatcli --setup --global  # Create user config shared by all projects
    chatcli --global "query"  # Use the user config even inside a project
"""

import sys
import getpass
import json
import os
from pathlib import Path

import yaml

from .config import Config
from .ui import REPL


DEFAULT_CONFIG = """# chatcli configuration
provider:
  provider: anthropic        # anthropic | openai | openai-compatible | text-tools
  model: claude-sonnet-4-6
  # api_key: sk-...          # Or set CHATCLI_API_KEY / provider-specific env vars
  # api_base: https://...    # For custom endpoints (Ollama, vLLM, etc.)
  max_tokens: 8192
  thinking: true
  thinking_budget: 4096

permissions:
  auto:                      # Auto-execute these tools
    - read_file
    - glob
    - grep
    - list_dir
    - git_status
    - git_diff
    - binary_inspect
    - binary_find
    - binary_hexdump
    - encoded_string_extract
    - obfuscated_data_map
    - reverse_technique_map
  ask:                       # Ask before these tools
    - bash
    - write_file
    - edit_file
    - multi_edit
    - ida_analyze
    - ida_deobfuscate
    - runtime_string_hooks
    - external_static_analyze
    - yara_scan
    - upx_unpack
    - binary_patch
    - chatcli_auto_request
  deny: []                   # Never allow these tools
  mode: default              # default | ask | accept_edits | dont_ask | auto
  protect_sensitive_files: true
  sensitive:
    - .env
    - .env.*
    - "*.pem"
    - "*.key"
    - id_rsa
    - id_dsa

max_tool_rounds: 50
self_correction: true
max_self_correction_rounds: 3
max_work_cycles: 20          # /work continuation cycles before pausing
smart_work: true             # route implementation-like prompts into /work automatically
confirm_plan: true           # ask for plan approval before coding work
show_diffs: true             # show colored +/- diff after file edits
max_diff_lines: 80           # truncate displayed diffs after this many lines
tool_preview_lines: 0        # 0 keeps terminal output compact; errors still show a short preview
tool_preview_chars: 800      # max chars to echo when previews are enabled
search_backend: auto        # auto | bing | duckduckgo
ida_path: ""                 # path to idat64/idat (headless IDA); avoid pointing to ida gui
auto_resume: false           # auto-restore last session + continue work on startup
auto_compress: true          # auto-compress context when it gets too long
compress_threshold: 80000    # tokens - trigger compression above this
max_retries: 3               # retry failed API calls with exponential backoff
request_timeout: 120         # API request timeout in seconds
max_tool_output_chars: 40000 # max chars per tool result fed into history
temp_script_dir: .chatcli/tmp
temp_script_name: scratch.py
enforce_temp_script_iteration: true
context_file: .chatcli/context.md
"""


def _yaml_string(value: str) -> str:
    return json.dumps(value)


def _detected_provider_settings() -> dict[str, str]:
    provider = os_provider = ""
    try:
        provider = os.environ.get("CHATCLI_PROVIDER", "").strip()
        model = os.environ.get("CHATCLI_MODEL", "").strip()
        api_base = os.environ.get("CHATCLI_API_BASE", "").strip()

        if not provider:
            if os.environ.get("ANTHROPIC_API_KEY"):
                provider = "anthropic"
            elif os.environ.get("MIMO_API_KEY"):
                provider = "openai-compatible"
                api_base = api_base or "https://api.xiaomimimo.com/v1"
            elif os.environ.get("OPENAI_API_KEY"):
                provider = "openai"
            else:
                provider = "anthropic"

        os_provider = provider
    except Exception:
        provider = "anthropic"
        model = ""
        api_base = ""

    if not model:
        model = "claude-sonnet-4-6" if provider == "anthropic" else "gpt-4.1"

    return {
        "provider": os_provider or provider,
        "model": model,
        "api_base": api_base,
        "api_key": "",
    }


def _render_config(settings: dict[str, str] | None = None) -> str:
    settings = settings or {}
    provider = settings.get("provider", "anthropic")
    model = settings.get("model", "claude-sonnet-4-6")
    api_key = settings.get("api_key", "")
    api_base = settings.get("api_base", "")
    ida_path = settings.get("ida_path", "")
    context_file = settings.get("context_file", ".chatcli/context.md")

    lines: list[str] = []
    for line in DEFAULT_CONFIG.splitlines():
        if line.startswith("  provider:"):
            lines.append(
                f"  provider: {_yaml_string(provider)}        "
                "# anthropic | openai | openai-compatible | text-tools"
            )
        elif line.startswith("  model:"):
            lines.append(f"  model: {_yaml_string(model)}")
            if api_key:
                lines.append("  api_key: " + _yaml_string(api_key))
        elif line.startswith("  # api_key:") and api_key:
            continue
        elif line.startswith("  # api_base:") and api_base:
            lines.append("  api_base: " + _yaml_string(api_base))
        elif line.startswith("ida_path:"):
            lines.append(f"ida_path: {_yaml_string(ida_path)}                 # path to idat64/idat (headless IDA); avoid pointing to ida gui")
        elif line.startswith("context_file:"):
            lines.append(f"context_file: {_yaml_string(context_file)}")
        else:
            lines.append(line)
    return "\n".join(lines) + "\n"


def setup_config(
    config_file: Path | None = None,
    settings: dict[str, str] | None = None,
    quiet: bool = False,
) -> Path:
    """Create default config file."""
    config_file = config_file or Config.default_config_file()
    config_dir = config_file.parent

    if config_file.exists():
        if not quiet:
            print(f"Config already exists at {config_file}")
        return config_file

    config_dir.mkdir(parents=True, exist_ok=True)
    config_file.write_text(_render_config(settings), encoding="utf-8")

    # Also create a sample context file
    context_file = config_dir / "context.md"
    if not context_file.exists():
        context_file.write_text(
            "# Project Context\n\n"
            "Add project-specific instructions here. "
            "The model will read this file to understand your project.\n\n"
            "## Tech Stack\n- ...\n\n"
            "## Conventions\n- ...\n",
            encoding="utf-8",
        )

    if quiet:
        return config_file

    print(f"Created config at {config_file}")
    print(f"Created context at {context_file}")
    print("\nNext: set your API key via environment variable:")
    print("  export ANTHROPIC_API_KEY=sk-ant-...")
    print("  or")
    print("  export OPENAI_API_KEY=sk-...")
    print("  or")
    print("  export MIMO_API_KEY=...")
    print("  or")
    print("  export CHATCLI_API_KEY=...")
    return config_file


def _prompt_default(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def _choose_provider(default: str) -> tuple[str, str, str]:
    choices = [
        ("anthropic", "Anthropic", "claude-sonnet-4-6", ""),
        ("openai", "OpenAI", "gpt-4.1", ""),
        ("openai-compatible", "OpenAI-compatible", "gpt-4.1", ""),
        ("text-tools", "Text-tools", "gpt-4.1", ""),
        ("openai-compatible", "MiMo / xiaomimimo.com", "claude-sonnet-4-6", "https://api.xiaomimimo.com/v1"),
    ]
    print("\n选择模型服务商：")
    default_index = 1
    for idx, (provider, label, _, api_base) in enumerate(choices, 1):
        if provider == default and not api_base:
            default_index = idx
            break
    for idx, (_, label, _, _) in enumerate(choices, 1):
        marker = " (默认)" if idx == default_index else ""
        print(f"  {idx}. {label}{marker}")

    raw = _prompt_default("输入序号", str(default_index))
    try:
        index = int(raw)
    except ValueError:
        index = default_index
    if index < 1 or index > len(choices):
        index = default_index
    provider, _, model, api_base = choices[index - 1]
    return provider, model, api_base


def _env_api_key(provider: str, api_base: str) -> tuple[str, str]:
    import os

    if os.environ.get("CHATCLI_API_KEY"):
        return "CHATCLI_API_KEY", os.environ["CHATCLI_API_KEY"]
    if "xiaomimimo.com" in api_base.lower():
        value = os.environ.get("MIMO_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
        return ("MIMO_API_KEY" if os.environ.get("MIMO_API_KEY") else "OPENAI_API_KEY"), value
    if provider == "anthropic":
        return "ANTHROPIC_API_KEY", os.environ.get("ANTHROPIC_API_KEY", "")
    return "OPENAI_API_KEY", os.environ.get("OPENAI_API_KEY", "")


def _read_config_data(config_file: Path) -> dict:
    if not config_file.exists():
        return {}
    data = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _write_provider_settings(config_file: Path, settings: dict[str, str], preserve_template: bool) -> None:
    config_file.parent.mkdir(parents=True, exist_ok=True)
    if preserve_template:
        config_file.write_text(_render_config(settings), encoding="utf-8")
        return

    data = _read_config_data(config_file)
    provider_data = data.setdefault("provider", {})
    provider_data["provider"] = settings["provider"]
    provider_data["model"] = settings["model"]
    if settings.get("api_base"):
        provider_data["api_base"] = settings["api_base"]
    else:
        provider_data.pop("api_base", None)
    if settings.get("api_key"):
        provider_data["api_key"] = settings["api_key"]
    config_file.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def guide_config(config_file: Path, preserve_template: bool = False) -> None:
    data = _read_config_data(config_file)
    provider_data = data.get("provider", {}) if isinstance(data.get("provider"), dict) else {}
    detected = _detected_provider_settings()

    current_provider = provider_data.get("provider") or detected["provider"]
    provider, default_model, default_api_base = _choose_provider(current_provider)

    current_model = provider_data.get("model") or detected.get("model") or default_model
    if current_provider != provider:
        current_model = default_model
    model = _prompt_default("模型名", current_model)

    current_api_base = provider_data.get("api_base") or detected.get("api_base") or default_api_base
    if provider in {"openai-compatible", "text-tools"}:
        api_base = _prompt_default("API base URL", current_api_base)
    else:
        api_base = _prompt_default("API base URL（默认通常留空）", current_api_base)

    env_name, env_key = _env_api_key(provider, api_base)
    api_key = ""
    if env_key:
        print(f"检测到 {env_name}，不会把 key 写入配置文件。")
    else:
        print("未检测到 API key。可以留空，之后用环境变量配置；也可以写入本地配置文件。")
        api_key = getpass.getpass("API key（留空跳过）: ").strip()

    _write_provider_settings(
        config_file,
        {
            "provider": provider,
            "model": model,
            "api_base": api_base,
            "api_key": api_key,
        },
        preserve_template=preserve_template,
    )
    print(f"配置已更新：{config_file}")


def _first_run_config_file(config_file: Path | None = None) -> Path | None:
    if config_file is not None:
        return None if config_file.exists() else config_file
    if os.environ.get("CHATCLI_CONFIG"):
        config_file = Config.default_config_file()
        return None if config_file.exists() else config_file
    if Config.find_config_file() is None:
        return Config.default_config_file()
    return None


def ensure_first_run_config(interactive: bool, config_file: Path | None = None) -> Config:
    requested_config_file = config_file
    first_run_config_file = _first_run_config_file(requested_config_file)
    if first_run_config_file is not None:
        settings = _detected_provider_settings()
        setup_config(first_run_config_file, settings=settings, quiet=not interactive)
        if interactive:
            print("未发现当前环境配置文件，已自动创建默认配置。")
            guide_config(first_run_config_file, preserve_template=True)

    config = Config.load(str(requested_config_file) if requested_config_file else None)
    if not config.provider.api_key and interactive:
        config_file = requested_config_file or Config.find_config_file() or Config.default_config_file()
        print("\n当前配置还没有可用 API key，进入配置向导。")
        guide_config(config_file, preserve_template=False)
        config = Config.load(str(config_file) if config_file else None)
    return config


def main():
    force_resume = False
    force_evolve = False
    force_print = False
    evolve_focus = ""
    setup_requested = False
    setup_scope = "local"
    config_override: Path | None = None
    positional: list[str] = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--setup", "-s"):
            setup_requested = True
        elif arg == "--global":
            setup_scope = "global"
            config_override = Config.global_config_file()
        elif arg in ("--local", "--project"):
            setup_scope = "local"
            config_override = Config.local_config_file()
        if arg in ("--version", "-v"):
            from . import __version__
            print(f"chatcli v{__version__}")
            return
        if arg in ("--help", "-h"):
            print(__doc__)
            return
        if arg in ("--resume", "-r"):
            force_resume = True
        elif arg in ("--evolve", "-e"):
            force_evolve = True
        elif arg in ("--print", "-p"):
            force_print = True
        elif arg == "--focus" and i + 1 < len(args):
            evolve_focus = args[i + 1]
            i += 1
        elif arg in ("--setup", "-s", "--global", "--local", "--project"):
            pass
        else:
            positional.append(arg)
        i += 1

    if setup_requested:
        config_file = (
            Config.global_config_file()
            if setup_scope == "global"
            else Config.default_config_file()
        )
        preserve_template = not config_file.exists()
        config_file = setup_config(config_file)
        if sys.stdin.isatty() and sys.stdout.isatty():
            guide_config(config_file, preserve_template=preserve_template)
        return

    # Load config, creating first-run config when none exists.
    interactive_setup = sys.stdin.isatty() and sys.stdout.isatty()
    config = ensure_first_run_config(interactive_setup, config_override)

    # Check for API key
    if not config.provider.api_key:
        print(
            "Error: No API key found. Set CHATCLI_API_KEY, ANTHROPIC_API_KEY, "
            "OPENAI_API_KEY, or MIMO_API_KEY."
        )
        print("Or run 'chatcli --setup' to configure provider settings interactively.")
        sys.exit(1)

    # Single-shot mode (skip if a mode flag was set)
    query = " ".join(positional).strip()
    if not query and force_print and not sys.stdin.isatty():
        query = sys.stdin.read().strip()

    if query and not force_resume and not force_evolve:
        from .checkpoint import mark_clean
        repl = REPL(config)
        try:
            if query.lstrip().startswith("/"):
                handled = repl._handle_command(query)
                if handled is not None:
                    return
            repl.agent.run(query)
            repl._process_auto_requests()
        finally:
            mark_clean(config.workspace)
        return

    if force_print and not query:
        print("Error: --print requires a query argument or piped stdin.")
        sys.exit(1)

    # Interactive REPL
    repl = REPL(config)
    if force_resume or config.auto_resume:
        repl._resume_flag = True
    if force_evolve:
        repl._evolve_flag = True
        repl._evolve_focus = evolve_focus
    repl.run()


if __name__ == "__main__":
    main()
