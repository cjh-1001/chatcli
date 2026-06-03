"""chatcli — Give any chat LLM local CLI superpowers.

Usage:
    chatcli              # Interactive REPL
    chatcli "query"      # Single-shot query
    chatcli --print "query"  # Single-shot query for scripts
    chatcli --setup      # Create default config
"""

import sys
from pathlib import Path

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
  thinking_budget: 16000

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
ida_path: ""                 # optional path to idat64/idat/ida64/ida for ida_analyze
auto_resume: false           # auto-restore last session + continue work on startup
auto_compress: true          # auto-compress context when it gets too long
compress_threshold: 80000    # tokens — trigger compression above this
max_retries: 3               # retry failed API calls with exponential backoff
request_timeout: 120         # API request timeout in seconds
max_tool_output_chars: 40000 # max chars per tool result fed into history
temp_script_dir: .chatcli/tmp
temp_script_name: scratch.py
enforce_temp_script_iteration: true
context_file: .chatcli/context.md
"""


def setup_config():
    """Create default config file."""
    config_dir = Path.cwd() / ".chatcli"
    config_file = config_dir / "config.yaml"

    if config_file.exists():
        print(f"Config already exists at {config_file}")
        return

    config_dir.mkdir(exist_ok=True)
    config_file.write_text(DEFAULT_CONFIG, encoding="utf-8")

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


def main():
    force_resume = False
    force_evolve = False
    force_print = False
    evolve_focus = ""
    positional: list[str] = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--setup", "-s"):
            setup_config()
            return
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
        else:
            positional.append(arg)
        i += 1

    # Load config
    config = Config.load()

    # Check for API key
    if not config.provider.api_key:
        print(
            "Error: No API key found. Set CHATCLI_API_KEY, ANTHROPIC_API_KEY, "
            "OPENAI_API_KEY, or MIMO_API_KEY."
        )
        print("Or run 'chatcli --setup' to create a config file first.")
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
