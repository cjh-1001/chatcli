"""REPL command definitions and tab completion."""

from prompt_toolkit.completion import Completer, Completion, PathCompleter

from .agent_session import session_dir_for_workspace
from .checkpoint import list_backups


COMMAND_DEFS = [
    ("Work", "/work <task>", "Start autonomous work mode"),
    ("Work", "/work continue", "Continue the active work task"),
    ("Work", "/work status", "Show active work task progress"),
    ("Work", "/work done", "Mark the active work task done"),
    ("Analyze", "/audit <target>", "Run a defensive source-code security audit"),
    ("Analyze", "/reverse <exe> [goal]", "Static reverse analysis; goal can be natural language"),
    ("Analyze", "/crackme <exe> [goal]", "Shortcut for authorized CTF/crackme analysis"),
    ("Analyze", "/crack <exe> [goal]", "Shortcut for crackme validation audit"),
    ("Analyze", "/patch <exe> [goal]", "Shortcut for binary patch audit"),
    ("Analyze", "/malware <exe> [goal]", "Shortcut for static behavior triage plan"),
    ("Analyze", "/malware-share [sample] [--report path] [--include-sample]", "Create a defensive sample-sharing package"),
    ("Session", "/plan <task>", "Explore and produce a plan"),
    ("Session", "/session", "Open session picker"),
    ("Session", "/resume", "Open session picker"),
    ("Session", "/session save [name]", "Save session"),
    ("Session", "/session load <name>", "Load session"),
    ("Session", "/session list", "List saved sessions"),
    ("Session", "/history clear", "Clear chat history while preserving learning state"),
    ("Skill", "/skills list", "List loaded skills"),
    ("Skill", "/skills match <query>", "Show which skills match a request"),
    ("Skill", "/skills improve <skill> <note>", "Improve a skill with a reusable lesson"),
    ("Tools", "/tools list", "List registered tools"),
    ("Tools", "/tools check [tool...] [--versions]", "Check tool/dependency availability"),
    ("Window", "/child new <name> [task]", "Create a child analysis window"),
    ("Window", "/child run <name> <task>", "Run a child task in the background"),
    ("Window", "/child list", "List child windows"),
    ("Window", "/child show <name>", "Show child status and output tail"),
    ("Window", "/child summarize [name]", "Summarize child results in the main window"),
    ("Window", "/child wait [name|all]", "Wait for child tasks and refresh summaries"),
    ("Settings", "/doctor", "Check local chatcli health"),
    ("Settings", "/auto-requests list", "Show queued internal automation requests"),
    ("Settings", "/permissions", "Show or change current permission mode"),
    ("Settings", "/auto", "Toggle auto-approval for ask-level tools"),
    ("Settings", "/debug", "Toggle debug output"),
    ("General", "/help", "Show this command list"),
    ("General", "/exit", "Save and quit"),
    ("Analyze", "/evolve <target>", "Start evolution mode"),
    ("Project", "/checkpoint list", "List backups"),
    ("Project", "/checkpoint restore <id>", "Restore a backup"),
    ("Project", "/memory list", "List memories"),
]

COMPLETION_COMMANDS = []
for _, usage, description in COMMAND_DEFS:
    root = usage.split(" ", 1)[0]
    if not any(cmd == root for cmd, _ in COMPLETION_COMMANDS):
        COMPLETION_COMMANDS.append((root, description))

COMMAND_ALIASES = {
    "/continue": ("/work", "continue"),
    "/status": ("/work", "status"),
    "/save": ("/session", "save"),
    "/load": ("/session", "load"),
    "/sessions": ("/session", "list"),
    "/resume": ("/session", "open"),
    "/clear": ("/history", "clear"),
    "/children": ("/child", "list"),
    "/quit": ("/exit", ""),
    "/ida": ("/reverse", "--ida"),
    "/crackme": ("/reverse", "--crackme"),
    "/crack": ("/reverse", "--crackme"),
    "/patch": ("/reverse", "--crackme --patch"),
}

SUBCOMMANDS = {
    "/work": [
        ("continue", "Continue active work task"),
        ("status", "Show active work status"),
        ("done", "Mark active work task done"),
    ],
    "/session": [
        ("open", "Open session picker"),
        ("save", "Save session"),
        ("load", "Load session; no name opens picker"),
        ("list", "List saved sessions"),
    ],
    "/history": [
        ("clear", "Clear chat history and preserve durable state"),
    ],
    "/skills": [
        ("list", "List loaded skills"),
        ("match", "Rank skills for a request"),
        ("improve", "Improve a named skill"),
    ],
    "/tools": [
        ("list", "List registered tools"),
        ("check", "Check tool availability"),
        ("--versions", "Include external tool versions"),
    ],
    "/child": [
        ("new", "Create a child window"),
        ("run", "Run a background child task"),
        ("list", "List child windows"),
        ("show", "Show child output tail"),
        ("summarize", "Summarize child results"),
        ("wait", "Wait for running child tasks"),
        ("close", "Close an idle child window"),
    ],
    "/checkpoint": [
        ("list", "List backups"),
        ("restore", "Restore a backup"),
    ],
    "/permissions": [
        ("mode", "Set current permission mode"),
        ("show", "Show current permission settings"),
    ],
    "/auto-requests": [
        ("list", "List queued internal automation requests"),
        ("process", "Process queued internal automation requests"),
        ("clear", "Clear queued internal automation requests"),
    ],
    "/memory": [
        ("list", "List memories"),
    ],
    "/evolve": [
        ("--continuous", "Run continuous evolution"),
        ("--target", "Set target file or area"),
        ("--goal", "Set evolution goal"),
    ],
    "/reverse": [
        ("--ida", "Use IDA headless analysis"),
        ("--no-ida", "Skip IDA and use lightweight static triage only"),
        ("--crackme", "Optional hint: CTF/crackme validation logic"),
        ("--patch", "Optional hint: audit and optionally create a patched copy"),
        ("--behavior", "Optional hint: sandbox behavior-analysis plan"),
    ],
    "/malware-share": [
        ("--report", "Include a specific report file"),
        ("--output-dir", "Write package to a specific directory"),
        ("--include-sample", "Include sample bytes as a quarantine artifact"),
        ("--no-redact-paths", "Do not redact local user paths in text artifacts"),
        ("--no-redact-secrets", "Do not redact obvious secrets in text artifacts"),
    ],
}


class REPLCompleter(Completer):
    def __init__(self, workspace):
        self.workspace = workspace
        self._path_completer = PathCompleter()

    def _session_names(self):
        try:
            sessions_dir = session_dir_for_workspace(self.workspace)
            if not sessions_dir.exists():
                return []
            return sorted(p.stem for p in sessions_dir.glob("*.json"))
        except Exception:
            return []

    def _backup_ids(self):
        try:
            return [str(b.get("id", "")) for b in list_backups() if b.get("id")]
        except Exception:
            return []

    def _complete_words(self, words, prefix):
        for word, description in words:
            if word.startswith(prefix):
                yield Completion(
                    word,
                    start_position=-len(prefix),
                    display=word,
                    display_meta=description,
                )

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if text.startswith("/"):
            parts = text.split()
            trailing_space = text.endswith(" ")
            if len(parts) >= 1 and (trailing_space or len(parts) > 1):
                base = parts[0]
                arg_prefix = "" if trailing_space else parts[-1]
                arg_index = len(parts) if trailing_space else len(parts) - 1
                if arg_index == 1 and base in SUBCOMMANDS:
                    yield from self._complete_words(SUBCOMMANDS[base], arg_prefix)
                    return
                if base == "/session" and len(parts) >= 2 and parts[1] == "load":
                    for name in self._session_names():
                        if name.startswith(arg_prefix):
                            yield Completion(name, start_position=-len(arg_prefix))
                    return
                if base == "/checkpoint" and len(parts) >= 2 and parts[1] == "restore":
                    for backup_id in self._backup_ids():
                        if backup_id.startswith(arg_prefix):
                            yield Completion(backup_id, start_position=-len(arg_prefix))
                    return
                yield from self._path_completer.get_completions(document, complete_event)
                return

            matched = False
            seen = set()
            for cmd, description in COMPLETION_COMMANDS:
                if cmd in seen:
                    continue
                if cmd.startswith(text):
                    seen.add(cmd)
                    matched = True
                    yield Completion(
                        cmd,
                        start_position=-len(text),
                        display=cmd,
                        display_meta=description,
                    )
            if not matched and text.endswith(" "):
                yield from self._path_completer.get_completions(document, complete_event)
            return
        if text.endswith(" "):
            yield from self._path_completer.get_completions(document, complete_event)

