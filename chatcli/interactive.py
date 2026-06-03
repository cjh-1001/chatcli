"""Interactive CLI selection — arrow-key navigable prompts.

Uses prompt_toolkit (already a project dependency) to create
inline interactive selectors that feel native to the terminal.
"""

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.formatted_text import to_formatted_text
from prompt_toolkit.styles import Style
from prompt_toolkit.output import create_output
from prompt_toolkit.input import create_input


_STYLE = Style.from_dict({
    "selected": "bold reverse",
    "normal": "",
    "prompt": "bold",
    "dim": "dim",
    "key-hint": "dim italic",
})


def confirm(prompt_text: str, default: bool = True) -> bool:
    """Show an interactive Yes/No prompt navigable with up/down arrows.

    Returns True for Yes, False for No. Press Enter to confirm,
    up/down arrows or j/k to switch, y/n to quick-select.
    """
    selected_yes = default

    def get_text():
        yes_prefix = ">" if selected_yes else " "
        no_prefix = ">" if not selected_yes else " "
        yes_style = "class:selected" if selected_yes else "class:normal"
        no_style = "class:selected" if not selected_yes else "class:normal"

        lines = [
            ("class:prompt", f"  {prompt_text}\n"),
            (yes_style,   f"    {yes_prefix} Yes\n"),
            (no_style,    f"    {no_prefix} No\n"),
            ("class:key-hint", "    [↑ ↓ / j k  ·  Enter  ·  Esc to cancel]"),
        ]
        return to_formatted_text(lines)

    result = [default]

    kb = KeyBindings()

    @kb.add("up")
    @kb.add("k")
    def go_up(event):
        nonlocal selected_yes
        selected_yes = True

    @kb.add("down")
    @kb.add("j")
    def go_down(event):
        nonlocal selected_yes
        selected_yes = False

    @kb.add("y")
    def key_yes(event):
        nonlocal selected_yes
        selected_yes = True
        result[0] = True
        event.app.exit()

    @kb.add("n")
    def key_no(event):
        nonlocal selected_yes
        selected_yes = False
        result[0] = False
        event.app.exit()

    @kb.add("enter")
    def key_enter(event):
        result[0] = selected_yes
        event.app.exit()

    @kb.add("escape")
    @kb.add("c-c")
    def key_cancel(event):
        result[0] = default
        event.app.exit()

    content = FormattedTextControl(text=get_text)
    window = Window(content=content, dont_extend_height=True)
    layout = Layout(HSplit([window]))

    app = Application(
        layout=layout,
        key_bindings=kb,
        style=_STYLE,
        full_screen=False,
        erase_when_done=False,
        input=create_input(),
        output=create_output(),
    )

    app.run()

    # Print the final selection so it stays visible
    choice = "Yes" if result[0] else "No"
    print(f"    {choice}")
    return result[0]


def select(
    options: list[str],
    prompt_text: str = "Select:",
    default_index: int = 0,
    max_display: int = 10,
) -> int | None:
    """Show an interactive scrollable list navigable with arrow keys.

    Returns the index of the selected option, or None if cancelled.
    Up/down arrows or j/k to move, Enter to confirm, Esc to cancel.
    """
    if not options:
        return None

    idx = max(0, min(default_index, len(options) - 1))

    def get_visible_slice():
        """Compute which options are visible based on scroll position."""
        half = max_display // 2
        if len(options) <= max_display:
            start, end = 0, len(options)
        elif idx < half:
            start, end = 0, max_display
        elif idx >= len(options) - half:
            start, end = len(options) - max_display, len(options)
        else:
            start = idx - half
            end = start + max_display
        return start, end

    def get_text():
        start, end = get_visible_slice()
        lines = [("class:prompt", f"  {prompt_text}\n")]

        if start > 0:
            lines.append(("class:dim", f"    ... ({start} more above)\n"))

        for i in range(start, end):
            prefix = "> " if i == idx else "  "
            style = "class:selected" if i == idx else "class:normal"
            text = options[i]
            if len(text) > 80:
                text = text[:77] + "..."
            lines.append((style, f"    {prefix}{text}\n"))

        if end < len(options):
            lines.append(("class:dim", f"    ... ({len(options) - end} more below)\n"))

        lines.append(("class:key-hint", "    [↑ ↓ / j k  ·  Enter  ·  Esc to cancel]"))
        return to_formatted_text(lines)

    result = [default_index if default_index < len(options) else 0]
    cancelled = [False]

    kb = KeyBindings()

    @kb.add("up")
    @kb.add("k")
    def go_up(event):
        nonlocal idx
        idx = max(0, idx - 1)

    @kb.add("down")
    @kb.add("j")
    def go_down(event):
        nonlocal idx
        idx = min(len(options) - 1, idx + 1)

    @kb.add("enter")
    def key_enter(event):
        result[0] = idx
        event.app.exit()

    @kb.add("escape")
    @kb.add("c-c")
    def key_cancel(event):
        cancelled[0] = True
        event.app.exit()

    # Number keys for quick selection
    for i in range(min(9, len(options))):
        @kb.add(str(i + 1))
        def quick_select(event, n=i):
            result[0] = n
            event.app.exit()

    content = FormattedTextControl(text=get_text)
    window = Window(content=content, dont_extend_height=True)
    layout = Layout(HSplit([window]))

    app = Application(
        layout=layout,
        key_bindings=kb,
        style=_STYLE,
        full_screen=False,
        erase_when_done=False,
        input=create_input(),
        output=create_output(),
    )

    app.run()

    if cancelled[0]:
        print("    (cancelled)")
        return None

    print(f"    {options[result[0]]}")
    return result[0]
