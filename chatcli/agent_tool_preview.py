"""Compact terminal previews for selected tool outputs."""

import re


class AgentToolPreviewMixin:
    def _should_preview_tool_output(self, name: str, result) -> bool:
        if not result.content:
            return False
        preview_lines = int(getattr(self.config, "tool_preview_lines", 0) or 0)
        if preview_lines <= 0 and not result.is_error:
            return name in (
                "ida_analyze",
                "ida_focus_decompile",
                "ida_deobfuscate",
                "encoded_string_extract",
                "obfuscated_data_map",
                "reverse_technique_map",
                "reverse_evidence_map",
                "runtime_string_hooks",
            )
        if name in ("write_file", "edit_file", "multi_edit"):
            return False
        text = result.content.strip()
        if not text or text == "(no output)":
            return False
        return True

    def _compact_markdown_sections(
        self, text: str, wanted: tuple[str, ...], per_section: int = 6,
    ) -> list[str]:
        """Return a compact excerpt from selected markdown sections."""
        lines = text.splitlines()
        selected: list[str] = []
        active = False
        remaining = 0
        for line in lines:
            heading = re.match(r"^#{2,4}\s+(.+)$", line)
            if heading:
                title = heading.group(1).strip().lower()
                active = any(title.startswith(w) for w in wanted)
                remaining = per_section if active else 0
                if active:
                    selected.append(heading.group(1).strip())
                continue
            if active and remaining > 0 and line.strip():
                selected.append(line)
                remaining -= 1
        return selected

    def _preview_read_file(self, text: str, max_lines: int) -> list[str]:
        """Show a small code excerpt instead of hiding file reads entirely."""
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) <= max_lines:
            return lines

        scored: list[tuple[int, int, str]] = []
        signature_pattern = re.compile(r"\b(class|def|async def|function)\b")
        control_pattern = re.compile(r"\b(return|if|for|while|try|except|with)\b")
        declaration_pattern = re.compile(r"\b(const|let|var|import|from)\b")
        for idx, line in enumerate(lines):
            code = line.split("\t", 1)[-1].strip()
            score = 0
            if signature_pattern.search(code):
                score += 6
            elif control_pattern.search(code):
                score += 4
            elif declaration_pattern.search(code):
                score += 2
            if code.startswith(("@", "#", "//", "/*")):
                score += 1
            if len(code) > 120:
                score -= 1
            scored.append((-score, idx, line))
        scored.sort()
        picks = sorted((idx, line) for _, idx, line in scored[:max_lines])
        return [line for _, line in picks]

    def _preview_binary_inspect(self, text: str, max_lines: int) -> list[str]:
        lines = text.splitlines()
        important_prefixes = (
            "Path:", "Size:", "SHA256:", "Entropy:", "Format:", "Machine:",
            "Subsystem:", "Entry RVA:", "Entry VA:", "Entry:", "Image base:",
        )
        selected = [
            line for line in lines
            if line.startswith(important_prefixes)
        ]
        selected.extend(self._compact_markdown_sections(
            text,
            ("packer", "pe", "elf", "mach-o", "sections", "imports"),
            per_section=4,
        ))
        return selected[:max_lines]

    def _preview_ida_analyze(self, text: str, max_lines: int) -> list[str]:
        lines = text.splitlines()
        selected = [
            line for line in lines
            if line.startswith((
                "Input:", "Output JSON:", "Processor:", "Image base:", "Entry:",
                "Segments:", "Functions:", "Imports:", "Strings:",
                "Candidate functions:", "Entry analysis order:", "Pseudocode functions:",
            ))
        ]
        selected.extend(self._compact_markdown_sections(
            text,
            ("entry analysis order", "candidate functions", "top functions", "imports", "strings", "pseudocode"),
            per_section=5,
        ))
        return selected[:max_lines]

    def _preview_ida_deobfuscate(self, text: str, max_lines: int) -> list[str]:
        lines = text.splitlines()
        selected = [
            line for line in lines
            if line.startswith((
                "Input:", "Output JSON:", "Processor:", "Image base:",
                "Patched IDA database:", "Opaque predicates:",
                "Junk instructions:", "Flattened candidates:",
                "PE/API function labels:", "Function maps:", "Signatures:",
                "External deobfuscators:", "Strings:", "Pseudocode functions:",
            ))
        ]
        selected.extend(self._compact_markdown_sections(
            text,
            (
                "warnings",
                "flattened switch",
                "opaque predicates",
                "junk instructions",
                "pe/api labels",
                "function maps",
                "external deobfuscators",
            ),
            per_section=4,
        ))
        return selected[:max_lines]

    def _preview_obfuscated_data_map(self, text: str, max_lines: int) -> list[str]:
        lines = text.splitlines()
        selected = [
            line for line in lines
            if line.startswith(("Path:", "Size:", "SHA256:", "Window:"))
        ]
        selected.extend(self._compact_markdown_sections(
            text,
            (
                "suspicious pe sections",
                "high-entropy regions",
                "plain magic hits",
                "xor magic hits",
                "crypto",
                "recommended next actions",
            ),
            per_section=4,
        ))
        return selected[:max_lines]

    def _preview_reverse_markdown(self, text: str, max_lines: int) -> list[str]:
        lines = text.splitlines()
        selected = [
            line for line in lines
            if line.startswith((
                "Path:", "Size:", "Plain strings returned:",
                "Base64/hex decoded strings:", "XOR decoded strings:",
                "JSON output:", "Frida script:", "Frida collector:",
                "x64dbg script:", "Module:", "Decrypt offset:",
                "API hooks:", "Argument indexes:", "Goal:", "Signals:",
                "Keywords:", "Input:", "Output JSON:", "Targets:", "Errors:",
            ))
        ]
        selected.extend(self._compact_markdown_sections(
            text,
            (
                "recommended routes",
                "matched imports",
                "matched strings",
                "candidate functions",
                "pseudocode hits",
                "pseudocode",
                "calls",
                "function maps",
                "strings",
                "obfuscation signals",
                "xref function hints",
                "decoded base64/hex",
                "xor strings",
                "main-window rule",
                "recommended use",
            ),
            per_section=4,
        ))
        return selected[:max_lines]

    def _select_tool_preview_lines(
        self, name: str, text: str, max_lines: int, max_chars: int,
    ) -> tuple[str, list[str], bool]:
        """Pick useful terminal preview lines without flooding the screen."""
        all_lines = text.splitlines()
        truncated = len(text) > max_chars
        if name == "read_file":
            shown = self._preview_read_file(text, max_lines)
            return "code", shown, truncated or len(all_lines) > len(shown)
        if name == "binary_inspect":
            shown = self._preview_binary_inspect(text, max_lines)
            return "key output", shown, truncated or len(all_lines) > len(shown)
        if name == "ida_analyze":
            shown = self._preview_ida_analyze(text, max_lines)
            return "key output", shown, truncated or len(all_lines) > len(shown)
        if name == "ida_focus_decompile":
            shown = self._preview_reverse_markdown(text, max_lines)
            return "key output", shown, truncated or len(all_lines) > len(shown)
        if name == "ida_deobfuscate":
            shown = self._preview_ida_deobfuscate(text, max_lines)
            return "key output", shown, truncated or len(all_lines) > len(shown)
        if name == "obfuscated_data_map":
            shown = self._preview_obfuscated_data_map(text, max_lines)
            return "key output", shown, truncated or len(all_lines) > len(shown)
        if name in (
            "encoded_string_extract",
            "reverse_technique_map",
            "reverse_evidence_map",
            "runtime_string_hooks",
        ):
            shown = self._preview_reverse_markdown(text, max_lines)
            return "key output", shown, truncated or len(all_lines) > len(shown)

        shown = all_lines[:max_lines]
        if len(text) > max_chars:
            shown = text[:max_chars].splitlines()[:max_lines]
        truncated = truncated or len(all_lines) > len(shown)
        return "output", shown, truncated

    def _render_tool_output_preview(self, name: str, result) -> None:
        """Echo a small, readable preview of selected tool output."""
        if not self._should_preview_tool_output(name, result):
            return
        from rich.markup import escape
        configured_lines = int(getattr(self.config, "tool_preview_lines", 8) or 0)
        if configured_lines <= 0 and name in (
            "ida_analyze",
            "ida_focus_decompile",
            "ida_deobfuscate",
            "encoded_string_extract",
            "obfuscated_data_map",
            "reverse_technique_map",
            "reverse_evidence_map",
            "runtime_string_hooks",
        ) and not result.is_error:
            max_lines = 8
        else:
            max_lines = max(1, configured_lines)
        max_chars = max(80, int(getattr(self.config, "tool_preview_chars", 1200)))
        text = result.content.strip()
        label, shown, truncated = self._select_tool_preview_lines(
            name, text, max_lines, max_chars,
        )
        if result.is_error:
            label = "error"
        label_style = "red" if result.is_error else "dim"
        line_style = "red" if result.is_error else "dim"
        self._safe_print(f"    [{label_style}]showing {label}[/]")
        for line in shown:
            self._safe_print(f"      [{line_style}]{escape(line)}[/]")
        if truncated:
            self._safe_print("      [dim]... output kept in context[/]")

