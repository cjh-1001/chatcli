"""Orchestrate parallel analysis of remote results via observer children."""

from __future__ import annotations

from .base import Tool, ToolResult


class OrchestrateResultsTool(Tool):
    """Spawn observer child agents to analyze remote analysis results in parallel."""

    name = "orchestrate_results"
    description = (
        "Spawn parallel observer child agents to analyze remote analysis results. "
        "Each observer focuses on one dimension:\n"
        "  static_observer  — binary metadata, capa, yara, strings, behavior hypotheses\n"
        "  dynamic_observer — API trace, process tree, file/registry changes, hypothesis validation\n"
        "  network_observer — DNS, HTTP, TLS, C2 patterns, network IOCs\n"
        "  correlator       — cross-references all observers, produces unified report\n"
        "\n"
        "Observers run in parallel; correlator waits for observers to complete. "
        "All results are written to .chatcli/children/<observer-name>.md.\n"
        "\n"
        "Use this after remote_consume (or remote_guest download) has pulled "
        "results to a local directory."
    )
    parameters = {
        "type": "object",
        "properties": {
            "result_dir": {
                "type": "string",
                "description": "Local path to downloaded results (e.g., .chatcli/remote_results/case-abc123/).",
            },
            "roles": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Observer roles to spawn. Default: static, dynamic, network. Use 'all' for all 4 including correlator.",
            },
        },
        "required": ["result_dir"],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def execute(
        self,
        result_dir: str,
        roles: list[str] | None = None,
        **kwargs,
    ) -> ToolResult:
        from pathlib import Path

        target = Path(result_dir).expanduser().resolve()
        if not target.is_dir():
            return ToolResult(
                content=f"Result directory not found: {target}",
                is_error=True,
            )

        # This tool can only be called from within the REPL context
        # (it needs access to ChildWindowMixin methods).
        # When called standalone (tests, non-REPL), return a plan.
        from chatcli.orchestrate import (
            ANALYSIS_ROLES,
            get_observer_roles,
            get_role_order,
        )

        role_names = roles if roles else get_observer_roles()
        if "all" in role_names:
            role_names = get_role_order()

        valid = [r for r in role_names if r in ANALYSIS_ROLES]
        invalid = [r for r in role_names if r not in ANALYSIS_ROLES]

        lines = [
            f"# Orchestration Plan: {target.name}",
            f"Result directory: {target}",
            "",
            "## Roles to spawn",
        ]

        for r in valid:
            role = ANALYSIS_ROLES[r]
            deps = role.get("depends_on", [])
            dep_text = f" (depends on: {', '.join(deps)})" if deps else ""
            lines.append(f"- **{r}**{dep_text}: {role['description'][:100]}")

        if invalid:
            lines.append(f"\n## Invalid roles (skipped): {', '.join(invalid)}")

        lines.extend([
            "",
            "## Execution plan",
            "1. Spawn observers in parallel: " + ", ".join([r for r in valid if r != "correlator"]),
            "2. Wait for observers to complete",
            "3. Spawn correlator to merge findings",
            "4. Read correlator output → final report",
            "",
            "## To execute",
            f"Run `/observe {target} {(' ').join(valid)}` in the chatcli REPL.",
            "Or let the main agent read child records from .chatcli/children/.",
        ])

        # Try to auto-spawn if we're in a REPL context
        repl_hint = (
            "\n\n[Note: This tool shows the plan. To actually spawn observers, "
            "use `/observe <result_dir>` in interactive mode, or call "
            "chatcli_auto_request to queue child tasks.]"
        )

        return ToolResult(
            content="\n".join(lines) + repl_hint,
            metadata={
                "result_dir": str(target),
                "roles": valid,
                "role_count": len(valid),
            },
        )
