"""Darwin evolution skill — iterative code optimization.

/evolve <file> [--goal <text>] [--test <cmd>] [--generations N] [--variations N]

Generates N code variations per generation, tests each, keeps the
fittest, and repeats for G generations. Think "natural selection for code."

Progress is saved to .chatcli/evolve/ for interrupt/resume.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional


def _evolve_dir(workspace: str) -> Path:
    return Path(workspace) / ".chatcli" / "evolve"


def _state_file(workspace: str) -> Path:
    return _evolve_dir(workspace) / "state.json"


def _log_file(workspace: str) -> Path:
    return _evolve_dir(workspace) / "log.md"


# ── State management ──────────────────────────────────────────────


def start_evolve(
    workspace: str,
    target_file: str,
    goal: str = "improve the code",
    test_cmd: str = "",
    generations: int = 3,
    variations: int = 3,
) -> dict:
    """Initialize an evolution session. Returns state dict."""
    ev_dir = _evolve_dir(workspace)
    ev_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now().isoformat()

    state = {
        "target": target_file,
        "goal": goal,
        "test_cmd": test_cmd,
        "generations": generations,
        "variations": variations,
        "current_gen": 0,
        "best_score": None,
        "best_content": "",
        "history": [],
        "started": now,
        "status": "running",
    }
    _save_state(workspace, state)

    # Init log
    lf = _log_file(workspace)
    lf.write_text(
        f"# Evolution Log\n\n"
        f"**Target:** {target_file}\n"
        f"**Goal:** {goal}\n"
        f"**Test:** {test_cmd or '(manual review)'}\n"
        f"**Generations:** {generations} × {variations} variations\n"
        f"**Started:** {now}\n\n"
        f"---\n\n",
        encoding="utf-8",
    )

    return state


def get_state(workspace: str) -> Optional[dict]:
    """Read current evolution state."""
    sf = _state_file(workspace)
    if not sf.exists():
        return None
    return json.loads(sf.read_text(encoding="utf-8"))


def _save_state(workspace: str, state: dict):
    _state_file(workspace).write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def record_generation(workspace: str, gen: int, results: list[dict],
                       winner: int, score: float, best_content: str) -> dict:
    """Record a completed generation. Updates state and returns it."""
    state = get_state(workspace)
    if not state:
        return {}

    entry = {
        "generation": gen,
        "results": results,
        "winner": winner,
        "score": score,
        "time": datetime.now().isoformat(),
    }
    state["history"].append(entry)
    state["current_gen"] = gen
    state["best_score"] = score
    state["best_content"] = best_content

    if gen >= state["generations"]:
        state["status"] = "done"

    _save_state(workspace, state)

    # Append to log
    with open(_log_file(workspace), "a", encoding="utf-8") as f:
        f.write(f"## Generation {gen}\n\n")
        for i, r in enumerate(results):
            mark = "★" if i == winner else ""
            f.write(
                f"- {mark} Variation {i+1}: score={r.get('score','?')}"
                f" {r.get('summary','')}\n"
            )
        f.write(f"\n**Winner:** variation {winner+1} (score={score})\n\n")

    return state


def complete_evolve(workspace: str, summary: str = "") -> None:
    """Mark evolution as complete."""
    state = get_state(workspace)
    if state:
        state["status"] = "done"
        _save_state(workspace, state)

    if summary:
        with open(_log_file(workspace), "a", encoding="utf-8") as f:
            f.write(f"---\n\n## Final Result\n\n{summary}\n")


def get_progress(workspace: str) -> str:
    """Return a human-readable progress summary."""
    state = get_state(workspace)
    if not state:
        return "(no active evolution)"

    gen = state["current_gen"]
    total = state["generations"]
    best = state.get("best_score", "—")

    lines = [
        f"Evolution: gen {gen}/{total} | best score: {best}",
        f"Target: {state['target']}",
        f"Goal: {state['goal']}",
        f"Test: {state.get('test_cmd') or '(manual)'}",
    ]
    if state["history"]:
        last = state["history"][-1]
        lines.append(f"Last: gen {last['generation']} winner=var {last['winner']+1} score={last['score']}")

    return "\n".join(lines)


# ── Evolution prompt ───────────────────────────────────────────────


def _evolve_prompt_base(target: str, goal: str, test_cmd: str, gen_label: str,
                        total: int, var_count: int, extra: str = "") -> str:
    """Shared prompt template for evolution generations."""
    test_part = f"\n**Test command:** `{test_cmd}`" if test_cmd else ""
    return f"""\
## DARWIN EVOLUTION MODE — {gen_label}

You are evolving `{target}` through natural selection — generating variations,
testing them, and keeping the fittest.

**Goal:** {goal}
**Variations per generation:** {var_count}{test_part}
{extra}
### Rules:
- Keep variations SMALL — one focused change each
- ALWAYS run the test before declaring a winner
- If all variations fail, keep the baseline and note what was tried
- Do NOT change the test or the goal
- Report scores as: `SCORE: <number> — <reason>`
"""


def build_evolve_prompt(state: dict) -> str:
    """Build the system prompt for non-first generations."""
    gen = state["current_gen"]
    return _evolve_prompt_base(
        target=state["target"],
        goal=state["goal"],
        test_cmd=state.get("test_cmd", ""),
        gen_label=f"Generation {gen + 1}/{state['generations']}",
        total=state["generations"],
        var_count=state["variations"],
        extra="""
### Process for this generation:

1. **Baseline:** Read the current state and run the test to get a baseline score.
2. **Generate variations:** For each variation, apply ONE focused change.
3. **Test each variation:** Run the test command (or manually review).
   Score each 0-100 (tests=50, goal=30, quality=20).
4. **Select the fittest:** Keep the best, revert failures.
5. **Record results:** Report scores clearly so I can log them.
""",
    )


def build_evolve_first_prompt(state: dict) -> str:
    """First-generation prompt with extra setup instructions."""
    return _evolve_prompt_base(
        target=state["target"],
        goal=state["goal"],
        test_cmd=state.get("test_cmd", ""),
        gen_label=f"Generation 1/{state['generations']}",
        total=state["generations"],
        var_count=state["variations"],
        extra="""
### Setup (do this first):
1. Read the target file to understand the current code
2. Run the test command to get a baseline score
3. Create `.chatcli/evolve/log.md` if it doesn't exist

### For each generation:
1. Generate variations, each with ONE focused change
2. Test each variation
3. Score each 0-100 (tests=50, goal=30, quality=20)
4. Keep the best, discard the rest
5. Report: `SCORE: <number> — <reason>`

After all generations, summarize what evolved and why.

**Start now — read the target file and begin Generation 1.**
""",
    )


# ── Continuous self-improvement mode ──────────────────────────────


def start_continuous(workspace: str, focus: str = "") -> dict:
    """Start a continuous self-improvement session. No fixed target —
    the model scans the codebase and picks optimization targets one by one.
    """
    ev_dir = _evolve_dir(workspace)
    ev_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now().isoformat()

    state = {
        "mode": "continuous",
        "focus": focus or "general code quality and performance",
        "cycles_completed": 0,
        "current_target": "",
        "current_goal": "",
        "total_improvements": [],
        "started": now,
        "status": "running",
    }
    _save_state(workspace, state)

    lf = _log_file(workspace)
    lf.write_text(
        f"# Continuous Evolution Log\n\n"
        f"**Mode:** Continuous self-improvement\n"
        f"**Focus:** {state['focus']}\n"
        f"**Started:** {now}\n\n"
        f"---\n\n",
        encoding="utf-8",
    )

    return state


def record_cycle(workspace: str, target: str, goal: str,
                  result: str, score: int = 0) -> dict:
    """Record a completed improvement cycle."""
    state = get_state(workspace)
    if not state:
        return {}

    state["cycles_completed"] = state.get("cycles_completed", 0) + 1
    state["total_improvements"].append({
        "target": target,
        "goal": goal,
        "result": result,
        "score": score,
        "time": datetime.now().isoformat(),
    })
    state["current_target"] = ""
    state["current_goal"] = ""
    _save_state(workspace, state)

    # Log
    n = state["cycles_completed"]
    with open(_log_file(workspace), "a", encoding="utf-8") as f:
        f.write(f"## Cycle {n}: {target}\n\n")
        f.write(f"**Goal:** {goal}\n")
        f.write(f"**Score:** {score}\n\n")
        f.write(f"{result}\n\n")
        f.write(f"---\n\n")

    return state


def get_continuous_progress(workspace: str) -> str:
    """Return progress for continuous mode."""
    state = get_state(workspace)
    if not state:
        return "(no active evolution)"

    n = state.get("cycles_completed", 0)
    improvements = state.get("total_improvements", [])
    lines = [
        f"Continuous Evolution: {n} cycles completed",
        f"Focus: {state.get('focus', 'general')}",
        f"Started: {state.get('started', '?')[:16]}",
    ]
    for imp in improvements[-5:]:
        lines.append(f"  [{imp['score']}] {imp['target']} — {imp['goal'][:60]}")

    return "\n".join(lines)


def build_continuous_prompt(state: dict) -> str:
    """Build the never-ending self-improvement prompt."""
    focus = state.get("focus", "general code quality and performance")
    cycles = state.get("cycles_completed", 0)
    improvements = state.get("total_improvements", [])

    recent = ""
    if improvements:
        recent = "\n**Recent improvements:**\n"
        for imp in improvements[-3:]:
            recent += f"- [{imp['score']}] `{imp['target']}` — {imp['goal'][:80]}\n"

    return f"""\
## CONTINUOUS SELF-IMPROVEMENT MODE

You are in a continuous improvement loop. Your job: keep making chatcli better,
one focused change at a time. Do NOT stop until the user interrupts you.

**Focus area:** {focus}
**Cycles completed so far:** {cycles}{recent}

### Each cycle:

1. **SCAN** the codebase for a concrete improvement opportunity:
   - Dead code or unused imports
   - Functions that can be simplified or inlined
   - Better error handling or edge case coverage
   - Performance bottlenecks
   - Missing type annotations or docstrings
   - Code duplication that can be extracted
   - Better naming or restructuring

2. **PICK ONE** — the most impactful quick win. Report what you chose and why.

3. **EXECUTE** — make the change with edit_file. Keep it SMALL and SAFE:
   - One focused change per cycle
   - If it touches agent.py or tools/*, the auto-backup will protect you
   - Verify the change compiles (run `python -c \"import chatcli\"` or similar)

4. **VERIFY** — check that nothing broke:
   - At minimum: `python -c \"from chatcli.tools import create_registry; create_registry()\"`
   - If there's a specific test, run it

5. **LOG** — tell me what you did so I can record it. Format:
   ```
   CYCLE DONE: <target file> | <what changed> | SCORE: <0-100>
   ```

### Rules:
- ONE change per cycle — don't batch unrelated edits
- ALWAYS verify the code still imports/works after each change
- If a change breaks things, revert it immediately
- After 3 cycles, pick a different area of the codebase
- Don't touch the same file more than 3 times in a row
- The auto-backup system protects you — don't be afraid to experiment

### Current codebase health check:
Run `python -c "from chatcli.tools import create_registry; r=create_registry(); print(str(len(r.list_tools())) + ' tools OK')"` to confirm chatcli works.

**Start your first cycle now. Scan, pick, execute, verify, log. Go!**
"""

