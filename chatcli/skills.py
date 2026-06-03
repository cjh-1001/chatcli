"""Skill loader for chatcli.

Skills are folders containing a SKILL.md file with YAML frontmatter:

---
name: skill-name
description: When to use this skill.
---

Body instructions...
"""

from dataclasses import dataclass
from pathlib import Path
import re

import yaml


@dataclass
class Skill:
    name: str
    description: str
    body: str
    path: Path
    aliases: tuple[str, ...] = ()
    triggers: tuple[str, ...] = ()

    @property
    def body_chars(self) -> int:
        return len(self.body)


def _skill_roots(workspace: str) -> list[Path]:
    return [
        Path(__file__).resolve().parent / "skills",
        Path.home() / ".chatcli" / "skills",
        Path(workspace) / ".chatcli" / "skills",
    ]


def _parse_skill(path: Path) -> Skill | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return None

    name = path.parent.name
    description = ""
    body = raw.strip()
    aliases: tuple[str, ...] = ()
    triggers: tuple[str, ...] = ()

    if raw.startswith("---"):
        parts = raw.split("---", 2)
        if len(parts) >= 3:
            try:
                meta = yaml.safe_load(parts[1]) or {}
            except Exception:
                meta = {}
            metadata = meta.get("metadata") if isinstance(meta.get("metadata"), dict) else {}
            name = str(meta.get("name") or name).strip()
            description = str(meta.get("description") or "").strip()
            aliases = _normalise_terms(meta.get("aliases") or metadata.get("aliases"))
            triggers = _normalise_terms(meta.get("triggers") or metadata.get("triggers"))
            body = parts[2].strip()

    if not name or not description or not body:
        return None
    if not triggers:
        triggers = _derive_triggers(name, description)
    return Skill(
        name=name,
        description=description,
        body=body,
        path=path,
        aliases=aliases,
        triggers=triggers,
    )


def _normalise_terms(value) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        raw_terms = re.split(r"[,;\n]+", value)
    elif isinstance(value, (list, tuple, set)):
        raw_terms = list(value)
    else:
        raw_terms = [value]
    terms = []
    seen = set()
    for raw in raw_terms:
        term = str(raw).strip()
        key = term.lower()
        if term and key not in seen:
            terms.append(term)
            seen.add(key)
    return tuple(terms)


def _derive_triggers(name: str, description: str) -> tuple[str, ...]:
    """Build a compact routing vocabulary from stable skill metadata."""
    text = f"{name} {description}".lower()
    words = re.findall(r"[a-z0-9][a-z0-9_-]{2,}", text)
    cjk_terms = re.findall(r"[\u4e00-\u9fff]{2,}", f"{name} {description}")
    stop = {
        "the", "and", "for", "with", "when", "use", "uses", "this", "that",
        "workflow", "skill", "tasks", "task", "code", "source",
    }
    terms = []
    seen = set()
    for term in [name, *words, *cjk_terms]:
        key = term.lower()
        if key in stop or key in seen:
            continue
        terms.append(term)
        seen.add(key)
        if len(terms) >= 18:
            break
    return tuple(terms)


def discover_skills(workspace: str) -> list[Skill]:
    """Discover built-in, user, and project skills.

    Later roots override earlier roots by skill name, so project skills can
    replace user or built-in skills.
    """
    skills: dict[str, Skill] = {}
    for root in _skill_roots(workspace):
        if not root.exists():
            continue
        for skill_file in sorted(root.glob("*/SKILL.md")):
            skill = _parse_skill(skill_file)
            if skill:
                skills[skill.name] = skill
    return sorted(skills.values(), key=lambda s: s.name)


def rank_skills(query: str, workspace: str, limit: int = 5) -> list[tuple[int, Skill]]:
    """Rank skills for a query using name, aliases, triggers, and description."""
    text = (query or "").lower()
    if not text.strip():
        return []
    ranked: list[tuple[int, Skill]] = []
    for skill in discover_skills(workspace):
        score = 0
        name = skill.name.lower()
        if name in text:
            score += 12
        for alias in skill.aliases:
            if alias.lower() in text:
                score += 10
        for trigger in skill.triggers:
            if trigger.lower() in text:
                score += 4
        for word in re.findall(r"[a-z0-9][a-z0-9_-]{2,}|[\u4e00-\u9fff]{2,}", text):
            if word in skill.description.lower():
                score += 1
        if score:
            ranked.append((score, skill))
    ranked.sort(key=lambda item: (-item[0], item[1].name))
    return ranked[:max(1, int(limit or 5))]


def _skill_excerpt(body: str, limit: int) -> str:
    if len(body) <= limit:
        return body
    lines = []
    used = 0
    for line in body.splitlines():
        stripped = line.rstrip()
        if not stripped and not lines:
            continue
        next_used = used + len(stripped) + 1
        if next_used > limit:
            break
        lines.append(stripped)
        used = next_used
    excerpt = "\n".join(lines).strip()
    return excerpt + "\n\n[Skill body truncated in system prompt. Read the Source file before applying this skill.]"


def render_skills_prompt(
    workspace: str,
    inline_body_limit: int = 2200,
    large_skill_excerpt: int = 900,
) -> str:
    skills = discover_skills(workspace)
    if not skills:
        return ""

    lines = ["## Skills"]
    lines.append(
        "Use this routing index to pick the right skill quickly. When a request "
        "matches a skill, read its Source file before applying detailed workflow "
        "instructions, especially when the body is marked truncated. Project skills "
        "override user and built-in skills."
    )
    lines.append("")
    lines.append("### Skill Routing Index")
    for skill in skills:
        triggers = ", ".join(skill.triggers[:12]) or "(none)"
        aliases = f"; aliases={', '.join(skill.aliases)}" if skill.aliases else ""
        lines.append(
            f"- {skill.name}: {skill.description} "
            f"[triggers: {triggers}{aliases}; source: {skill.path}; chars: {skill.body_chars}]"
        )

    lines.append("")
    lines.append("### Inline Skill Notes")
    for skill in skills:
        lines.append("")
        lines.append(f"#### {skill.name}")
        lines.append(f"Source: {skill.path}")
        if skill.body_chars <= inline_body_limit:
            lines.append(skill.body)
        else:
            lines.append(_skill_excerpt(skill.body, large_skill_excerpt))
    return "\n".join(lines)
