"""Shared collectors for malware behavior analysis result structures."""

from __future__ import annotations

from typing import Any


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_text_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if str(item).strip()]


def report_candidate_to_capability(
    item: dict[str, Any],
    *,
    category_default: str = "unknown",
    label_default: str = "能力候选",
    force_category_default: bool = False,
    claim_level: str | None = None,
    required_validation: list[str] | None = None,
) -> dict[str, Any]:
    capability = {
        "category": category_default if force_category_default else item.get("category", category_default),
        "label": item.get("category", label_default),
        "matched_terms": [item.get("technique", "")],
        "evidence": [item.get("evidence", "")],
        "confidence": item.get("confidence", "low"),
        "required_validation": list(required_validation or []),
    }
    if claim_level is not None:
        capability["claim_level"] = claim_level
    return capability


def collect_analysis_items(
    value: Any,
    *,
    capabilities: list[dict[str, Any]] | None = None,
    attack_chain: list[dict[str, Any]] | None = None,
    audits: list[dict[str, Any]] | None = None,
    include_capabilities: bool = True,
    include_attack_chain: bool = True,
    include_steps: bool = True,
    include_audits: bool = True,
    include_report_attack_chain: bool = True,
    include_report_candidates: bool = False,
    report_candidate_category_default: str = "unknown",
    report_candidate_label_default: str = "能力候选",
    report_candidate_force_category_default: bool = False,
    report_candidate_claim_level: str | None = None,
    report_candidate_required_validation: list[str] | None = None,
    require_capability_identity: bool = False,
) -> None:
    """Recursively collect common analysis lists from nested JSON-like objects."""
    if isinstance(value, dict):
        if include_capabilities and capabilities is not None:
            caps = value.get("capabilities")
            if isinstance(caps, list):
                for item in caps:
                    if not isinstance(item, dict):
                        continue
                    if require_capability_identity and not (item.get("category") or item.get("label")):
                        continue
                    capabilities.append(item)

        if include_attack_chain and attack_chain is not None:
            chain = value.get("attack_chain")
            if isinstance(chain, list):
                attack_chain.extend(item for item in chain if isinstance(item, dict))

        if include_steps and attack_chain is not None:
            steps = value.get("steps")
            if isinstance(steps, list):
                attack_chain.extend(item for item in steps if isinstance(item, dict))

        if include_audits and audits is not None:
            audit = value.get("audit")
            if isinstance(audit, dict):
                audits.append(audit)

        hints = value.get("report_hints")
        if isinstance(hints, dict):
            if include_report_attack_chain and attack_chain is not None:
                hinted_chain = hints.get("attack_chain")
                if isinstance(hinted_chain, list):
                    attack_chain.extend(item for item in hinted_chain if isinstance(item, dict))
            if include_report_candidates and capabilities is not None:
                candidates = hints.get("key_capability_candidates")
                if isinstance(candidates, list):
                    for item in candidates:
                        if isinstance(item, dict):
                            capabilities.append(
                                report_candidate_to_capability(
                                    item,
                                    category_default=report_candidate_category_default,
                                    label_default=report_candidate_label_default,
                                    force_category_default=report_candidate_force_category_default,
                                    claim_level=report_candidate_claim_level,
                                    required_validation=report_candidate_required_validation,
                                )
                            )

        for child in value.values():
            collect_analysis_items(
                child,
                capabilities=capabilities,
                attack_chain=attack_chain,
                audits=audits,
                include_capabilities=include_capabilities,
                include_attack_chain=include_attack_chain,
                include_steps=include_steps,
                include_audits=include_audits,
                include_report_attack_chain=include_report_attack_chain,
                include_report_candidates=include_report_candidates,
                report_candidate_category_default=report_candidate_category_default,
                report_candidate_label_default=report_candidate_label_default,
                report_candidate_force_category_default=report_candidate_force_category_default,
                report_candidate_claim_level=report_candidate_claim_level,
                report_candidate_required_validation=report_candidate_required_validation,
                require_capability_identity=require_capability_identity,
            )
    elif isinstance(value, list):
        for child in value:
            collect_analysis_items(
                child,
                capabilities=capabilities,
                attack_chain=attack_chain,
                audits=audits,
                include_capabilities=include_capabilities,
                include_attack_chain=include_attack_chain,
                include_steps=include_steps,
                include_audits=include_audits,
                include_report_attack_chain=include_report_attack_chain,
                include_report_candidates=include_report_candidates,
                report_candidate_category_default=report_candidate_category_default,
                report_candidate_label_default=report_candidate_label_default,
                report_candidate_force_category_default=report_candidate_force_category_default,
                report_candidate_claim_level=report_candidate_claim_level,
                report_candidate_required_validation=report_candidate_required_validation,
                require_capability_identity=require_capability_identity,
            )
