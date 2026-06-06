"""Build a lightweight evidence graph from behavior and attack-chain outputs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ._json_utils import load_json
from ._text_utils import short_text
from ._analysis_collectors import as_text_list, collect_analysis_items
from .base import Tool, ToolResult, coerce_int, coerce_str_list


def _find_lists(value: Any, capabilities: list[dict[str, Any]], attack_chain: list[dict[str, Any]]) -> None:
    collect_analysis_items(
        value,
        capabilities=capabilities,
        attack_chain=attack_chain,
        include_report_candidates=True,
        report_candidate_category_default="report_candidate",
        report_candidate_label_default="报告能力候选",
    )


def _add_node(
    nodes: dict[str, dict[str, Any]],
    node_id: str,
    node_type: str,
    label: str,
    max_nodes: int,
    **attrs,
) -> bool:
    if node_id not in nodes:
        if len(nodes) >= max_nodes:
            return False
        nodes[node_id] = {"id": node_id, "type": node_type, "label": label, **attrs}
    return True


def _add_edge(edges: list[dict[str, str]], source: str, target: str, edge_type: str, label: str = "") -> None:
    edge = {"source": source, "target": target, "type": edge_type, "label": label}
    if edge not in edges:
        edges.append(edge)


def _as_list(value: Any) -> list[str]:
    return as_text_list(value)


def _dedupe_attack_chain(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    positions: dict[str, int] = {}
    for item in items:
        if item.get("step") is not None:
            key = f"step:{item.get('step')}"
        else:
            key = f"behavior:{short_text(item.get('behavior'), 100).lower()}"
        if key not in positions:
            positions[key] = len(deduped)
            deduped.append(item)
            continue
        current = deduped[positions[key]]
        if not current.get("source_category") and item.get("source_category"):
            deduped[positions[key]] = item
    return deduped


def _build_graph(capabilities: list[dict[str, Any]], attack_chain: list[dict[str, Any]], max_nodes: int) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    category_to_caps: dict[str, list[str]] = {}

    for idx, cap in enumerate(capabilities):
        if len(nodes) >= max_nodes:
            break
        category = str(cap.get("category") or "unknown")
        label = str(cap.get("label") or cap.get("category") or "能力候选")
        cap_id = f"cap:{idx}:{category}"
        _add_node(
            nodes,
            cap_id,
            "capability",
            label,
            max_nodes,
            category=category,
            confidence=str(cap.get("confidence") or "low"),
            claim_level=str(cap.get("claim_level") or "static capability"),
            confidence_reason=str(cap.get("confidence_reason") or ""),
            evidence_sources=_as_list(cap.get("evidence_sources")),
        )
        category_to_caps.setdefault(category, []).append(cap_id)

        for term in _as_list(cap.get("matched_terms"))[:10]:
            sig_id = f"signal:{term.lower()[:80]}"
            if _add_node(nodes, sig_id, "signal", short_text(term), max_nodes):
                _add_edge(edges, sig_id, cap_id, "matches", "matches")

        for eidx, evidence in enumerate(_as_list(cap.get("evidence"))[:8]):
            ev_id = f"evidence:{idx}:{eidx}"
            if _add_node(nodes, ev_id, "evidence", short_text(evidence), max_nodes):
                _add_edge(edges, ev_id, cap_id, "supports", "supports")

        gates = _as_list(cap.get("claim_gate")) + _as_list(cap.get("required_validation"))
        for gidx, gate in enumerate(gates[:6]):
            gate_id = f"gate:{idx}:{gidx}"
            if _add_node(nodes, gate_id, "validation", short_text(gate), max_nodes):
                _add_edge(edges, cap_id, gate_id, "requires_validation", "requires")

    for idx, step in enumerate(attack_chain):
        if len(nodes) >= max_nodes:
            break
        step_no = step.get("step", idx + 1)
        behavior = str(step.get("behavior") or f"step {step_no}")
        step_id = f"step:{step_no}"
        _add_node(
            nodes,
            step_id,
            "attack_step",
            short_text(behavior),
            max_nodes,
            confidence=str(step.get("confidence") or ""),
            gate_status=str(step.get("gate_status") or ""),
        )
        categories = str(step.get("source_category") or "")
        for category in [part.strip() for part in categories.split("+") if part.strip()]:
            for cap_id in category_to_caps.get(category, []):
                _add_edge(edges, cap_id, step_id, "orders_into", "orders into")

        for eidx, evidence in enumerate(_as_list(step.get("evidence"))[:4]):
            ev_id = f"step_evidence:{step_no}:{eidx}"
            if _add_node(nodes, ev_id, "evidence", short_text(evidence), max_nodes):
                _add_edge(edges, ev_id, step_id, "supports", "supports")

    return {"nodes": list(nodes.values()), "edges": edges}


def _audit_graph(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    supported_targets = {edge.get("target") for edge in edges if edge.get("type") == "supports"}
    validation_sources = {edge.get("source") for edge in edges if edge.get("type") == "requires_validation"}

    unsupported_capabilities = [
        {
            "id": node.get("id"),
            "label": node.get("label"),
            "category": node.get("category"),
            "confidence": node.get("confidence"),
        }
        for node in nodes
        if node.get("type") == "capability" and node.get("id") not in supported_targets
    ]
    unsupported_attack_steps = [
        {
            "id": node.get("id"),
            "label": node.get("label"),
            "confidence": node.get("confidence"),
            "gate_status": node.get("gate_status"),
        }
        for node in nodes
        if node.get("type") == "attack_step" and node.get("id") not in supported_targets
    ]
    validation_required = [
        {
            "id": node.get("id"),
            "label": node.get("label"),
            "category": node.get("category"),
            "confidence": node.get("confidence"),
        }
        for node in nodes
        if node.get("type") == "capability" and node.get("id") in validation_sources
    ]

    evidence_source_counts: dict[str, int] = {}
    for node in nodes:
        if node.get("type") != "capability":
            continue
        sources = node.get("evidence_sources") or []
        if not sources:
            evidence_source_counts["unspecified"] = evidence_source_counts.get("unspecified", 0) + 1
            continue
        for source in sources:
            key = str(source).strip() or "unspecified"
            evidence_source_counts[key] = evidence_source_counts.get(key, 0) + 1

    return {
        "unsupported_capabilities": unsupported_capabilities,
        "unsupported_attack_steps": unsupported_attack_steps,
        "validation_required": validation_required,
        "evidence_source_counts": evidence_source_counts,
        "summary": {
            "unsupported_capabilities": len(unsupported_capabilities),
            "unsupported_attack_steps": len(unsupported_attack_steps),
            "validation_required": len(validation_required),
        },
    }


class EvidenceGraphTool(Tool):
    name = "evidence_graph"
    description = (
        "Build a lightweight evidence graph linking signals, evidence snippets, "
        "behavior capabilities, claim gates, and attack-chain steps. Useful for "
        "auditing whether malware-report conclusions are evidence-backed."
    )
    parameters = {
        "type": "object",
        "properties": {
            "capabilities": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Optional behavior capability objects.",
            },
            "attack_chain": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Optional attack-chain step objects.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files to mine for capabilities and attack-chain hints.",
            },
            "max_nodes": {
                "type": "integer",
                "description": "Maximum graph nodes to return. Default 300.",
            },
        },
    }

    def execute(
        self,
        capabilities: list[dict[str, Any]] | None = None,
        attack_chain: list[dict[str, Any]] | None = None,
        json_paths: list[str] | str | None = None,
        max_nodes: int = 300,
        **kwargs,
    ) -> ToolResult:
        max_nodes = coerce_int(max_nodes, 300, minimum=20, maximum=2000)
        caps = [item for item in (capabilities or []) if isinstance(item, dict)]
        chain = [item for item in (attack_chain or []) if isinstance(item, dict)]
        warnings = []

        for raw_path in coerce_str_list(json_paths):
            data, error = load_json(Path(raw_path), label="evidence graph")
            if error:
                warnings.append(error)
                continue
            _find_lists(data, caps, chain)

        chain = _dedupe_attack_chain(chain)
        if not caps and not chain:
            return ToolResult(
                content="Error: provide capabilities, attack_chain, or json_paths containing those structures.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        graph = _build_graph(caps, chain, max_nodes)
        audit = _audit_graph(graph)
        node_counts: dict[str, int] = {}
        edge_counts: dict[str, int] = {}
        for node in graph["nodes"]:
            node_counts[node["type"]] = node_counts.get(node["type"], 0) + 1
        for edge in graph["edges"]:
            edge_counts[edge["type"]] = edge_counts.get(edge["type"], 0) + 1

        lines = [
            "# Evidence Graph",
            "",
            f"Capabilities: {len(caps)}",
            f"Attack-chain steps: {len(chain)}",
            f"Nodes: {len(graph['nodes'])}",
            f"Edges: {len(graph['edges'])}",
            "",
            "## Node Types",
        ]
        lines.extend(f"- {key}: {value}" for key, value in sorted(node_counts.items()))
        lines.extend(["", "## Edge Types"])
        lines.extend(f"- {key}: {value}" for key, value in sorted(edge_counts.items()))
        lines.extend([
            "",
            "## Audit",
            f"- Unsupported capabilities: {audit['summary']['unsupported_capabilities']}",
            f"- Unsupported attack steps: {audit['summary']['unsupported_attack_steps']}",
            f"- Capabilities requiring validation: {audit['summary']['validation_required']}",
        ])
        if audit["evidence_source_counts"]:
            lines.extend(["", "## Evidence Sources"])
            lines.extend(
                f"- {key}: {value}"
                for key, value in sorted(audit["evidence_source_counts"].items())
            )
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "warnings": warnings,
                "node_counts": node_counts,
                "edge_counts": edge_counts,
                "audit": audit,
                "graph": graph,
            },
        )
