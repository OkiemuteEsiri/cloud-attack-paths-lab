from __future__ import annotations

from .models import AttackPath, Edge, Node


def _priority(score: float) -> str:
    if score >= 80:
        return "P0"
    if score >= 60:
        return "P1"
    if score >= 40:
        return "P2"
    return "P3"


def score_path(nodes: dict[str, Node], path_nodes: tuple[str, ...], edges: tuple[Edge, ...]) -> AttackPath:
    destination = nodes[path_nodes[-1]]
    start = nodes[path_nodes[0]]

    criticality = destination.criticality * 10
    privilege = 15 if destination.privileged else 0
    exposure = 12 if start.internet_exposed else 0
    likelihood = sum(edge.likelihood for edge in edges) / len(edges) * 6
    weak_controls = sum((5 - edge.control_strength) for edge in edges) / len(edges) * 5
    hop_penalty = max(0, len(edges) - 1) * 4

    raw = criticality + privilege + exposure + likelihood + weak_controls - hop_penalty
    score = round(max(0.0, min(100.0, raw)), 1)

    rationale = [f"destination criticality={destination.criticality}/5"]
    if destination.privileged:
        rationale.append("destination grants privileged capability")
    if start.internet_exposed:
        rationale.append("path originates from an internet-exposed node")
    if any(edge.control_strength <= 1 for edge in edges):
        rationale.append("one or more relationships have weak preventive controls")
    rationale.append(f"path length={len(edges)} hop(s)")

    return AttackPath(
        nodes=path_nodes,
        relations=tuple(edge.relation for edge in edges),
        score=score,
        priority=_priority(score),
        rationale=tuple(rationale),
    )
