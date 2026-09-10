from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable

from .models import AttackPath, Edge, Node
from .scoring import score_path


def build_adjacency(edges: Iterable[Edge]) -> dict[str, list[Edge]]:
    adjacency: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source].append(edge)
    return dict(adjacency)


def validate_graph(nodes: dict[str, Node], edges: Iterable[Edge]) -> None:
    seen_edges: set[tuple[str, str, str]] = set()
    for edge in edges:
        if edge.source not in nodes or edge.target not in nodes:
            raise ValueError(f"edge references unknown node: {edge.source}->{edge.target}")
        key = (edge.source, edge.target, edge.relation)
        if key in seen_edges:
            raise ValueError(f"duplicate edge: {key}")
        seen_edges.add(key)


def find_paths(
    nodes: dict[str, Node],
    edges: list[Edge],
    start_ids: set[str],
    target_ids: set[str],
    max_hops: int = 5,
) -> list[AttackPath]:
    validate_graph(nodes, edges)
    if max_hops < 1:
        raise ValueError("max_hops must be >= 1")

    adjacency = build_adjacency(edges)
    results: list[AttackPath] = []

    for start in sorted(start_ids):
        if start not in nodes:
            raise ValueError(f"unknown start node: {start}")
        queue = deque([(start, (start,), tuple())])

        while queue:
            current, path_nodes, path_edges = queue.popleft()
            hops = len(path_edges)
            if current in target_ids and hops > 0:
                results.append(score_path(nodes, path_nodes, path_edges))
                continue
            if hops >= max_hops:
                continue

            for edge in adjacency.get(current, []):
                if edge.target in path_nodes:
                    continue
                queue.append((edge.target, path_nodes + (edge.target,), path_edges + (edge,)))

    return sorted(results, key=lambda item: (-item.score, item.hops, item.nodes))
