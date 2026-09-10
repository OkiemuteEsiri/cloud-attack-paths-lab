from __future__ import annotations

import argparse
import json
from pathlib import Path

from .graph import find_paths
from .models import Edge, Node


def load_inventory(path: Path) -> tuple[dict[str, Node], list[Edge], set[str], set[str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    nodes: dict[str, Node] = {}
    for item in payload["nodes"]:
        node = Node(
            id=item["id"], name=item["name"], node_type=item["node_type"], provider=item["provider"],
            criticality=item.get("criticality", 1), internet_exposed=item.get("internet_exposed", False),
            privileged=item.get("privileged", False), tags=frozenset(item.get("tags", [])),
        )
        if node.id in nodes:
            raise ValueError(f"duplicate node id: {node.id}")
        nodes[node.id] = node
    edges = [Edge(**item) for item in payload["edges"]]
    return nodes, edges, set(payload["entry_points"]), set(payload["protected_targets"])


def render_markdown(nodes: dict[str, Node], paths: list) -> str:
    lines = ["# Cloud Attack Path Assessment", "", "Synthetic defensive analysis; paths indicate potential exposure, not evidence of compromise.", ""]
    if not paths:
        lines.append("No paths matched the configured entry points and protected targets.")
        return "\n".join(lines) + "\n"
    lines += ["| Priority | Score | Path |", "|---|---:|---|"]
    for path in paths:
        names = " → ".join(nodes[node_id].name for node_id in path.nodes)
        lines.append(f"| {path.priority} | {path.score:.1f} | {names} |")
    lines += ["", "## Remediation focus", ""]
    for index, path in enumerate(paths[:5], start=1):
        lines.append(f"{index}. **{path.priority} / {path.score:.1f}** — " + "; ".join(path.rationale))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic cloud attack-path relationships")
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--max-hops", type=int, default=5)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    nodes, edges, entry_points, targets = load_inventory(args.inventory)
    paths = find_paths(nodes, edges, entry_points, targets, max_hops=args.max_hops)
    report = render_markdown(nodes, paths)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
