from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


VALID_TYPES = {"identity", "role", "resource", "network", "secret", "control"}
VALID_PROVIDERS = {"aws", "azure", "gcp", "shared"}


@dataclass(frozen=True)
class Node:
    id: str
    name: str
    node_type: str
    provider: str
    criticality: int = 1
    internet_exposed: bool = False
    privileged: bool = False
    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.name.strip():
            raise ValueError("node id and name are required")
        if self.node_type not in VALID_TYPES:
            raise ValueError(f"unsupported node type: {self.node_type}")
        if self.provider not in VALID_PROVIDERS:
            raise ValueError(f"unsupported provider: {self.provider}")
        if not 1 <= self.criticality <= 5:
            raise ValueError("criticality must be between 1 and 5")


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: str
    likelihood: int = 1
    control_strength: int = 3

    def __post_init__(self) -> None:
        if not self.source or not self.target or not self.relation:
            raise ValueError("edge source, target, and relation are required")
        if not 1 <= self.likelihood <= 5:
            raise ValueError("likelihood must be between 1 and 5")
        if not 0 <= self.control_strength <= 5:
            raise ValueError("control_strength must be between 0 and 5")


@dataclass(frozen=True)
class AttackPath:
    nodes: tuple[str, ...]
    relations: tuple[str, ...]
    score: float
    priority: str
    rationale: tuple[str, ...]

    @property
    def hops(self) -> int:
        return max(0, len(self.nodes) - 1)
