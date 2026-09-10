# Architecture

## Objective

Model potential cloud privilege and resource relationships as a directed graph, identify paths from exposed or lower-trust entry points to protected targets, and prioritize those paths for defensive remediation.

## Components

1. **Data model (`src/models.py`)** — immutable nodes, edges, and scored attack paths with strict validation.
2. **Graph engine (`src/graph.py`)** — validates relationship integrity, builds adjacency maps, and performs bounded breadth-first path discovery without revisiting nodes in the same path.
3. **Risk engine (`src/scoring.py`)** — produces an explainable 0–100 score using target criticality, privileged capability, internet exposure, relationship likelihood, preventive-control strength, and path length.
4. **CLI/reporting (`src/cli.py`)** — loads synthetic inventory, executes analysis, and renders Markdown findings.
5. **Synthetic data (`data/`)** — provider-neutral AWS, Azure, GCP, and shared-identity relationships created solely for demonstration.
6. **Tests (`tests/`)** — validate graph integrity, path discovery, cycle handling, and major scoring behaviors.

## Trust boundaries

The lab does not authenticate to cloud providers or execute changes. Input is offline JSON. Relationships describe potential trust or privilege paths, not confirmed compromise or exploitability.

## Security design principles

- Fail closed on malformed nodes, invalid scoring ranges, unknown graph references, or duplicate relationships.
- Preserve provider and resource identity rather than collapsing cross-cloud relationships.
- Keep likelihood, control strength, business criticality, and exposure as distinct factors.
- Bound traversal depth to reduce noisy or misleading path expansion.
- Produce rationale with each score so priority decisions remain reviewable.
