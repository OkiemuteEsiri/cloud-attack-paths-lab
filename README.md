# Cloud Attack Paths Lab

A defensive cloud security engineering project for modeling identity, privilege, resource, network, and secret relationships as a directed graph and identifying high-risk paths from exposed entry points to protected cloud assets.

This repository demonstrates how cloud attack-path analysis can support exposure management, IAM review, architecture assurance, purple-team planning, and remediation validation without relying on live cloud credentials or exploit activity.

## Problem statement

Cloud risk is rarely isolated to a single finding. A modestly exposed application can become materially dangerous when it can assume a workload role, chain into a privileged identity, cross a trust boundary, or reach sensitive secrets. Traditional control-by-control audits often miss these compound relationships.

This lab treats those relationships as a graph and answers a more useful defensive question: **which potential paths can connect an entry point to a protected target, and which paths deserve remediation first?**

## What is implemented

- Immutable, validated cloud graph data models
- Provider-aware AWS, Azure, GCP, and shared-identity nodes
- Directed trust/privilege relationship modeling
- Fail-closed graph integrity validation
- Cycle-safe bounded breadth-first path discovery
- Explainable 0–100 contextual path scoring
- P0–P3 remediation prioritization
- Internet-exposure and target-criticality context
- Preventive-control strength and relationship-likelihood factors
- Markdown executive reporting
- CLI execution against offline JSON inventory
- Realistic synthetic multi-cloud dataset
- Eight meaningful unit tests
- Architecture and methodology documentation
- Example executive assessment
- Remediation and revalidation workflow
- Least-privilege GitHub Actions quality checks

## Architecture

```text
Synthetic cloud inventory
        |
        v
Validated Node / Edge models
        |
        v
Graph integrity controls
        |
        v
Bounded path discovery
        |
        v
Contextual scoring engine
        |
        v
P0-P3 prioritized paths
        |
        v
Markdown assessment + remediation workflow
```

See [`docs/architecture.md`](docs/architecture.md) for component and trust-boundary details.

## Risk model

Each path receives an explainable score based on:

- protected-target criticality;
- privileged capability at the destination;
- internet exposure of the entry point;
- modeled likelihood of each relationship;
- preventive-control strength along the path;
- path length.

The model deliberately separates **potential reachability** from **evidence of compromise**. A discovered path means the modeled trust relationships can connect two points; it does not claim that exploitation occurred.

Priority bands:

| Priority | Score | Intended response |
|---|---:|---|
| P0 | 80–100 | Immediate architecture/IAM review and remediation planning |
| P1 | 60–79.9 | High-priority remediation |
| P2 | 40–59.9 | Planned hardening and control validation |
| P3 | <40 | Track, monitor, and reassess as context changes |

## Synthetic scenario

The included dataset demonstrates two intentionally simplified paths:

1. AWS public web tier → application role → production admin role
2. Azure public application → shared CI identity → GCP secret store

All identities, systems, permissions, and relationships are synthetic and created only for this repository.

## Usage

Requires Python 3.11+ and no third-party runtime dependencies.

```bash
python -m src.cli data/synthetic_cloud_graph.json
```

Write the assessment to a file:

```bash
python -m src.cli data/synthetic_cloud_graph.json --report reports/generated-assessment.md
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## MITRE ATT&CK context

| Technique | Defensive relevance |
|---|---|
| T1078.004 – Valid Accounts: Cloud Accounts | Cloud identity and role trust can expand impact when an account is compromised. |
| T1098 – Account Manipulation | Excessive privilege relationships can increase persistence opportunity. |
| T1552.001 – Unsecured Credentials: Credentials In Files | Secret reachability should be evaluated where workloads can access sensitive stores. |
| T1190 – Exploit Public-Facing Application | Public workloads can be modeled as defensive entry-point assumptions. |

ATT&CK mappings provide threat-model context only and are not assertions that any adversary behavior occurred.

## Remediation workflow

1. Confirm the modeled relationship is valid and still required.
2. Identify the narrowest control change that breaks or materially weakens the path.
3. Apply least privilege, stronger workload identity, scoped federation, network restriction, MFA/conditional access where applicable, or secret-boundary controls.
4. Refresh the graph inventory.
5. Re-run path discovery.
6. Retain before/after path evidence and reviewer approval before closure.

See [`docs/methodology.md`](docs/methodology.md) for the full assessment and revalidation method.

## Project structure

```text
.github/workflows/security-quality.yml
src/models.py
src/graph.py
src/scoring.py
src/cli.py
data/synthetic_cloud_graph.json
tests/test_attack_paths.py
docs/architecture.md
docs/methodology.md
reports/example-assessment.md
README.md
```

## Skills demonstrated

- Cloud security architecture
- Identity and access management analysis
- Attack-path / graph reasoning
- Exposure management
- Risk-based prioritization
- Multi-cloud security engineering
- Defensive threat modeling
- Python engineering
- Test design
- Security reporting
- Remediation validation
- CI/CD security hygiene

## Limitations

This is an offline defensive lab, not a cloud discovery or exploitation tool. It does not authenticate to AWS, Azure, or GCP; enumerate real permissions; prove credential compromise; execute privilege escalation; or make cloud changes. Relationship likelihood and control-strength values are analyst inputs and require governance in a production implementation.

## Roadmap

- Add provider-specific inventory adapters for sanitized/exported configuration data
- Add graph-diff reporting for before/after remediation validation
- Add control-owner and remediation-SLA metadata
- Add optional NetworkX adapter while retaining dependency-free core logic
- Add path-choke-point analysis for identifying remediation actions that break multiple paths
- Add machine-readable JSON/SARIF output

## Safety and ethics

This repository is intentionally defensive. It contains no real credentials, client data, production targeting, exploit payloads, persistence mechanisms, credential theft logic, or destructive automation. Use attack-path analysis only with data and environments you are authorized to assess.
