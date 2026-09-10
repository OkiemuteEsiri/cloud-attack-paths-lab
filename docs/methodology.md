# Assessment Methodology

## Scope

This lab demonstrates defensive analysis of synthetic cloud trust relationships. It is designed for exposure management, IAM review, architecture assurance, and purple-team planning—not exploitation.

## Workflow

1. Define authorized entry points and protected targets.
2. Normalize identities, roles, resources, network boundaries, secrets, and controls into graph nodes.
3. Model only evidenced trust relationships as directed edges.
4. Validate that every edge references known nodes and that duplicate relationships are rejected.
5. Discover bounded paths from entry points to protected targets.
6. Prioritize paths using explainable business and security context.
7. Review the highest-priority path for the weakest relationship or control boundary.
8. Remediate the smallest set of relationships that materially reduces path reachability.
9. Re-run the same dataset or refreshed inventory to verify that the path is removed or its score has materially declined.

## Risk model

The score is intentionally contextual rather than a claim of exploitability. Factors include:

- destination business criticality;
- privileged capability at the destination;
- internet exposure of the starting node;
- likelihood assigned to each modeled relationship;
- preventive-control strength along the path;
- path length, with longer paths slightly discounted.

Priorities are P0 (80–100), P1 (60–79.9), P2 (40–59.9), and P3 (<40).

## MITRE ATT&CK context

Relevant defensive mappings depend on the modeled relationship:

- **T1078.004 – Valid Accounts: Cloud Accounts**: identity or role trust may enable unauthorized cloud access if credentials are compromised.
- **T1098 – Account Manipulation**: excessive or weakly governed privilege relationships can increase persistence opportunity.
- **T1552.001 – Unsecured Credentials: Credentials In Files**: secret-access paths warrant review where workloads can reach sensitive stores.
- **T1190 – Exploit Public-Facing Application**: internet-exposed workloads can serve as defensive entry-point assumptions for attack-path analysis.

These mappings provide threat-model context only; a path is not evidence that any technique occurred.

## Remediation and validation

Preferred treatments are least privilege, removal of unused role chaining, stronger workload identity, reduced cross-cloud trust, network restriction, conditional access, MFA where applicable, short-lived credentials, protected secret boundaries, and improved monitoring.

A finding should be closed only after the underlying relationship is changed and the assessment is re-run. Validation evidence should capture the changed control, the new graph/path result, reviewer, and date.
