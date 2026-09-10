# Example Cloud Attack Path Assessment

> Synthetic data only. This report demonstrates output style and does not describe a real environment.

## Executive summary

The synthetic graph contains two material paths from public application tiers to privileged or sensitive cloud targets. Both paths are driven by identity trust relationships rather than a single software vulnerability. The highest-value remediation is to reduce role chaining and cross-cloud privilege, then re-run the graph to verify path removal.

## Priority observations

| Priority | Scenario | Defensive interpretation |
|---|---|---|
| P0 | AWS public web tier → application role → production admin role | Internet exposure combined with weak role-chaining controls creates a short route to privileged capability. |
| P0 | Azure public application → shared CI identity → GCP secret store | Cross-cloud workload trust allows an exposed application tier to reach a privileged shared identity and sensitive secret boundary. |

## Recommended actions

1. Remove unused AWS role-chaining permissions and introduce explicit conditions around workload identity.
2. Scope the shared CI identity to minimum required resources and replace broad cross-cloud trust with narrowly bounded federation.
3. Restrict protected secret access to approved workload identities and network contexts.
4. Add monitoring for privilege-assumption changes, cross-cloud trust changes, and sensitive secret access.
5. Re-run the analyzer after remediation and retain the before/after path evidence.

## Validation criteria

A remediation is considered validated when the affected protected target is no longer reachable from the original entry point under the modeled relationship set, or when the remaining path is demonstrably constrained by stronger controls and produces a materially lower risk score.
