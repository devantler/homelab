# Privileged RBAC audit

The `audit-privileged-rbac` Kyverno ClusterPolicy reports Role and ClusterRole
rules that grant wildcard administration, RBAC `bind`/`escalate`, or identity
impersonation. Wildcard verbs, resources and API groups are evaluated as effective
permissions, so renaming a chart's administrative role does not hide it.

The policy runs in **Audit** mode. It reports privileged grants while controllers
continue reconciling. `policies.kyverno.io/scored: "false"` records these staged
findings as warnings in PolicyReports. It has no chart-name, namespace-label or resource-name
exceptions. A `resourceNames` restriction is retained for review, rather than
treated as proof that a powerful grant is safe.

Impersonation is checked against its actual Kubernetes resources: users, groups
and service accounts in the core API group, plus UIDs and user-extra subresources
in `authentication.k8s.io`. These differ from the `roles` and `clusterroles`
resources governing `bind` and `escalate`. Ordinary reads, non-resource health
checks, and empty or not-yet-populated aggregated roles do not trigger findings.
See [Kubernetes impersonation](https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/)
and [RBAC privilege escalation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping).

The reports controller receives only `get`, `list` and `watch` on Roles and
ClusterRoles. That grant is applied in the controllers layer before the policy's
infrastructure layer. It grants no binding, escalation, impersonation or resource
mutation. Existing Kyverno resource filters still govern background scanning.

The local regression suite checks ordinary and privileged grants with the same
Kyverno version used in CI and production. A separate application check requires
the exact fixture census, so a policy that stops matching cannot pass merely by
skipping every test.

Promotion to **Enforce** remains tracked in #3486. It requires a fresh complete
holder inventory, exact owner-reviewed exceptions, regression fixtures for those
exceptions, and evidence that existing-resource reports are complete. Existing
Kubescape scanner exceptions are not admission exceptions. Production role and
binding inventories remain private operator evidence.
