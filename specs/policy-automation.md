# Team policy automation

Accepted [ADR-059](../docs/decisions/059-unattended-policy-authority.md) separates the current rights of people from recurring team execution; [ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md) (a) keeps the automation envelope under namespace RBAC. Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md) and [ADR-335](../docs/decisions/335-usable-by-default.md) D5/D6/D8/D14. The [research](../docs/research/background-identity.md) records alternatives.

## Authoring and the automation envelope

A DebugPolicy lives in the application namespace of its target workload, in that workload's cluster, and is written with kubectl or GitOps like a PrometheusRule. Namespace RBAC on `debugpolicies.asservat.io` decides who may author one; the chart aggregates that write access into `edit` and `admin`.

`AccessBinding.spec.automation` is the team's ceiling for its policies. It is allowed only on an Allow binding whose subjects are groups and whose roles include `workload-maintainer`, and uses the binding's namespace, workload scope and optional `notAfter`. Writing it needs `bind` on `automation` ([REQ-PER-001](permissions.md#req-per-001--canonical-permission-configuration)). The [typed envelope](contracts/policy-authority.schema.json) names the allowed action kinds and an optional `maxLifetimeSeconds` ceiling for policy grants of intrusive kinds (dumps, commands, raw or argument observation). Non-intrusive kinds and always-on recorders are bounded by rates, ring sizes and the workload's [capacity](capacity.md) share, not by lifetimes or run counts. Several policies never multiply a workload's allowance. See [an automation binding](../examples/access-binding-automation.yaml).

A policy uses the single matching envelope in its namespace, or names one with `spec.automationRef` when several exist; with none it is `Accepted=False` (`DelegationRequired`). Human-only exec inheritance is not an envelope.

## Identity and acceptance

The author is attributed by Kubernetes audit. The policy executes as an installation-local principal: `issuer=urn:asservat:installation:<installation UUID>`, `subject=policy:<policy UID>`, `clientID=policy-executor`, `identityType=workload`. Public endpoints never accept this issuer; the strings are not credentials. The collector authenticates dispatch separately ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D3).

The hub accepts each observed generation that compiles and fits its envelope, with no activation call. The acceptance records the binding, generation and the sponsoring groups (by name) that hold `workload-maintainer` through that binding, and writes `collection-scope/v1.policyAuthority` ([execution](execution.md#req-exe-001--separate-immutable-scopes)). Recipes and workloads are named; the hub records digests and UIDs. Nothing written to CRD status is trusted. A changed execution scope is accepted again and, for intrusive actions, reviewed again; unchanged re-applies, retries and restarts change nothing. The number of policies is limited only by Kubernetes.

`get_policy_status` and the policy status (`observedGeneration`; conditions `Accepted`, `ApprovalRequired`, `Active`) explain the policy without evidence content. A policy without intrusive actions is `Active` once accepted.

## Execution, deactivation and revocation

Connectors watch DebugPolicies and push changes. Each source start (arming a recorder, a trigger dispatch, a save) is admitted once under one permission snapshot ([REQ-PER-006](permissions.md#req-per-006--freshness-composition-and-explainability)): accepted scope, current envelope, every sponsoring group's current allow, denies, grants and budgets. It runs to its applicable hard ends (grant expiry, envelope `notAfter`, local ceiling). The scheduler follows Pod events to cover all authorized replicas.

Suspension (`spec.suspend`), deletion or a new generation stops new admissions for the old acceptance; reverting YAML never revives an old acceptance. `deactivate_policy` ([ADR-229](../docs/decisions/229-policy-deactivation-and-console.md)) stops an accepted generation at once for a current `workload-maintainer` of a sponsoring group; it is idempotent, audited and refunds nothing. Envelope removal, a sponsoring group losing its allow, a deny of the executor or a sponsor, deactivation and deletion push a stop to running sources; a disconnected source runs to its admitted hard end.

The author's logout, departure or disabled account does not revoke team authority; an unrelated personal deny does not either. Deleting an IdP group alone is not a revocation: operators remove the envelope.

## Approval of automatic intrusive actions

Automatic intrusive actions need a policy grant (maintainer decision). When a generation with intrusive actions is accepted, the hub opens its review and the policy reports `ApprovalRequired` with the link. Any current `action-approver` for the target decides it ([REQ-AUT-003](authorization.md#req-aut-003--individual-and-policy-grants)); approval attaches the grant to the policy and the policy becomes `Active`. There is no grant ID to copy.

The grant lasts `approvals.policyGrants.defaultAgeSeconds` (default 90 days), at most the administrator maximum and the envelope's `maxLifetimeSeconds` (ADR-335 D6). The policy reports `RenewalDue` from `renewalNoticeSeconds` before expiry; an approver renews in place, keeping grant, counters and policy link with a new expiry. Login, re-apply, restart and retry never renew it. An expired grant stops intrusive admissions while non-intrusive actions continue. A new generation with an unchanged execution digest keeps the grant; a changed digest opens a new review.

A policy grant records the policy, approver, `policyExecutor` and `policyAuthority`. Members of a sponsoring group and current approvers may inspect it (`get_grant`); this confers no decision or evidence access.

## Evidence

The policy principal has no download, raw-query, live-view or sharing rights, and neither author nor executor joins the evidence audience. Viewers and recording-save initiators are authorized as themselves. Team sharing follows REQ-SHR-005 and REQ-SHR-008. Sensitive observation follows [REQ-AUT-006](authorization.md#req-aut-006--sensitive-observation-sessions).

SC-PER-007 and SC-EXE-001 cover: the author leaves but the team policy stays eligible; envelope removal, sponsor loss, grant expiry and denies stop running intrusive sources; repeated applies cannot reset spend; namespace writers without `bind` on `automation` cannot change an envelope; a policy without intrusive actions runs on apply; an intrusive policy runs once approved and keeps running after renewal.
