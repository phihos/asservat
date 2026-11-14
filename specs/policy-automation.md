# Team policy automation

Accepted ADR-059 refines REQ-AUT-001/003, REQ-PER-001/006/007/008 and REQ-EXE-001. It separates the current rights of people from recurring execution. The [research](../docs/research/background-identity.md) records the standards and alternatives. Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md) and [ADR-335](../docs/decisions/335-usable-by-default.md) D5/D6/D8/D14.

## Operator configuration and low-effort authoring

A team owns its policies: a DebugPolicy lives in the application namespace of the workload it targets, in that workload's cluster, and is written with kubectl or GitOps like a PrometheusRule. Whoever namespace RBAC lets write `debugpolicies.asservat.io` there may author one; the chart aggregates that write access into the namespace `edit` and `admin` ClusterRoles.

`AccessBinding.spec.automation` is the team's reusable ceiling for those policies. It is allowed only on an Allow binding whose subjects are groups and whose roles include `workload-maintainer`, and uses the binding's own namespace, workload scope and optional `notAfter`. Creating or changing it requires `bind` on `accessroles.asservat.io` named `automation` in that namespace ([ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md)): the administrator binds the chart's `asservat-bind-automation` ClusterRole, or sets `permissions.aggregateAutomation` so namespace `admin` holds it.

The [typed envelope](contracts/policy-authority.schema.json) names the allowed action kinds; everything else is optional. Intrusive action kinds (dumps, commands, raw or argument observation) additionally take `maxGrantSeconds` (default: the administrator's policy-grant period, ADR-335 D6); they are bounded by that expiring grant and the rate and concurrency limits of ADR-335 D8, not by a run count. Non-intrusive kinds and always-on recorders have no lifetime, run count or lifetime byte total: they are bounded by rates, ring sizes and the workload's capacity share ([capacity](capacity.md)). Node/workload limits, observation rates, storage and grant rules still apply; several policies cannot multiply a workload's aggregate allowance. Action kinds are restricted to the expanded recipe's exact kinds and never waive intrusive review or local safety rules.

See [an automation binding](../examples/access-binding-automation.yaml). An operator normally configures one envelope per team namespace. A policy whose namespace has exactly one matching envelope uses it; several require `spec.automationRef` naming the binding; none leaves the policy `Accepted=False` with reason `DelegationRequired` and the binding to add. Human-only exec inheritance is not an envelope: a maintainer cannot name a powerful service account.

## Identity and acceptance

The policy's author, the policy execution principal and the authenticated collector are distinct. The first is attributed by Kubernetes audit, the second identifies the bounded policy, the third authenticates dispatch ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D3). The policy principal is `issuer=urn:asservat:installation:<installation UUID>`, `subject=policy:<policy UID>`, `clientID=policy-executor`, `identityType=workload`. This issuer is internal and never accepted by public endpoints; the strings are not credentials.

The hub accepts each observed generation that compiles and fits its envelope, with no activation call ([REQ-PER-007](permissions.md#req-per-007--submission-and-policy-execution-identity)). The acceptance records the binding and generation and the sponsoring groups (by name) that hold `workload-maintainer` through that binding. Sponsors are execution authority, distinct from evidence-owner management; they never come from review sources or catalog ownership. The collection scope records installation, policy, namespace, target workload (by name, with the UID matched as provenance), action kinds, acceptance time and the limits that apply. No caller supplies an executor, digest or sponsor by writing CRD status.

`collection-scope/v1.policyAuthority` is required for a DebugPolicy scope and forbidden for DebugCapture. Ongoing sources, trigger incidents and existing-recording saves use the same policy identity. Authored policies contain configuration intent; resolution belongs to acceptance. No user-computed digest or ID is needed: recipes and workloads are named, and the hub records their digests and UIDs.

Changing executor, sponsors, envelope or limits changes the execution scope and is accepted again; for intrusive actions a changed execution digest needs review again. Reapplied unchanged YAML, retries and restarts change nothing and cannot reset counters or extend authority. The number of policies is not limited beyond Kubernetes object limits (ADR-335 D8).

## Status and deactivation

`get_policy_status` and the policy's status (`observedGeneration`; conditions `Accepted`, `ApprovalRequired`, `Active`) explain the policy without content. A policy without intrusive actions is `Active` as soon as it is accepted.

`deactivate_policy` ([ADR-229](../docs/decisions/229-policy-deactivation-and-console.md)) stops an accepted generation at once, for example during an incident. It requires a current, undenied `workload-maintainer` allow of a sponsoring group; Kubernetes writers stop policies with `spec.suspend` or deletion. Deactivation clears the acceptance and signals the scheduler in the same transaction (`NOTIFY`); the hub pushes a stop to the policy's running sources and refuses later admissions. It refunds no spend, deletes no evidence, is idempotent and writes an audit row. A new generation is accepted again.

## Continued execution and revocation

The connector of each cluster watches DebugPolicies with an informer and pushes changes over its hub connection, as for AccessBindings. Suspension, deletion or a new generation is an event that stops new admissions for the old acceptance at once; pause/resume is a control field that never resets authority, and reverting YAML cannot revive an earlier acceptance.

Each source start (arming an ongoing recorder, a trigger dispatch, a save) is admitted once, under one permission snapshot ([REQ-PER-006](permissions.md#req-per-006--freshness-composition-and-explainability)): the accepted scope, the current envelope, every sponsoring group's current allow for that target, denies, grants and budgets. The admission is bounded by every applicable hard end (grant expiry, envelope `notAfter`, local ceiling) and the started source runs to it, as a started download does ([ADR-312](../docs/decisions/312-started-downloads-run-to-original-bounds.md)). The scheduler maintains all authorized replicas within source ceilings by reacting to Pod events, not by a timer. Revocation reaches running sources as a pushed stop: envelope removal, a sponsoring group losing its allow, a deny of the executor or a sponsoring group, deactivation and policy deletion. A source whose connector has no hub connection runs to its admitted hard end; a pending stop is delivered on reconnect. An unrelated personal deny does not revoke team execution. Additional evidence-owner managers lend no execution authority.

The author's logout, token expiry, departure or a disabled account does not revoke team-policy authority. Deleting an IdP group alone is not a local revocation; operators remove its envelope through Kubernetes. Irreversible effects already performed cannot be undone.

## Approval of automatic intrusive actions

Automatic intrusive actions need a policy grant. When a generation with intrusive actions is accepted, the hub opens its review (reason `policyCollection`) and the policy reports `ApprovalRequired` with the review link in status, console and MCP. Any current `action-approver` for the target decides it; step-up applies only when configured ([REQ-AUT-003](authorization.md#req-aut-003--individual-and-policy-grants)); automation identities cannot review. Approval attaches the grant to the policy in the same transaction, and the policy becomes `Active`; there is no separate request or attach step and no grant ID to copy.

The grant lasts the administrator's policy-grant period (default 90 days, at most the envelope's `maxGrantSeconds`; ADR-335 D6). The policy reports `RenewalDue` from the earlier of 14 days or 15 % of the grant period before expiry, so a short period is not due for its whole life; an approver renews in place, which keeps the grant, its counters and its policy link and sets a new expiry. An expired grant stops intrusive admissions while non-intrusive actions of the same policy continue. A new generation with an unchanged execution digest keeps the grant; a changed digest opens a new review, and the old grant ends with the old acceptance.

A policy AccessGrant records the policy and approver and separately binds `policyExecutor` and `policyAuthority`. Effective scope and lifetime are the intersection of envelope and review. Personal manual collection plus result access cannot be transferred to recurring automation.

Policy-grant metadata needs current authorization: `get_grant` and the grant list require current whole-workload collection rights on the approved workload. Current approvers keep review access. A current member of a sponsoring group may inspect the policy configuration, original and effective dates and grant reservations, so team management survives an author's departure; this grants no decision authority, evidence access or personal continuation. `can_revoke` reflects current reviewer or sponsor eligibility.

## Evidence and reuse

The policy principal supplies no human download, raw-query, live-view or sharing rights. Evidence keeps its recorded audience and source deadlines; neither author nor executor is added to it. Viewers and recording-save initiators are authorized separately from the source's policy. Team-managed sharing follows REQ-SHR-005 and REQ-SHR-008.

## User-facing explanation and acceptance cases

The console's policy view and review show the team, the grant's expiry and renewal state, limits and continuation after an author's departure. Configuration preview and source discovery share the typed execution-authority summary, which has no authorization value. MCP `list_recordings` (including policy-owned live sources) exposes the same bounded fields as the browser. Manual sources cannot claim team automation. A missing, expired or removed envelope explains the remedy without asking developers for SSO credentials.

SC-PER-007 and SC-EXE-001 include: the author leaves but the team policy stays eligible; the former author cannot read or manage; envelope removal, sponsor loss, grant expiry and scoped denies stop running intrusive sources and refuse new admissions; repeated applies cannot reset spend; user-only exec cannot create an automation principal; namespace writers without `bind` on `automation` cannot add or remove an envelope; source and viewer authorization diverge correctly; every sponsoring group must still hold its allow; a policy without intrusive actions runs on apply; an intrusive policy runs once its review is approved and keeps running after renewal; wrong policy, installation or workload and expiry are negative cases.

Personal offline-user execution and SCIM/CAEP integrations remain optional future modes. Browser session refresh is for interactive human access, never a credential kept for recurring jobs.

`get_policy_status` reports the accepted policy's grant expiry and renewal state and the rate and ring limits that apply; a policy has no lifetime execution or byte pool (ADR-335 D6). Status confers no acquisition, evidence or personal continuation rights.

Finite onTrigger/before-zero network-header recording uses the triggering Pod and the admitted occurrence key through the recorder preview/request pipeline. Preview eligibility is not admission: admission matches the actual action to the accepted authority and charges the grant and policy budgets. The policy principal never opens a personal review. Recording settings use the accepted issuer namespace; missing or changed settings refuse new work. Sensitive observation is admitted and settled under [REQ-AUT-006](authorization.md#req-aut-006--sensitive-observation-sessions).
