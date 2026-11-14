# Team policy automation

Scope: [ADR-059](../decisions/059-unattended-policy-authority.md) and the
[normative contract](../../specs/policy-automation.md) for C-01, C-02, C-03,
C-09, C-10, C-20 and C-24; REQ-PER-007 and TASK-07. C-01 accepts
administrator configuration, C-03 evaluates delegation and grants, C-09/C-10
accept and run policies. Mechanisms follow
[ADR-330](../decisions/330-event-driven-system-design.md) D1, D5, D6, D7 and
D10 and [ADR-335](../decisions/335-usable-by-default.md) D5, D6, D8 and D14.

## Authority

An automation-bearing AccessBinding in the application namespace it grants
carries the typed `spec.automation` envelope (allowed action kinds and, for
intrusive kinds, the grant period, administrator-configured with a default of
90 days per ADR-335 D6; its subjects are the sponsoring groups), as in
ADR-329. There is no execution count or lifetime byte budget: storms are
bounded by the rate and concurrency limits (ADR-335 D8), the per-incident
cap, the per-workload storage quota and retention. Adding or changing `spec.automation`
requires `bind` on `accessroles.asservat.io` named `automation`, enforced by the
Helm-rendered ValidatingAdmissionPolicy and aggregated into `admin` only when
`permissions.aggregateAutomation` is set
([permission-observation.md](permission-observation.md)).
The structural CRD validates its shape with reviewed CEL rules.

`authorization.PolicyPrincipal` is the installation-local identity a policy
runs as. `AcceptedPolicyAuthority`, `AutomationProjection` and `PolicyUse`
are distinct types from bearer identity, evidence-read authorization and
local permits. `ValidatePolicyAcceptance` checks that a generation fits its
namespace's envelope and that the sponsoring groups hold `workload-maintainer`;
`EvaluatePolicy` evaluates team authority without a human token. The evaluator pins the accepted policy and
digest, installation and workload, supports only arm, incident and
recordingSave purposes, intersects the original expiry with current source
and deny state, and checks the action kind and grant expiry. A personal
deny of the former creator does not revoke team authority; a sponsor or
executor deny does. It never issues a disclosure identity or approval, and
failure never falls back to controller privileges.

## Policy source

DebugPolicies live in application namespaces, next to the workloads they
target. Each cluster's connector (the hub-worker for the hub cluster) runs a
DebugPolicy informer (LIST once, then WATCH; relist only after a watch restart
or `410 Gone`) and pushes changes over its hub connection, as for
AccessBindings. Each policy is validated against the
embedded canonical schemas; status is never authority. The informer cache
stays valid until a watch event replaces it; deletion leaves a UID tombstone
so a same-name replacement is a new policy. Accepted policies stay valid
until replaced or deleted, not until a timer expires; only intrusive actions
depend on a grant's expiry. The number of policies per cluster is not limited
beyond Kubernetes object limits. The connector writes
`status.observedGeneration` and conditions (`Accepted`, `ApprovalRequired`,
`RenewalDue`, `Active`) for the generation the hub processed.

The collection-intent digest covers the spec minus the control fields listed
in REQ-EXE-001 (an omitted recording-save opt-in is false). Pause, resume and
other control edits keep the accepted scope, expiry and limits. A new
generation that changes the collection-intent digest is accepted as a new
scope; when it also changes the execution digest of an intrusive action, it
opens a new review. The execution digest that lets approvals survive label or
sharing edits stays. An unchanged reapply changes nothing.

## Acceptance, grants and deactivation

The hub accepts each pushed generation when it arrives: it compiles the
policy, resolves the envelope and sponsoring groups, and in one SQL
transaction records the acceptance, the active acceptance ID and an audit row
([operation-audit.md](operation-audit.md)). The acceptance is keyed by
(policy UID, generation), so a duplicate delivery or reapply returns the
existing acceptance and never reactivates a replaced or deactivated one. The
stored record holds identifiers, revisions, digests, limits and sponsoring
groups; no tokens, membership lists or recipe text.

When the accepted generation has intrusive actions, the same transaction
opens its `policyCollection` review. `decide_review` approving it creates the
grant and attaches it to the acceptance in one transaction; renewal updates
the same grant's expiry. Approval is decided by any current
`action-approver`; there is no request or attach call and no grant reference
in the policy spec.

`deactivate_policy` (team-maintainer authority) clears the active acceptance
under the row lock and writes an audit row. The console page `/policies`
lists policies with their status, opens reviews and renewals, and
deactivates.

## Triggers

Detectors run on the region's connector and push matching deltas to the hub
over the connector connection ([regional-context-start.md](regional-context-start.md)).
The connector arms a detector when a policy becomes active and disarms it on
deactivation, both delivered as events.

| Detector | Event source |
| --- | --- |
| exit / restart | Pod informer (container restart count and last termination) |
| probe | Event informer, field-selected to probe failures of the policy's Pods |
| alert | Alertmanager `webhook_config` receiver on the connector, matched against the policy's label matchers |
| log | One `pods/log?follow=true&sinceTime=` stream per armed container of every Pod within the administrator's replica ceiling; the connector's concurrent streams and per-stream window buffer are derived from its memory request (memory request ÷ per-stream buffer) |
| resource | `metrics.k8s.io` PodMetrics sampled at the policy's configured interval (no watch exists) |

A region without a configured Alertmanager receiver reports `unsupported`,
so activation refuses alert policies there. Each delta carries the Pod, the
detector level and its time; a Pod whose state is unknown keeps its
previous detector state, and a log record larger than the per-stream window
buffer is counted under the suppression reason `overlong`. The hub evaluates level and re-arm against the per-detector
state in the trigger ledger and reuses the S-02 investigation with the
policy executor; eligibility and the SQL checks after locks evaluate the
executor through its current acceptance and team delegation. Triggers are
events, so the number of armed policies adds no polling. Each occurrence
key is the idempotency key of the capture it starts.

Recorder policies (finite onTrigger and before-zero network headers) compile
the same accepted composition as activation. The exact recorder scope must
match the accepted authority before an occurrence is spent; the trigger
previews the triggering Pod and submits through the normal capture request
pipeline. Atomic admission matches the actual plan action before reserving
output; a snapshot-only grant cannot authorize a recorder.
Raw predicates stay refused until the live-observation authority and node
boundary qualify.

## Recurring sharing

A DebugPolicy may declare bounded `spec.sharing`
([ADR-239](../decisions/239-recurring-policy-sharing.md)). It takes effect
with the acceptance when a sponsoring group of the automation AccessBinding
holds sharing authority (`evidence-owner` or `workload-maintainer`); those
groups become the share managers, recorded by name, and the policy is the
recorded creator. The acceptance record carries the
instruction. The policy principal has no sharing right of its own: each
capture consumes one slot of the reviewed instruction (the maintainer's
"explicitly bounded recurring-policy sharing"); slots carry no time cap and
need no renewal (ADR-335 D7). `sharing` is outside
the collection-intent digest, so editing it stops sharing without
interrupting collection.

## Policy CRD

The namespaced DebugPolicy CRD declares exactly one `recipeRef` (a recipe
name; the hub records its digest) or `profileComposition`, and names its
target workload by kind and name in its own namespace; it has no grant
reference. `scripts/policy-crd.py` synchronizes the component, profile and
override shapes. `override.value` keeps its JSON type because a structural
property cannot express that union; the canonical schema validates it before
compilation.

## Boundaries

Public OIDC verification never trusts the policy principal. Resolved
DebugPolicy scopes and policy grants carry the team authority record;
DebugCapture does not. Configuration previews explain execution identity,
owner groups, continuation, state, expiry and limits; these explanations are
not credentials, and discovery still requires the viewer's current rights.
