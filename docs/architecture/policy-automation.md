# Team policy automation

Scope: [ADR-059](../decisions/059-unattended-policy-authority.md) and the
[normative contract](../../specs/policy-automation.md) for C-01, C-02, C-03,
C-09, C-10, C-20 and C-24; REQ-PER-007 and TASK-07. C-01 accepts
administrator configuration, C-03 evaluates delegation and grants, C-09/C-10
accept and run policies. Mechanisms follow
[ADR-330](../decisions/330-event-driven-system-design.md) D1, D5, D6, D7 and
D10.

## Authority

An automation-bearing AccessBinding in the hub namespace carries the typed
`spec.automation` envelope (allowed actions, counts, bytes, sponsoring and
maintainer groups). Only Asservat administrators can write it, because the
hub namespace is administrator-only (ADR-328); application-namespace
bindings cannot carry it ([permission-observation.md](permission-observation.md)).
The structural CRD validates its shape with reviewed CEL rules.

`authorization.PolicyPrincipal` is the installation-local identity a policy
runs as. `AcceptedPolicyAuthority`, `AutomationProjection` and `PolicyUse`
are distinct types from bearer identity, evidence-read authorization and
local permits. `ValidatePolicyAcceptance` requires the activating human's
current entitlement and membership; `EvaluatePolicy` evaluates later team
authority without a human token. The evaluator pins the accepted policy and
digest, installation and workload, supports only arm, renew, incident and
recordingSave purposes, intersects the original expiry with current source
and deny state, and checks the action, count and byte envelope. A personal
deny of the former creator does not revoke team authority; a sponsor or
executor deny does. It never issues a disclosure identity or approval, and
failure never falls back to controller privileges.

## Policy source

The hub-worker runs a DebugPolicy informer (LIST once, then WATCH; relist only
after a watch restart or `410 Gone`). Each policy is validated against the
embedded canonical schemas; status is never authority. The informer cache
stays valid until a watch event replaces it; deletion leaves a UID tombstone
so a same-name replacement is a new policy. Accepted policies stay valid
until replaced or deleted, not until a timer expires. The controller writes
`status.observedGeneration` and conditions (`Accepted`, `Active`) for the
generation it processed.

The collection-intent digest covers the spec minus the control fields listed
in REQ-EXE-001 (an omitted recording-save opt-in is false). Pause, resume and
other control edits keep the accepted scope, expiry and limits. A new
generation that changes the collection-intent digest suspends the policy
until it is activated again. The execution digest that lets approvals
survive label or sharing edits stays.

## Activation and deactivation

`activate_policy` (MCP and browser) is an authenticated request. It compiles
the policy, checks the current human, the exact delegation and the original
deadlines, and in one SQL transaction records the immutable acceptance, the
active acceptance ID and an audit row ([operation-audit.md](operation-audit.md)).
The request's idempotency key is stored with the acceptance: a retry with the
same key returns the original acceptance and never reactivates a replaced or
deactivated one. Replacing a scope names the prior acceptance; a stale
concurrent replacement fails. The original creator is recorded on first
acceptance and each later submitter separately, for independent-review
checks. The stored record holds identifiers, revisions, digests, ceilings and
sponsoring groups; no tokens, membership lists or recipe text.

`deactivate_policy` (team-maintainer authority) clears the active acceptance
under the row lock and writes an audit row. The console page `/policies`
lists, activates and deactivates policies through the same operations.

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
| log | One `pods/log?follow=true&sinceTime=` stream per armed container (≤ 32 containers per policy, records ≤ 4 MiB per window) |
| resource | `metrics.k8s.io` PodMetrics sampled at the policy's configured interval (no watch exists) |

A region without a configured Alertmanager receiver reports `unsupported`,
so activation refuses alert policies there. Each delta carries the Pod, the
detector level and its time; a Pod whose state is unknown keeps its
watermark, and an overlong log record is counted under the suppression
reason `overlong`. The hub evaluates level and re-arm against the per-detector
watermark in the trigger ledger and reuses the S-02 investigation with the
policy executor; eligibility and the SQL checks after locks evaluate the
executor through its current acceptance and team delegation. Each occurrence
key is the idempotency key of the capture it starts.

Recorder policies (finite onTrigger and before-zero network headers) compile
the same accepted composition as activation. The exact recorder scope must
match the accepted authority before an occurrence is spent; the trigger
previews the triggering Pod and submits through the normal capture-intent
pipeline. Atomic admission matches the actual plan action before reserving
output or grant spend; a snapshot-only grant cannot authorize a recorder.
Raw predicates stay refused until the live-observation authority and node
boundary qualify.

## Recurring sharing

A DebugPolicy may declare bounded `spec.sharing`
([ADR-239](../decisions/239-recurring-policy-sharing.md)). Activation needs the
activating human's `evidence:share` and an evidence-owner group of the
automation AccessBinding as sponsor; those groups become the share managers,
recorded as stable group IDs. The acceptance record carries the
instruction. The policy principal has no sharing right of its own: each
capture consumes one slot of the reviewed instruction. `sharing` is outside
the collection-intent digest, so editing it stops sharing without
interrupting collection.

## Policy CRD

The DebugPolicy CRD declares exactly one `recipeRef` or `profileComposition`,
synchronized by `scripts/policy-crd.py` for the component, profile and
override shapes and the UUID `grantRef`. `override.value` keeps its JSON type
because a structural property cannot express that union; the canonical
schema validates it before compilation. Existing installations apply CRD
changes separately from `helm upgrade`.

## Boundaries

Public OIDC verification never trusts the policy principal. Resolved
DebugPolicy scopes and policy grants carry the team authority record;
DebugCapture does not. Configuration previews explain execution identity,
owner groups, continuation, state, expiry and limits; these explanations are
not credentials, and discovery still requires the viewer's current rights.
