# Team automation authority components

Accepted [ADR-059](../decisions/059-unattended-policy-authority.md) and [normative contract](../../specs/policy-automation.md) refine C-01/C-02/C-03/C-09/C-10/C-20/C-24, TASK-07 and REQ-PER-007. C-01 owns administrator configuration acceptance; C-03 owns delegation eligibility and grants; C-09/C-10 own accepted execution and activation. No new service, database, public permission API or directory credential is introduced.

## Implemented boundary

AccessBinding has an optional typed automation envelope in the canonical schema, Go wire/domain values and bounded Kubernetes reader. The journal deep-copies it; canonical configuration digests include it. The generated structural CRD uses an explicitly reviewed CEL equivalent for Allow/group/maintainer restrictions. Native permission admission restricts automation-bearing bindings to installation permission administrators, checking both old and new objects. An existing ordinary delegated writer cannot add the field, widen it, strip it or delete its containing binding.

`authorization.PolicyPrincipal` derives the installation-local workload identity. `AcceptedPolicyAuthority`, `AutomationProjection` and `PolicyUse` have distinct types from bearer identity, evidence-read authorization and local permits. `ValidatePolicyAcceptance` requires current authenticated author entitlement/membership; `EvaluatePolicy` evaluates subsequent team authority without a human token or identity refresh. `AutomationEvaluator` reads accepted policy and current delegation through purpose-specific ports and rechecks original clocks after blocking reads. Failure never resolves to controller privileges.

The pure evaluator pins an exact accepted policy/digest, installation and workload, supports only arm/renew/incident/recordingSave purposes, intersects original expiry and current source/deny/owner deadlines, and checks action/count/byte envelopes. A personal deny of the former creator does not revoke team authority; a sponsor or executor deny does. It cannot issue a disclosure identity or approval. Its limit checks are ceilings, not durable spending.

## Durable source, acceptance and current readers

The initial `PolicySourceClient` now reads a concrete DebugPolicy over the bounded Kubernetes client, pinning installation/cluster, namespace UID and resource name/UID. It requires an explicit named read permission, validates the complete spec against 15 embedded canonical schemas and ignores status as authority. Reads expire within five seconds of the original observation and preserve microsecond timestamps for SQL. The separate numeric parser allows finite fractional resource thresholds without weakening integer-only permission configuration. The source collection-intent digest excludes only the control fields in REQ-EXE-001 and resolves omitted recording-save opt-in to false; it is not a resolved execution digest. `PolicySourceObserver` writes current observations through the existing separately credentialed SQL source facet. Failure never refreshes the previous lease. A deleting object supplies a permanent UID tombstone; a vanished/replaced UID fails closed even when a deletion event was missed. Broad discovery/watch supervision and the signature/compiler acceptance chain remain unfinished.

Migration 00019 retains the administrator automation envelope in each accepted permission basis and in the immutable encrypted permission audit. `AutomationAuthorities` checks the current binding UID/generation/digest, workload scope, complete deny projection and exact acknowledged envelope snapshot. Ordinary assignments keep their historical basis digest across continuous harmless binding edits; automation pins the current delegation revision separately. Merely possessing an older assignment activation audit cannot authorize a newly edited envelope.

C-09's `PolicySourceWriter` and `PolicyAcceptor` ports have SQL adapters. Separate credentials observe policy sources, accept scopes, acknowledge encrypted audit and read accepted authority. Source observation cannot accept a scope; acceptance cannot acknowledge itself or refresh its own source. A private installation/root association prevents caller-selected cross-installation reads. The original creator is pinned on first acceptance, while each later authenticated submitter is preserved separately for independent-review checks.

A complete source observation lasts at most five seconds. It contains the full resource revision and a separate normalized collection-intent digest. Suspension is explicit. Harmless control edits and pause/resume retain the accepted scope, expiry and limits; collection-intent changes advance an internal monotonic version, including A → B → A. A jumped resource generation also advances that version: a relist cannot prove that an intermediate collection change never happened. Source deletion is a permanent UID tombstone. Out-of-order observations, changed immutable identity and ambiguous same-generation source changes fail closed. The producer must canonicalize only the exclusions permitted by `specs/execution.md` and must not refresh a stale cache or conceal a watch gap. Its production Kubernetes watch/signature/compiler composition is still pending.

Acceptance takes locks in fleet-trust → permission-root → policy-source order. It checks the current authenticated human, signed-submission facts, source, exact delegation and original deadlines after blocking work, then atomically records the immutable acceptance, consumed nonce and active acceptance ID. The submission explicitly pins the prior acceptance when replacing a scope; stale parallel replacements fail. Exact nonce retries return the original receipt, including its original expiry, and never reactivate it. A new nonce cannot recreate an already accepted scope. The receipt is provenance, not current eligibility. The signature verifier and compiler are mandatory independent upstream ports: a caller cannot make its own DTO trusted by constructing this value.

Acceptance audit uses the existing encrypted immutable object format with a distinct `policy-acceptance/v1` purpose and exact read-back authentication. Acknowledgement can finish after revocation/expiry, but cannot restore source freshness or extend authority. The SQL record is content-minimized: identifiers, revisions, scope/submission digests, ceilings and sponsoring assignments; no token, personal membership list, signature bytes or recipe text. Nonces and tombstones are currently retained; bounded metadata retirement and SQL backup retention remain later qualification work.

The accepted-policy reader requires current source availability, matching collection-intent version, an acknowledged exact acceptance, original expiry and current recovery trust/issuer epoch. It returns the original source deadline separately from long-lived policy authority. `AutomationEvaluator` rechecks and intersects that deadline after reading the current delegation, preventing a slow read from renewing a nearly expired observation. All these results remain preflight, not execution permits or evidence access.

## Restart-trigger composition (ADR-228)

[ADR-228](../decisions/228-restart-triggered-policy-captures.md) composes these components in
hub-api for the first trigger: `HubPolicySources` reads hub-held DebugPolicies, `PolicyActivation`
(MCP/browser `activate_policy`) accepts the compiled restart subset in-process and publishes the
acceptance audit, and `PolicyTrigger` polls each active policy every 15 seconds through the
`observe-workload-restarts` regional query and the migration 00082 trigger ledger
(`PolicyTriggers`). Captures reuse the S-02 investigation with the policy executor; the shared
eligibility port and every SQL re-check after locks evaluate the executor through its current
acceptance and team delegation. Policy acceptance, source observation, audit acknowledgement and the
trigger ledger share the ordinary hub credential's `policy-automation` duty (ADR-222). The
remaining items below still apply to other detectors, intrusive actions and grants.

[ADR-229](../decisions/229-policy-deactivation-and-console.md) adds `PolicyDeactivation`
(MCP/browser `deactivate_policy`, team-maintainer authority, `PolicyTriggers.DeactivatePolicy`
clears `policy_source.active_id` under the row lock), the console page `/policies` over the three
generic policy operations, and runs each tick's captures on one goroutine per policy that
`PolicyTrigger.Run` joins.

## Runtime composition still required

C-09 still must supply authenticated ingress, the complete canonical policy compiler and protected supervision of the Kubernetes source journal. The [submission signature components](policy-submissions.md) now provide independently verified post-persistence human submissions and a matching short-lived proof inside SQL acceptance; their protected bootstrap and complete ingress/compiler composition remain pending. The current acceptance facet checks a concrete whole-pod target supplied by those private producers; it is not the finished all-replica policy authoring workflow. C-03 must bind the exact grant/independent reviewer; C-10/C-11 must acquire short signed permits through atomic cumulative capacity/grant/retention/recovery checks. Durable accepted limits are ceilings, not a spending implementation. Carry the acceptance/delegation/source revision into final transactions and local permit renewal. Worker certificates and purpose-specific channels authenticate dispatch; policy principal strings alone do not.

Human browser sessions, coordinated standard refresh and back-channel logout now have [implemented and qualified components](browser-sessions.md); protected runtime composition and approval step-up remain. Public OIDC verification must never trust the internal automation issuer. Optional personal offline-token storage, directory polling and SCIM/security-event adapters remain absent. No public route, role binary or privileged collection is enabled by these components.

## Contract and prototype changes

Resolved DebugPolicy scopes and policy grants require the explicit team authority record. DebugCapture excludes it. Canonical fixture digests and dependent recording-save provenance change accordingly. Existing runtime scope migration is forbidden. Default evidence audiences, personal result-access grants and separate SharingIntent management are unchanged.

Configuration previews and shared recording/live-source contracts expose a bounded explanation of execution identity, owner groups, continuation, state, expiry and limits. The synthetic policy editor/review displays team execution and its consequences using existing minimalist components. These projections are not credentials, and discovery still requires the viewer's current rights.

## Verification

The initial reader regression rejects the new bounded field before implementation (`test/results/automation-binding-before.log`). Unit tests cover accepted versus departed authors, continued team eligibility with denied human reads, forged identities/targets, changed assignments, expiry, stale denies, envelope overrun, forbidden disclosure purpose, binding cutoff and deadlines after blocking reads. Real Kubernetes admission/CRD and Helm lifecycle qualification and repository gate results are recorded in [implementation progress](../implementation-progress.md); an unrun fixture is not a pass.

Automation admission passed against the actual API, including the old-object guard that prevents an ordinary delegate from stripping or deleting the envelope. The first full run exposed a retention observation-renewal gap. A follow-up regression reproduced a skipped timer cycle; observation-based scheduling fixes that defect and the strengthened 30-second continuity fixture passes. Failure evidence and bounded timing traces are retained; no freshness limit, rate ceiling or history requirement was relaxed. Helm install/upgrade/rollback/uninstall also passes. The remaining source/signature/session composition and remaining production latency/failure qualifications prevent an end-to-end execution claim; exact commands and results are in the progress record.

The persistence continuation and its actual verification results are recorded in [implementation progress](../implementation-progress.md). Synthetic source/compiler/identity/KMS inputs in SQL/S3 tests do not qualify production ingress or key custody.

The later source-adapter continuation passes unit/race/schema/architecture checks and the real permission fixture (`policy-source-gates.log`, `policy-source-permission-check.log`). Its Kubernetes → SQL test covers named read-only access, pause/resume without scope reset, collection edits, missed generations, deleting-object tombstones and same-name replacement rejection. `policy-source-permission-kubernetes-environment.json` records unchanged sources and complete cleanup. This fixture uses a permissive test-only DebugPolicy CRD to exercise the reader; product structural admission, discovery/watch supervision and signed/resolved acceptance are still required before execution. Earlier synthetic source evidence above remains distinct from this actual source read.

## Retained audit versions

Current automation eligibility requires the exact acknowledged current envelope receipt as well as the separately audited ordinary assignments. Policy execution also requires the retained policy-acceptance receipt. Both require a nonempty non-`null` immutable version and complete original receipt metadata. An older ordinary assignment audit cannot substitute for the current envelope's audit. Exact nonce replay remains historical provenance and cannot reactivate a policy whose retained receipt is unavailable.

The checks use existing bounded/full-row reads and preserve current source, recovery, identity and post-lock deadlines. They do not rewrite old records or grant runtime history-repair privileges. Actual qualification and remaining policy execution composition are tracked in [implementation progress](../implementation-progress.md).
