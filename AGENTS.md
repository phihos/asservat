# Working on Asservat

## Active implementation mandate

Maintainer clarification (2026-10-23): implement the specification and simplify it
when sensible. Preserve the requested product capabilities while revising
implementation choices that add complexity or runtime cost without a clear
benefit. Update the affected contracts and tests with those changes. Continue
through complete user workflows; a status question or component checkpoint does
not revoke the instruction to continue and does not require renewed permission.

## Delivery workflow

Maintainer-approved (2026-11-03): follow [the development workflow](docs/development-workflow.md).
Finish one end-to-end user workflow on one integration candidate. Delegate
bounded implementation/review/reproduction tasks against that candidate; park
unrelated feature work. Run focused reproductions during editing, broad gates
once on the integrated candidate, then fresh installed qualification. Reuse
unchanged-source evidence, preserve required final checks, and inspect producer
and consumer boundaries before expensive dispatches. Keep one concise current
feature ledger; prefer measured simplifications over added infrastructure.

## Event-driven, no polling (maintainer, 2026-11-14)

No polling where an event source exists. Use Kubernetes watches/informers,
PostgreSQL LISTEN/NOTIFY, push over existing connections or in-process
signals, and send changes when they happen rather than on a timer. Polling
does not scale and delays every change by its interval. Resync only after a
reconnect, a watch restart or a digest mismatch; a slow safety resync needs a
stated reason. Cached state remains valid until replaced: do not expire it
merely to force refreshes. Every new ticker/sleep loop, periodic full resend
or expiry-driven refresh must justify in its PR why no event source works.

## Limits need a reason (maintainer, 2026-11-14)

"If you can not give a good reason for a limit then remove the limit." A limit
stays only with a concrete resource cost that grows with it (and a bound
derived from that cost), an external protocol or API constraint, or an explicit
maintainer decision; write the reason next to it. Prefer pagination or
streaming over caps on lists.

## Threat model and security evidence (maintainer, 2026-11-13)

Operators keep every non-Asservat-administrator completely out of the Asservat
namespaces. Anyone who can write there, and any cluster administrator, is
trusted. Do not design mechanisms that defend against namespace writers,
forged Pods or owner references, tampered ConfigMaps or Secrets in those
namespaces, or a cluster administrator. ADR-328 records this threat model.

Components trust the Kubernetes platform like other applications:
configuration from mounted ConfigMaps and Secrets, callers authenticated by
TokenReview and TLS, protection by RBAC and Pod Security. Do not add runtime
re-verification of installer-created objects, UID pins, admission-policy
proofs, journals or launch receipts.

Maintainer decision (2026-11-13): AccessBindings move to the application
namespaces they grant, managed by ordinary namespace RBAC and observed by each
region's connector (ADR-329).

Every security measure must be backed by research first: cite external
sources (standards, vendor guidance, incident reports, comparable projects)
that describe its benefit. If nobody outside this project tells a positive
story about a measure, remove it. Agent-authored ADRs are not evidence.

## Security proportionality and delivery

Maintainer clarification (2026-10-20): the maintainer did not require permission
changes to interrupt in-flight downloads. Retain the existing permission-change
handling, but use a relaxed, bounded recheck interval. Select and document a
practical interval using measured end-to-end runtime behavior. Immediate or
per-step revalidation and the existing five-second interval are not immutable
requirements. This clarification takes precedence over older instructions and
ADRs that prescribe stricter download permission-check timing. The 2026-11-07
maintainer decision (ADR-312, below) removes rechecks after a download starts.

Maintainer decision (2026-11-07, ADR-311): authority is checked once per
operation and reused for at most `identity.AuthorityRecheckInterval` (30 s; 60 s
for the shared delivery-policy observation), never past an original deadline.
Do not reintroduce stacked five-second authority windows.

Maintainer decision (2026-11-13, verbatim): "Yes please make installation
best-practice. The installer pod goes against all best practices. And I can
really not see any security benefit. You could even argue that a compromised
installer or installer service account does way more harm." Replace the
installer Pod/continuation with Helm-native installation: Helm renders all
Kubernetes objects; idempotent hook Jobs only do work that needs live external
state (SQL schema/roles, key and object-store setup). Plain RBAC replaces
UID-pinned admission guards and their proofs. See
docs/reviews/helm-native-install-plan.md.

Do not let overzealous security requirements with unproven security benefits
stall development or cause runtime performance problems. Additional security
mechanisms must address a concrete risk and justify their implementation and
runtime costs. Prefer simple controls with demonstrated value; reconsider
agent-added restrictions whose benefits are speculative.

Distinguish explicit maintainer requirements from agent-authored design choices.
Existing code, tests, ADRs or repeated instructions do not by themselves turn an
agent-added restriction into a user requirement. Update affected contracts and
tests when revising such a choice. Measure the combined cost of checks in the
actual workflow and prioritize completing usable end-to-end outcomes.

## Complexity must pay for itself

Adapted for Asservat from [HAPTIC Rule #5](https://github.com/haproxy-haptic/HAPTIC/blob/0a8fba329ed100c56ef09c05a86e570c4770c0e4/CLAUDE.md#complexity-must-pay-for-itself-rule-5)
and [its rationale](https://github.com/haproxy-haptic/HAPTIC/blob/0a8fba329ed100c56ef09c05a86e570c4770c0e4/docs/agents/complexity-gate.md).

Assess the entire change against the observed problem. Individually correct
steps can collectively produce an unjustified design. Before adding watches,
API requests, permissions, background tasks, fallback behavior, configuration
or component dependencies, record concise numeric or yes/no answers in the plan
or PR. Reassess the cumulative change whenever its scope grows.

1. How frequent and harmful is the observed problem? Flag purely hypothetical
   or test-induced cases.
2. Has the maintainer already accepted this risk? Do not reopen it implicitly.
3. Does this help typical deployments, or mainly an uncommon path?
4. What do comparable projects do? Investigate absent precedent before assuming
   a novel mechanism is necessary.
5. What privileges, credentials, network access or exposure are added,
   especially on collectors and workers?
6. How many failure, degraded or fallback states are added? Two or more need
   scrutiny.
7. Does it need configuration solely to tune or disable its own machinery?
8. Does it depend on components or behavior outside Asservat's control?
9. Estimate aggregate API, watch, memory, CPU and network costs as workload,
   node and cluster counts grow.
10. Are upgrades, rollback and disabling straightforward and tested?
11. Would a smaller fix, documenting the limitation or doing nothing satisfy
    the actual requirement?

Items 1–4 and 11 assess benefit; 5–10 assess cost. When weak benefit coincides
with questionable cost, pause that additional mechanism before implementation
and present the observed problem, cumulative costs, cheaper alternatives and
a recommendation. Otherwise proceed autonomously; routine engineering choices
do not require another approval.

Keep tests aligned with agreed product guarantees. Record maintainer-authorized
contract changes explicitly; the relaxed download-check timing above is already
authorized. Understand why existing mechanisms exist before removing them.

## Implementation notes

The current design is ADR-327 to ADR-330 plus the maintainer decisions in
this file; the specification and docs/architecture/ follow ADR-330. Older
ADRs and component notes are history: where they prescribe polling,
expiring caches, five-second windows, per-request Jobs, private PKI or
enrollment layers, object-store audit pairs, spent-on-uncertain charges or
installer-era guards, ADR-330 supersedes them. Actual qualification is in
docs/implementation-progress.md.

Maintainer decision (2026-11-07, verbatim): "Please remove these rechecks after
download start if that causes too many problems." A content GET is fully
authorized before its response starts and then runs to its original bounds
(caller session/token expiry, session deadline, `AccessUntil`, effective
retention cut-offs, Stop); do not reintroduce post-start rechecks (ADR-312).

The maintainer explicitly allows subagents where parallel work improves speed;
coordinate file ownership. The maintainer requested one-shot completion of the
remaining work without stopping at component handoffs. Continue through the
implementation slices; track active work and verification in
docs/implementation-progress.md. This expands implementation authorization, not
permission to weaken invariants, claim unrun qualifications, use paid resources
or publish releases.

Read `README.md`, `docs/project-guide.md`, the relevant files in `specs/`,
`docs/decisions/README.md` and `docs/implementation-plan.md` before changing
behavior. Do not enable collection for users before the slice's authority,
custody and privacy requirements pass.

## Authority and invariants

User instructions override the original brief and these files. Accepted user decisions are one organization per installation with central multi-cluster management, PostgreSQL for hub transactional state with Kubernetes configuration/local control and object-store evidence; no mandatory broker, expiring policy grants for automatic intrusive actions, sharing within the organization, first-class pprof/similar runtime profiles, and automated permission management with configurable inheritance including pod exec rights, Kubernetes-only permission configuration, low-effort operator/maintainer workflows, and administrator-enforced maximum evidence retention, protection against capture storms and cross-workload storage exhaustion, and optional capture-time sharing plus explicitly bounded recurring-policy sharing. Multiple owner teams may manage evidence shares/instructions; creators remain immutable audit actors. Packet capture supports bounded pcap filters, dynamic Kubernetes peers, segmented rings and qualified HTTP-header extraction. Artifact shares remain concrete snapshots; future instructions never bypass owner, raw-approval or retention checks. Do not introduce a tenant abstraction, tenant IDs, tenant provisioning, or a requirement to host unrelated organizations in one hub.

Never add an embedded LLM, an agent harness, vendor telemetry, update checks, required SaaS/licence keys, public symbol lookup, anonymous evidence access, or unencrypted managed evidence storage. Do not write to external ticket/chat/wiki systems. Use synthetic evidence only in tests. Preserve workload Pod Security `restricted`. Do not weaken authorization, evidence limits or verification to complete a feature.

Research facts, design proposals, and measured integration results must remain distinguishable. Do not mark a pending experiment as passed. Maintain evidence provenance and explicit gaps; never silently substitute a replacement container or a new image for the intended target.

## Specification workflow

Use stable requirement, scenario and task IDs from `specs/traceability.yaml`. Change the relevant specification and schemas with the implementation. Add a decision record for consequential changes. Read only the documents needed for the task; the entire specification is not one prompt.

Before implementation, reproduce relevant defects with failing tests where feasible. Run affected unit/integration tests and repository gates. During the documentation phase, run `make spec-check`. Future runtime gates are planned in `docs/validation.md`; do not describe them as existing commands until implemented.

Every handoff states scope, changed contracts, verification commands and actual results, remaining uncertainty, and the next task. Unchecked tasks are not implemented. Do not install a spec framework merely to follow the file format.

## Local machine and outward actions

This host uses KDE/Wayland on CachyOS/Arch. Use `pkexec` for privileged repository-package/admin commands; plain `sudo` has no TTY. For AUR work, ask the user to cache credentials with `! sudo -v` before `paru`, or to run `! paru -S <pkg>` themselves. Do not create paid resources, publish releases, push registries, or alter protected branches without authorization.

Do not change this workstation's `core_pattern`, create privileged host collectors, or reuse someone else's test cluster for a crash experiment. Kind shares its host kernel; kernel-global experiments belong in disposable VMs.

Do not use stock validation phrases when corrected or qualify candor with "honest". State the correction and act on it.

Latest accepted refinements: whole-pod public scope with no container configuration/permissions/filtering; runtime container identity is provenance only. Monitor all authorized replicas within administrator ceilings, independently cap per-incident collection, and allow administrator-configured finite policy approval periods. Read specs/execution.md before changing digest or grant scope. The full design review and tabletop walkthroughs are in docs/reviews/.

Reusable capture profiles are an accepted first-release requirement: explicit builtin/organization/namespace catalogs, immutable versions, finite typed edits and flat composition into the existing recipe/approval/quota pipeline. Read specs/capture-profiles.md and specs/syscalls.md before changing them. Capture profiles are distinct from runtime profile artifacts. Syscall metadata must avoid user-memory reads; argument mode needs reviewed observation budgets. Preserve versioned composition provenance when repeating from capture history.

Resolve action lifecycles explicitly under specs/action-lifecycle.md: packet/syscall recorders default ongoing and save bounded windows on trigger, while dumps/commands/snapshots run onTrigger. Source arming, observation authority/resources and readiness are separate from incident saves. Manual requests are finite; zero history alone does not change execution mode.

Capture decisions include combined impact and data-handling assessment under specs/capture-assessment.md. Keep configured limits, estimates and measured qualification distinct; never invent overhead percentages or run trial captures during preview. Explain possible sensitive content, effective managed-copy deletion and external-copy limits without adding another consent/approval step.

Accepted follow-up: implement Save existing recordings now according to specs/recording-saves.md as a typed existing-source snapshot, never a full manual policy trigger. Preserve reviewed policy opt-in, original executor plus current initiator rights, source audiences/deadlines, shared budgets and repeat via fresh selection. Accepted ADR-036 requires qualified encrypted scratch StorageClass for offline analysis; no cross-Job emptyDir or plaintext PVC fallback. This remains a specification-stage task; runtime qualification is pending.

Accepted live-watch refinement: existing ongoing packet/syscall captures are observable through finite UI/MCP views under specs/live-watch.md. The maintainer chose approved projections live and saving before raw inspection. Display filters and pause/close affect only the viewer; no implicit acquisition, live sharing, source replacement, ring pinning or authority/retention extension. LiveWatch control is minimized SQL state; rows/replay remain bounded transient data. Maintain browser/MCP schema parity and the synthetic live controls when editing this design.

Implementation architecture now lives in docs/architecture/. Read its catalog, component/interface contract and runtime flow for the feature being changed. The package layout in code-organization.md supersedes earlier sketches. Keep one primary requirement/entity owner, allowed dependency direction, explicit role authority, purpose-specific control work and separate transient live delivery. Run make architecture-check alongside spec-check for architecture/contract changes; it is a design gate, not proof of runtime fencing or cryptography.

The maintainer requires native download for all gathered evidence and saved derivatives, including PCAPNG for Wireshark and cores plus available exact companions for the developer’s compatible debugger. GDB is an example, not a required local tool. specs/artifact-downloads.md supersedes the original brief raw-file prohibition. Reuse current covering grants, authenticate every transfer, preserve quotas/audit/managed encryption, and clearly state that local copies cannot be automatically deleted by Asservat. Do not replace local-tool workflows with mandatory sandbox queries.

The maintainer selected one bounded independent approval for manual collection and the same human’s selected result inspection/download. Read specs/investigation-approval.md before editing this scope. Exact child grants are created only after verified commit, share a finite parent disclosure pool, and retain current entitlement/client/expiry/revocation checks. New user-task findings and unresolved recommendations are tracked in docs/reviews/user-task-review.md; contract/prototype checks are not participant studies.

Use “user data” in product copy, specifications and interface terminology: observed workloads may be internal tools or external services. Keep the distinct legal term “personal data” where applicable.

The maintainer selected React + TypeScript for the production console, with compiled assets served by Go; ADR-046 supersedes earlier Go SSR suggestions. Keep the existing prototype as a design reference. Prefer established, actively maintained dependencies, with no abandoned library adopted by default. Read docs/technology.md, docs/architecture/build-or-reuse.md and docs/research/dependency-maintenance.md before choosing libraries. Isolated experiments under experiments/technology-selection are synthetic planning evidence only; they do not authorize enabling collectors or claim S-00 is complete. Full Go OpenAPI generation failed the actual schema corpus; TS generation requires the tested local reference adapter. ADR-048 now resolves the earlier format-freeze prerequisite; retain backend/commit and full download-session qualification.

The maintainer selected Helm as the official installation method and Keycloak as the first supported/tested external browser/MCP identity provider. Do not implicitly install dependencies or erase CRDs/evidence on uninstall. Internal users/login, static-key services, Helm-provided PostgreSQL (with pgBackRest) and a small SeaweedFS evidence store are explicitly selectable (ADR-063, accepted). Read docs/installation/helm.md, charts/asservat/README.md and specs/deployment-profiles.md before packaging changes; run make helm-check for chart changes.

Recurring team-policy execution is separate from human OIDC sessions (ADR-059, accepted): bounded AccessBinding.spec.automation and installation-local policy identities; a creator's departure does not revoke independent team authority; never replay stale human groups or require directory-reader credentials by default. Read specs/policy-automation.md.

Do not let fixtures, synthetic authority or test-only credentials confer production authority. Use synthetic evidence only in tests. Use an explicit build TMPDIR under ~/.cache; this workstation's /tmp is small.
