# Shared manual context investigation

C-09 now has one internal `ContextInvestigation` service for browser and MCP
composition under ADR-103, I-09, S-01/S-02 and TASK-02/03/05/07/11. It accepts
request-owned [current identity](current-request-identity.md) and delegates policy
evaluation to C-03, target resolution to C-05, compilation and explanation to
C-06, retention to C-15 and atomic admission to C-21. It does not expose a public
route, dispatch a collector, publish evidence or establish download authority.

The only supported diagnostic is the exact `builtin-pod-status-v1` recipe:
one whole-pod Kubernetes status projection with a 4096-byte native ceiling.
`incident-context/v1`, logs, process lists and network counters cannot silently
resolve to this narrower implementation. The service returns a typed unavailable
diagnostic error before target preparation for unsupported recipes.

## Passive review

`Preview(ctx, CurrentIdentity, ContextIntent)` returns a `ContextPreviewResult`
containing an immutable blueprint and a transient `ContextAssessment`. Intent
contains the public workload name reference, exact diagnostic name, requested
retention seconds and an optional protected reason reference. Current resolution
selects and pins one scheduled Pod, its actual supported owner, node and boot
identity. Submission resolves that exact pin; it cannot select another replica.

Current ordinary eligibility is checked before returning target metadata. The
complete default evidence audience is distinct from the requesting developer's
contributing assignments. The service observes current qualified capability,
accepted retention proof, workload storage selection and installation recovery.
An unprotected retention calculation cannot substitute for accepted source proof.
The original five-second identity and observation intervals bound all reads and
the final response, including time spent writing the draft. A request cannot
detach from the originating browser/MCP request by supplying another context.

Installed preview refusals emit a bounded private stage diagnostic for initial
identity/recovery/target resolution, each facts dependency, processing coverage,
compilation, passive draft persistence and final checks. Dependency errors remain
wrapped for `errors.Is` classification; their text and arbitrary nested stage
strings are never logged. Only fixed stage labels reach the existing exponentially
suppressed process logger. This adds no public result field, authority, retry or
freshness interval. An acknowledged `NotAvailable` envelope remains distinct from
an audit or transport failure that prevented any valid response.

Regional target-query diagnostics report success only after decoded target,
exact requested identity and original freshness validation. Fixed private
labels distinguish the hub receiver cutoff from the regional resolution cutoff;
successful transport alone is not a usable target observation. These diagnostics
never refresh either interval or substitute another Pod.

The passive `ContextPreview` holds server-generated preview, capture, case,
occurrence, artifact, attempt and assessment IDs; original actor/client; exact
authored intent; target pin; selected storage revisions; relative retention;
complete audience assignments; canonical scope/digest; assessment rule digest;
installation/issuer incarnation; and original creation/deadline. The deadline is
at most five minutes and is never extended on replay. No bearer/session token,
groups, current identity, recovery/retention proof or observation freshness is
serialized. The incarnation is a staleness binding, not recovery authority.

`ContextPreviewStore` requires immutable creation, exact actor/client lookup,
expiry and atomic active caps of ten per principal across clients and 1000 per
installation. Unknown create replies may consume a passive slot until expiry;
they cannot start collection. Serialized previews are bounded to 128 KiB and
scope bytes to 64 KiB. Domain validation is structural; shared application
validation additionally checks JSON, scope checksum and actual serialized size.
The PostgreSQL adapter owns durable enforcement and bounded cleanup separately.

The reason value can identify only separately encrypted, scope-bound control
data by ID, ciphertext digest and expiry. A configured protected reader must
recheck its current actor/client, target and exact ciphertext identity. No raw
reason text enters this blueprint or SQL. Missing support is an error, not a
silently discarded reason. The encrypted control writer remains required before
a public form accepting ordinary free-text reasons can use this service.

## Fresh acceptance and original retries

`Request(ctx, CurrentIdentity, previewID, idempotencyKey)` first obtains fresh
identity and recovery and asks `ContextAdmissionReplay` for the original accepted
operation. The submission digest is derived from the immutable preview ID;
SQL independently binds the original actor/client and request key. A conflicting
preview under the same key fails before reading another draft. Lookup rechecks
current SQL entitlement for the stored target and recovery after locks. It needs
neither a live Pod nor an unexpired preview, storage selection or acquisition
retention proof. This is essential when COMMIT succeeded but its response was
lost. Its result remains private capture navigation/status input, not evidence.

Only an absent accepted operation proceeds to draft lookup. The service checks
original actor/client, expiry and installation incarnation, resolves the exact
Pod and refreshes eligibility, capability, retention and storage. It recompiles
and compares canonical scope, complete audience, storage revisions, relative
retention policy provenance and current assessment rules. Material changes
require a new review. Updated observation times do not change reviewed scope or
extend a prior observation's deadline.

Each call owns at most one non-authoritative capacity readiness wait.
Request starts it beside exact-Pod resolution using the preview's pinned
target; Preview and CheckDiagnostic start it after target resolution. The
same wait overlaps eligibility, capability and retention reads in their
existing order, then joins before the authoritative storage read. Early
failure cancels and joins it before returning. Under
[ADR-213](../decisions/213-storage-readiness-at-consumption.md), this same
owned operation retains its original upper bound and single demand-attempt
state through consumption. A valid same-selection result below the existing
one-second freshness margin may poll every 250 ms for an independently
refreshed binding, while every retained non-storage fact remains current.
It may use the sole demand attempt only if the hint has not already spent it.
An early successful hint cannot satisfy the final margin check.

Request pins the preview's exact storage selection; Preview and
CheckDiagnostic pin their first valid authoritative selection. Read errors,
invalid/expired bindings, changed selections and cancellation refuse
consumption. Missing refresh or a failed demand prevents polling for a thin
result; a valid final read with sufficient margin can still succeed.
The wait uses the earliest original
caller, initial identity/recovery, preview, target, eligibility/identity,
capability, retention/proof/expiry and optional reason cutoff. It never
refreshes those facts or extends a binding's timestamps. Target resolution,
ordered initial fact reads and admission remain single operations, with the
existing final eligibility recheck retained. The bounded early hint behavior
for a missing/stale binding remains unchanged.

Evidence retention starts at actual submission preparation, not at preview
creation. A developer can review for two minutes and still request sixty seconds
of evidence retention. The first admitted registration fixes its anchor and
cutoffs. Concurrent submissions may calculate different anchors; exact accepted
replay returns the winner's original registration without altering dates or
reserving again. The original preview deadline still bounds admission/write time.

`AdmitContext` remains the only transaction that binds the request key, original
capture IDs and scope while reserving custody obligations. No second independent
"accepted preview" write is required. Unknown outcomes return an error and retain
the original IDs/key for the next lookup. A different key cannot reuse the same
preview to create another capture. A deliberate repeat requires a fresh preview.
Final current-identity checks reject revocation or changed group/scope/policy
claims after SQL work, while preserving its original request deadline.

Acceptance returns `accepted_pending_audit` or an exact already accepted retry.
It is not permission to execute, a committed artifact or a completed case. Intent
audit, current effect authority, dispatch, independent verification, publication,
case presentation and native download remain separate required compositions.

## Qualification and remaining composition

Focused `go test -race -count=1 ./internal/application/capture
./internal/domain/capture` passed with exit 0; output is retained in
`test/results/context-investigation-unit.log`. Tests exercise passive previews,
assessment identity, exact diagnostic rejection, relative retention after review,
immutable pins and material changes, unknown commit recovery after preview/Pod
disappearance, client/key conflicts, eight concurrent submissions, current proof
and recovery requirements, protected reason references, serialization/integrity
bounds, blocking expiry, originating-request cancellation, and changed identity
groups/scopes/policy after admission and replay. They use the actual shared
eligibility evaluator and request-owned identity handle with explicit test-only
dependency/effect ports; this is not real SQL/Kubernetes qualification.

The first material-change test incorrectly changed only a capability generation
while retaining its content digest. The compiler intentionally binds the ceiling
content digest; the corrected regression changes that digest. An initial design
review also removed evidence dates anchored to preview creation before this
qualification. Neither mistake was worked around by relaxing authority checks.

Public transports must project only the relevant preview/assessment and capture
navigation fields. Before target entitlement is established, named resolver
errors must not reveal whether another team's workload exists. Production
protected capability and storage-configuration producers, encrypted reason creation,
public contracts/UI composition and the later audit/execution/publication/download
path remain required. The existing 1024 historical-capture ceiling still needs
finite idempotency retirement and fair admission; passive preview cleanup does
not fix that separate limitation. Native/provider and full repository gates are
run by the parent task after a coordinated source freeze, with results recorded
in `docs/implementation-progress.md`.

## Approved recorder acceptance (ADR-252)

An approval review may outlive its passive preview. Its exact immutable blueprint
is retained, with the existing preview quotas, through the grant's original
review window/expiry. That permits locating the reviewed plan; it grants no
collection authority. A new review still requires a current preview.

Marked `approvedAcceptance/v1` recorder scopes bind action durations rather than
an absolute preview deadline. Same-requester submission fixes one capture deadline
within five minutes and the grant's original expiry, then performs the existing
current target/eligibility/storage/retention/incarnation/assessment checks against
the original identities and digest. Admission and API execution serialize current
grant use with revocation in SQL. Accepted retries recover their original deadline.
Legacy absolute-deadline plans cannot gain this interpretation; they require a
new preview/review. See [ADR-252](../decisions/252-approved-capture-acceptance.md).

The existing protected approval-settings reader is consulted once per recorder
submission. A changed administrator approval requirement invalidates the review
in either direction. Approval presentation separates passive preview expiry from
the bounded execution window assigned at acceptance.


The browser controller can submit an already-reviewed approval-required recorder
composition. A known `ApprovalRequired` response links the existing approval and
retains the original preview-bound intent key; it does not report capture
acceptance. Detailed `get_grant` outputs provide advisory `can_resume` and
`can_resolve` flags for the original full requester/client. Resume requires
capture scope; passive resolution requires the current read scope and a
previous approved decision, so pending/denied reviews have no close-by-lookup
control. An explicit button names the close-if-unstarted effect.
Resume additionally requires a currently usable marked approval and ordinary
collection rights. Only a user action invokes the existing request operation;
admission remains authoritative. Passive resolution can still find a previously
accepted capture after approval expiry without starting acquisition. The server emits `resume_requires_original_client` guidance only for the same
requesting human on another client while the marked plan is Approved; independent
reviewers and pending/denied reviews receive no such instruction. No grant is
transferred. The preview-bound key is stable across pending review, page remount
and lost replies; no browser credential or private authority is persisted.

Manual recorder assessment rules are `recorder-assessment/v2`: retention starts
at submission preparation, never preview creation. This changes the reviewed
rules digest so an unsubmitted older review must be refreshed. Existing-source
snapshot timing remains a distinct contract and is not implemented by this UI.
The page renders the actual supplied assessment actions, categories and output
limits; unknown overhead remains unknown.


The preview-derived intent key is public correlation. The current authenticated
actor and OAuth client scope SQL lookup; the submission digest binds the preview.
Knowing the key supplies no authority, another preview conflicts under that key,
and a closed preview cannot start under either the same or a different key.
A deliberate new intent requires a new review and preview ID.
