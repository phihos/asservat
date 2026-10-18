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
