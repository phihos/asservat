# Asservat handoff to Claude Code

## Current continuation (2026-10-23)

The maintainer subsequently resumed implementation and approved the complexity
review follow-up. The historical stop and no-Git statements below describe
2026-10-14 only. Git now exists. The current simplification worktree is
`/home/phil/Projekte/asservat-simplify-c62e02ac`, branch
`codex/simplify-installed-lifecycle`; the original checkout remains separate.

Start with the [current progress checkpoint](docs/implementation-progress.md),
[AGENTS.md](AGENTS.md) and the accepted
[complexity review](docs/reviews/complexity-2026-10-20/README.md). Candidate
`072e42a3` includes ADR-222 credential consolidation and the reviewed
`89bfff49` response-metadata/start phase correction on top
of `17e0ff63`: one authority construction per finite download preparation,
response-owned ordinary-permission reconstruction at 30 seconds, and removal of
two namespace GETs from candidate-only workload listing. Exact effect checks and
short current SQL/identity/retention/recovery checks remain. Selected race, real
SQL/S3 and design gates pass; the full current Go gate remains pending.

Native57 passes interrupted installation, regional enrollment, demand readiness
and console processing setup, then fails during capture resolution audit reserve.
One intent-audited capture has no execution/publication. Its persisted audit first-write cutoff was
only 1.433310 seconds after admission; execution preparation later
has insufficient parent headroom. The winning earlier cutoff and initial SQL
ReviewChanged predicate remain unknown. A separate regression now fixes the use
of response metadata freshness to shorten independently authorized startup, with
original effect deadlines preserved; capture/audit race and design gates pass. The two resolution records
are spent under the fixture's configured allowance. No download is attempted.
All 2,792 source hashes match; diagnostics are archived and all owned resources
are independently confirmed removed. No complete installed journey is claimed.

The implementation mandate remains active. ADR-219/221 from the isolated
projection tree is now integrated (`1d46304e`, followed by contract alignment
`9da475cd`): approved inspection shares acquisition, worker enrollment no longer
needs the human preparation socket, and shared capacity replaces four dedicated
query components. ADR-222 gives those hub facets one exact SQL grant union/pool;
key acquisition and pinned readers remain separate. Component/race/console checks
pass; combined compilation and design commands pass, with one generated design
report update retained for a stable repeat. Full Go, scoped real SQL and installed
qualification are next. Continue through complete workflows; status questions and
component handoffs do not revoke approval.

## Historical handoff (2026-10-14)

Prepared 2026-10-14 at approximately 08:20 Europe/Berlin.

## Start here

The user requested this local handoff and explicitly asked Codex to stop because of remaining credits. Codex interrupted both running implementation agents; the diagnostic agent had already finished. No build or native fixture is running under this handoff. Do not interpret the earlier one-shot continuation requests as an instruction for Codex to resume after this stop.

Workspace: `/home/phil/Projekte/asservat`. **There is no `.git` metadata.** Preserve the existing tree and staged work; do not reset it or assume there is a recoverable commit. Source manifests and result archives provide the current change provenance.

The overall implementation objective is to implement the accepted Asservat specification, making justified design corrections where necessary. The platform is still pre-alpha. Significant foundations exist, but there is **no complete installed developer investigation workflow**. The chart still rejects public runtime enablement. Do not enable it by substituting fixture authority or weakening acceptance checks.

Read, in this order:

1. `AGENTS.md` — project rules, accepted decisions, authority and testing invariants.
2. `docs/implementation-status.md` — capability inventory and remaining product work.
3. This handoff — newer than the top of the progress/status files for the latest download failure and accepted connector decision.
4. The top of `docs/implementation-progress.md`, then only the architecture/specification files relevant to the next change.
5. `docs/architecture/implementation-slices.md`, `docs/implementation-plan.md`, `docs/decisions/README.md`, and `specs/traceability.yaml` for acceptance scope and stable IDs.

Do not load all historical evidence into one prompt. The repository contains extensive historical failed runs and component handoffs. Newer explicitly scoped results supersede transient failure descriptions, not the requirements.

## Latest user decision — accepted, not implemented

Immediately before requesting this handoff, the user selected:

> Rotating cluster credential; outbound-only connectivity (Recommended)

The exact question was whether automatic connector recovery after Pod restarts should use a narrowly scoped, automatically rotated enrollment credential in a protected Kubernetes Secret in each workload cluster, or require hub access to each cluster's Kubernetes API.

Implement the first model. The credential establishes that cluster's identity only, expires unless renewed, and preserves outbound-only cluster connectivity. It is distinct from process-owned private keys and from the legacy short-lived bootstrap credential. The hub should retain a purpose-bound credential digest, not a reusable plaintext bearer. It must not authorize evidence access or another cluster. Rotation, uncertain replies, overlap, revocation and restart recovery need explicit bounded contracts. The finite configurable lifetime/default still needs a justified design; no default duration was approved or established by research.

This decision was sent to the owner agent before it was interrupted. No completed implementation or specification update for it is claimed. Architecture notes that still describe the choice as pending are superseded by this acceptance.

Relevant rationale: in-memory process keys disappear on restart; ADR-126 requires ordinary Pod/process recovery without administrator reenrollment. A legacy five-minute bootstrap/client-only leaf cannot provide indefinite restart identity. Hub-side online TokenReview would change the chosen network topology and require API credentials; offline token validation does not establish live Pod/deletion protections.

Primary references already examined:

- https://github.com/spiffe/spire/blob/main/doc/plugin_agent_keymanager_memory.md
- https://github.com/spiffe/spire/blob/main/doc/spire_agent.md
- https://kubernetes.io/docs/tasks/tls/certificate-rotation/

These support the bootstrap/process-key distinction, not an arbitrary recommended lifetime.

## Accepted product constraints to preserve

The full details are in AGENTS/specs; these are especially easy to lose during handoff:

- One organization per installation, central multi-cluster management; no tenant abstraction.
- Go backend, React/TypeScript console compiled and served by Go. PostgreSQL hub transactions, Kubernetes configuration/local control, encrypted object-store evidence. No mandatory broker.
- Official Helm installation. Keycloak first external identity provider; accepted small-deployment alternatives include internal login, static-key services, bundled PostgreSQL/pgBackRest and SeaweedFS. Many alternatives remain unfinished.
- Kubernetes API/CRDs for permission configuration, including configurable namespace inheritance and pod-exec-derived permissions. Team automation uses bounded policy identities, not stale offline human group membership or mandatory directory-reader credentials.
- Whole-pod public configuration/permissions/filtering. Internal container identity is provenance. Monitor all authorized replicas within administrator limits; cap expensive collection separately.
- Dynamic triggers, packet/syscall ongoing rings with save-on-trigger, on-trigger snapshots/dumps/commands, first-class pprof/similar profiles. Profile templates are distinct from runtime profile evidence.
- Live watch exposes approved projections; save before raw inspection. Viewing cannot silently acquire, replace, pin or extend a source.
- Native authenticated downloads for **all** evidence and saved derivatives. PCAPs may go to Wireshark; cores plus available exact companions go to the developer's compatible debugger, not necessarily GDB. Local-tool workflows are fundamental.
- One bounded independent approval may cover manual collection and the same developer's selected resulting inspection/download. Multiple owner teams, concrete shares and bounded capture-time/future sharing remain required.
- Say **user data**, not customer data. Enforce administrator maximum retention, encryption, fair storage reservations and capture-storm protection. Managed deletion cannot delete downloaded external copies.
- Envelope encryption wraps keys; dumps do not transit Vault/OpenBao. Collectors remain wrap-only; hub cannot receive unrestricted raw unwrap authority.
- No embedded LLM, agent harness, vendor telemetry/update checks, required SaaS/license keys, public symbol lookup, anonymous evidence access or managed plaintext evidence.
- Preserve workload Pod Security Restricted. Synthetic evidence only in tests. No workstation core-pattern change or privileged host collector.

## What is verified now

Result paths below are relative to the repository. The result JSON and its retained logs/manifests establish scope; a passing component is not a product-release milestone.

| Checkpoint | Actual result and limit |
| --- | --- |
| Original installed owner startup | `test/results/runtime-provider-owner-native-14/result.json`: PASS, all four required cases. Original observation-mode Pod obtains paired client/server identities with current registration and encrypted version-pinned audit; original Lease deletion and administrator-removal negatives pass. Does not establish Ready/TLS backend serving or the full installed investigation. |
| Passive Go profile endpoint planning | `test/results/runtime-profile-endpoint-component-2/result.json`: PASS, 30 parents / 269 named race tests, compile, vet and spec/architecture/Go-architecture/design gates. Does not establish accepted endpoint catalog, node dialing or installed profile collection. |
| Download fixture claim observation | `test/results/public-context-owner-claim-ready-component-1/result.json`: PASS, five Python tests, seven Go parents / 36 named race tests, compile and vet. Test-only notification replaces additional SQL claim polling without changing production authority. |
| Latest regional investigation | `test/results/public-context-journey-native-13/result.json`: **FAIL**. Collection invoked once, publication and case lookup pass. Original regional request takes 4.291055681 seconds. Download enrollment refuses before CSR processing; no PostgreSQL capacity error in this run. |

SHA-256 values rechecked at handoff:

```text
runtime-provider-owner-native-14/result.json
33cbf9e8479477078fc74619904aa34e381e56557c7796e3273b859f59eb89db
runtime-profile-endpoint-component-2/result.json
1c6e2a878b4cfcbbd42b6908bc479de1ef62154413be393666971f0520e9517b
public-context-owner-claim-ready-component-1/result.json
2fcfc269c506e9e331ca4eb5d47738a37d1049efb09d57240603e347665c2401
public-context-journey-native-13/result.json
6914f31ba8333b7f3f3e304b0bd725a8186d60cdddc9cd0fd7717d7d8a3d6490
```

The full native13 closure was independently checked before handoff: 3,117 outer sources, 2,365 native sources, nine archives and 168 pins matched; owned process groups, Docker/Kind/image resources and scratch were absent. Go exited 1 after 14.376 seconds; wrapper exited 1 after 105.881 seconds. The root execution session was terminal, not abandoned in the background.

Native12 genuinely failed with PostgreSQL SQLSTATE 53300 for `context_catalog_read_runtime`; native13 no longer exhibits that error after removing extra fixture SQL polling. Do not claim the root cause of native13 is known, or erase native12's result. Both published/exit snapshots in native13 contain 43 physical connections against 48 configured slots, three reserved. Snapshots are not peak measurements.

Earlier 45–50%, 35%, and 6–12-week estimates lacked a stable basis and are withdrawn in the status document. The last report's 0/10 fully accepted release milestones was an acceptance-gate count, **not zero engineering work** and not a valid effort estimate. No defensible whole-project percentage/ETA is established.

## Immediate next task: recover the original download continuation outcome

Latest native13 diagnostic:

- Enrollment exchange: one call, one `unavailable` refusal.
- Current-authority checks: 23 calls, no refusals.
- No CSR processing call; first observed refusal is the exchange boundary.
- Collection/publication/case lookup succeeded; no PostgreSQL 53300.

The fixture currently loses a decisive result: `public_context_journey_test.go` starts the original `shared.Call("prepare_artifact_download")` concurrently, then `native.enrollAndStart` may call `t.Fatal`. Its deferred cleanup cancels and drains the continuation without reporting whether it had already failed independently. A **fixture-only two-file diagnostic correction is staged, not integrated or run**.

Stage directory:

`/home/phil/.cache/asservat-build/planning/public-context-continuation-outcome-20261014`

Read `HANDOFF.md`, `manifest.json`, `review.patch`, `runner-manifest.json`, then the two payloads under `files/`:

- New `test/integration/public_context_continuation_outcome_test.go`.
- Changed `test/integration/public_context_journey_test.go`.

The staged wrapper delegates the original call once, retains its exact reply/error, records completion before channel send, and records cleanup cancellation-start before preserving cancel-then-join. It logs fixed classifications, booleans and durations only, never arbitrary errors, response content, evidence or credentials. Tests cover exact result ownership, private errors, both cleanup orderings and joined goroutines. It adds no production reads, retries, limits or deadline changes.

Frozen hashes:

```text
manifest.json       ec0ee2e53178bd54d260d191f9595bd19d78384d4c972e8360a9f91a1a6739cd
review.patch        e154fefd60de8ec8743da3b47c6681c1117c1adec3924883e1ee24de2f736af2
component.py        2acbc385ee56fbf751d205877af396dbb7a0fd6b39d16e464dad53dd10776316
runner-manifest.json 03ab42ef9c4a30b0e21d8310f6a7cdd744818cc58be3c858f95ef0c52158ec6c
```

After review and exact base-hash-checked integration, intended commands from the repo root are:

```bash
python3 /home/phil/.cache/asservat-build/planning/public-context-continuation-outcome-20261014/component.py public-context-continuation-outcome-component-1 --parent-exclusive-slot-allocated
python3 /home/phil/.cache/asservat-build/planning/public-context-continuation-outcome-20261014/native/run.py --mode journey --output-name public-context-journey-native-14 --parent-exclusive-slot-allocated
```

These commands **have not run**. Run them sequentially, after checking their reviewed inputs and output-name nonexistence. The handoff itself adds a source-tree file; runners that pin an exact file set may need an explicit documented accounting update. Do not silently weaken a hash check or include staged `.go` files in the live tree without review.

Use the recovered original outcome to choose the production correction. Do not blindly repeat native13 or assume a timing/registration cause.

Useful source map and observations:

- `internal/application/.../worker_routes.go`, `worker_channel.go`, `worker_owners.go`, and `context_native_runtime.go` can be located with `rg --files`; read their current implementations, not line numbers from old notes.
- `WorkerEnrollmentRouter.beginWorkerEnrollment` rejects absent/closed routes, expired bounds, or concurrent enrollment before delegation. Direct Begin does not require `route.owner`.
- `WorkerEnrollmentOperation.EnrollWorker` checks parent/context/bound/identity before entering the coordinator. The fixture proof factory returns a nonnil proof with no error. No CSR narrows the failure to an earlier boundary; it does not prove which predicate failed.
- `WorkerRequestOwners.Register` registers the local route, checks current identity/worker, claims the SQL owner, then performs final current checks and assigns `route.owner`. On failure it closes the route. **SQL claim notification is not completed registration/readiness.**
- `ContextNativeRuntime.ContinueContextDownload` owns the original registration and closes it on return, checks attachment/enrollment in a bounded loop, and then prepares native transfer.
- Current request identity retains original validity intersected with five seconds from construction. Worker current checks monotonically narrow their original interval. Read `docs/architecture/current-request-identity.md` before changing these bounds. Do not turn five seconds into a renewed global authority lease merely to pass the test.

## Other staged work: preserve it, do not treat it as qualified

All three agents used `/home/phil/.cache/asservat-build/planning` for independent staging. **Do not delete that cache directory.** No remaining agent should edit it after this stop. The streaming stage was interrupted mid-task and has no final review/test handoff.

### Installed owner/region composition (former agent owner_qualification)

Directory:

`/home/phil/.cache/asservat-build/planning/installed-observation-binding-20261014`

The frozen initial selection subset contains 16 source paths, plus a separate compatibility test supplement; it is not integrated or tested. It pins an original observation-format selection before the original nineteen startup claims. Omission preserves v1 bytes; explicit v2 requires the intended provider-installed layout. It cannot silently downgrade or upgrade from a later file. `ReadObservationParticipants` derives original owner and HWORK pins from the same native responses/brackets as the existing reader; it does not select replacement Pods.

Artifacts:

- `selection-manifest.json`: `a9bdcea7f5c8b4dd8567d09e52f3909b49233a8fd397ab3804dcf56a2994edf1`.
- `selection-changes.patch`: `eafa973c066262211d807ef0ac08eae8577eb7d5fd0c34aeb9d04899b83c415a`.
- `REGIONAL-AUTHORITY-DESIGN.md`: `ff0e5df34fcae07570f532632fa1511fb8ad6f9c481e4f01006593fef75041fd`.
- `HUB-PRIVILEGE-PROVISIONING.md`: `1ae0273a252754c4faf02ad8ee65436377be3ded69e318944b2eb08db57a1dd2`.
- `PRIMARY-PRECEDENTS.md`: `48f51a7c3e41ae6b43a439710b9f46f4947307c041b90631a53d72fe8fb95909`.
- `selection-component-v1/` has the exact 16 payloads plus a separate bootstrap test: valid v1 accepted, selection-only v2 refused while complete backend is absent.
- Component runner SHA: `d10cb4981c78a94d374873165547ffa47e2fa7d13078652ceb53160ee5cab3fe`.
- Component manifest SHA: `5a77ba16466bc56c059e8f5486fcdc3a8ea840040ff4d85df17901433dc10010`.

The runner proposes compilation, six serial race groups with 64 exact parents, vet and canonical checks. It has not run. Integrate only after review, checking base hashes and index conflicts.

**ADR-165 is reserved for this work.** No new migration was completed. Migration 60 belongs to streaming below; if connector credential persistence needs a migration, reserve 61 explicitly and inspect the current tree first.

Critical separation: SQL49/51 source/journal/ack/cleanup/verifier/finalizer duties are installation-root shared **hub duties**. Never mount those credentials in regional Pods. The staged hub privilege plan maps exact functions, four lifecycle-lock views and finalizer-only history reads; it is a plan, not tested provisioning. Reuse the existing private listener and ADR-153 fixed-phase protocol, not generic RPC. Any regional native attestation must be described as delegated regional proof, not an independent hub TokenReview.

Do not create a preliminary binding ConfigMap or partial immutable backend Secret as if it were complete installation authority. Finish the authorized restart identity design and exact producers/receipts first. Keep original immutable startup pins, current recovery fences, cancellation and cleanup.

Additional gap assessment:

`/home/phil/.cache/asservat-build/planning/installed-context-next-slice-20261014/ASSESSMENT.md`

SHA `95ed9bc753d0f0a1d2adfcdf39e0e29951c00e12a8a3f64be0264daa8f21349f`.

### Shared streaming custody (former agent runtime_profiles)

Directories:

- `/home/phil/.cache/asservat-build/planning/runtime-profiles-20261014/streaming-custody-assessment-v1`
- `/home/phil/.cache/asservat-build/planning/runtime-profiles-20261014/streaming-custody-v1`

**ADR-166 and migration 00060 are reserved here.** Live repo remains at migration 00059. The second directory contains `base-hashes.json` and a partial `work/` tree (173 files, approximately 2 MB at interruption, including many copied/generated unchanged bindings). Do not copy that whole tree over the repository. Identify intended changed files, review base hashes, finish missing tests/docs and generate a final manifest first.

Last agent report: drafted migration60/generated sqlc bindings, immutable plans and one-use transitions, recovery/retention-guarded SQL registration/journal/finalization, shared multipart writer, ranged ciphertext verification, read-only uncertain-completion reconciliation and upload/part/version purge. Synthetic HTTP/codec and real-service tests plus ADR166 were in progress when interrupted. **None of this implementation was built, tested, reviewed fully or integrated.** Some claimed drafts may be incomplete; inspect the files.

Only source generation ran: existing sqlc v1.31.1, binary SHA `fae55f275d1a5d8722eb5b52b97a2cc2d2f39e3d9135dd0449291be21df26b44`. No dependency installation or service launch.

Scope agreed for this work:

- Reuse ADR-048 framed format, four final receipts, existing custody ledger and workload quotas.
- Initial 128 MiB qualification supports profile/trace bounds; it does **not** reduce the product's 1 TiB/large-core requirement.
- Streaming admission is selected for declared native limits above 8 MiB; actual output may be tiny. Keep small-object behavior unchanged.
- Atomic reservation of final storage plus temporary multipart obligations; sequential 8 MiB parts, up to 17 at the initial bound, exact journal and one-use create/complete claims.
- AWS SDK single-attempt behavior, uncertain reply reconciliation, HTTP 200 embedded-error handling and bounded ranged ciphertext verification.
- No native hashes, secret keysets or credentials in SQL. No wider context authority.
- Local writer Close/join is not remote writer quiescence. Require an exact independent fence plus complete upload/parts/versions inventory before releasing charges; retain uncertain spend.
- Backpressure consumes original action time. Do not silently extend context's one-minute or verification's thirty-second bounds.
- Existing `artifact.Registration.Validate` small bound and small-object adapters cannot be advertised as large-object support. Review legacy direct-registration guards and deletion dispatch with the new path.

Approved fixture refactor: preserve the existing `TestContextAdmissionWithRealServices` body/selection with `streamingOnly=false`; a new `TestStreamingCustodyWithRealServices` uses the same bootstrap with `true`, runs its exact required cases and returns. No empty-pass or ambient-mode substitution. Close helper pools before subsequent suites. Coordinate shared `capture_admission_test.go`, generated models, schema version, indexes and harness edits; diagnostic work also touches this test area.

Assessment SHA: `cfd9fa481867ce9c518a15a0ecd652bc42ca6ed15df11d5836b94aa60c63743a`.

## Integrated changes that have not yet reached the progress document

The claim-notification fixture change is live in:

- `test/integration/public_context_journey_native_test.go`.
- `test/integration/public_context_owner_claim_test.go`.

It embeds/delegates the real store, publishes one buffered notification only after a successful uncanceled original claim, and waits within the original one-second/caller limit. It does not poll SQL, retry, modify concurrency or claim final registration readiness. Normal later cancellation of the helper claim context does not erase an already observed successful claim; cancellation at original return cannot notify another live waiter.

Integration evidence:

`test/results/public-context-owner-claim-ready-integration/result.json`

SHA `e0cac690e0522035498ef2a825aac5e90ceda01764de47af3e31cf5063508789`.

Independent native13 verification:

`/home/phil/.cache/asservat-build/planning/public-context-owner-claim-ready-20261014/native13-independent-verification.json`

SHA `4fca63bdd88b3195634e77a15019b15765a7b1ab01fcd3d0b160dadb066e5591`.

The top of `docs/implementation-progress.md` and the critical-work paragraph in `docs/implementation-status.md` still describe native12's catalog connection failure. Update them after the next coherent diagnostic checkpoint, preserving previous failures and distinguishing the changed native13 failure. This handoff deliberately does not launch another gate just to update those older files.

## Running qualification safely on this host

- One global build/native-fixture slot. External labs run sequentially. Parallel agents may research/stage disjoint files, but freeze all relevant live sources/docs during qualification. Do not modify a source tree while its test image is being built or tested.
- Use `GOMAXPROCS=2`, `GOFLAGS=-p=2`, and an explicit task TMPDIR under `/home/phil/.cache/asservat-build`. The provider-pair native runner has a separately qualified bounded `/tmp` usage; preserve that runner's behavior.
- The workstation previously ran out of disk and experienced power outages. Check free space before large work. Do not clean unrelated resources or run broad Docker prune commands.
- Preserve fixture PostgreSQL `max_connections=48`, three reserved slots, and Kubernetes clients at 20 QPS/burst20. Close leaked/setup-only pools; do not raise limits or blanket-reset pools to hide an error. Many adapters can perform nested acquisitions, so blanket pool-size-one changes are unsafe.
- Do not touch the unrelated `haptic-e2e-control-plane` cluster. No host core-pattern modification or privileged host crash experiments. Kernel-global experiments require disposable VMs.
- No paid resources, registry pushes, release publication or protected-branch changes are authorized by implementation continuation.
- Package/admin elevation uses `pkexec` on this KDE/Wayland host; ordinary non-TTY sudo is unsuitable. Do not perform new installations just for this handoff.
- Canonical spec Python: `/home/phil/.cache/asservat-build/spec-venv/bin/python`, with required format extras. Do not run a fresh environment missing date-time/URI validation.
- `make architecture-check` rewrites `docs/architecture/validation.json`. Existing frozen runners archive the generated output and restore the original before source-equality checks. Preserve provenance rather than ignoring that mutation.
- Applicable ordinary gates include `make go-check`, `go-architecture-check`, `sql-check`, `spec-check`, `architecture-check`, and UI/Helm gates when their code changes. Read Makefile/validation docs for arguments; targeted staged runners already encode important fixture setup/selection/cleanup.
- Every claimed run requires actual process exit, selected test names, source hashes, retained reports and joined cleanup. A running session or first success log is not a pass. Distinguish fixture-only facts from production authority.
- Archive copied Go/SQL sources as `.go.txt`/`.sql.txt` so they cannot enter normal package/migration discovery. Do not add generated archives to source globs.

## Recommended continuation order

1. Review and integrate the small original-continuation diagnostic stage; run its component gate and native14 once. Use its result to fix the actual download enrollment failure.
2. Review the original observation-selection subset and qualify its compatibility before composing v2 runtime activation. Record the newly accepted outbound rotating-credential decision in the relevant ADR/specs.
3. Finish/review the interrupted streaming custody implementation and its real-service qualification. Preserve small-path behavior and uncertain storage charges.
4. Complete protected owner/regional/capacity/audit provisioning and the installed S-02 path: actual browser/MCP target selection → preview/request → regional collection → encrypted publication → inspection/native download → revocation/expiry/deletion, across two clusters using product-provisioned authority.
5. Continue the remaining collector, trigger, recording/live, analysis, approval/sharing, ergonomics, small-deployment and production-operation slices from the accepted plan. Do not confuse the deep context foundations with completion of the comprehensive product.

There are no pending user questions from this handoff. The latest connector choice is answered. Codex stopped at the user's request; all staged work above is local and available to the next agent.
