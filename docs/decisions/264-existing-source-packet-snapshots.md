# ADR-264: Save a bounded window of an existing packet source

Status: implementation in progress; public availability and installed qualification remain gated.

REQ-LIF-005/006 and REQ-SAV-001–004 require saved history from an independently authorized ongoing source. ADR-263 arming deliberately creates no capture or evidence artifact. The ongoing policy trigger currently refuses incidents before occurrence admission because a finite new recorder cannot supply retained history.

Use a distinct typed source-snapshot request in the existing capture/execution/node channel. Its exact source ID/fence, source-binding digest, snapshot identity, immutable t0/before/after, original source start/hard end, dispatch and processing cutoffs, and output cap are accepted independently of the node. Dispatch issuance is separate from t0: a delayed event cannot acquire a new anchor. Manual recordingSave has after=0. The existing finite Recording validity and canonical bytes remain unchanged.

After ordinary occurrence/capacity/processing/storage admission and committed local start, the connector transfers its existing prepared output keys to one exact node work. The node synchronously copies prehistory through the existing source-owned WindowSnapshot before scheduling posthistory completion at original t0+after. It neither arms nor renews a source and does not debit observation again. Original source expiry/revocation denies new snapshots; an already admitted copy can finish under its separate remaining processing/storage authority. Cancellation affects only that saved output. Natural stopped-source grace is unchanged; no replacement source fills a gap.

The sanitized ring iterator encodes directly into bounded PCAPNG without filtering the source a second time. The initial encoder uses a fixed output arena of at most the existing 8 MiB native cap, separately reserved from the at-most-8 MiB frozen copy. Both reservations remain held until encoding/upload join and erasure. Existing whole-node frozen capacity and per-source concurrent-copy ceilings apply. No new default allocation or source is created to satisfy a save.

The node's authenticated result contains the exact immutable request/admission digest, constrained actual coverage and native hash/size. The connector independently hashes the received native stream before object writes and derives the final expected lifecycle from that result. The hub persists bounded coverage metadata separately from the immutable accepted request, validates it against the original bounds, and independently derives the same final expected digest. Native hashes and detailed evidence remain outside SQL. Publication continues to require exact manifest/native verification; upload success cannot select its own scope, audience, retention or expected provenance. Snapshot PCAPNG verification additionally checks packet timestamps against the requested interval and requires the producer's explicit nanosecond interface resolution. The finite timestamp clamping branch is unchanged; snapshot acquisition may legitimately predate queueing.

The engine exposes one explicit unknown-timestamp bit for legacy raw0 arrival fallback. Finite capture preserves its existing bytes and fallback timestamp. The ongoing source alone debits the original wire input, marks unknown input and stops/erases on that bit; it cannot retain arrival time as historical acquisition time. False does not assert qualified UTC placement. No NTP/clock service or inferred zero uncertainty is introduced. Public source/Save remains gated pending actual native wall-to-monotonic and hub/node t0 placement qualification.

Coverage is conservative. A running context, empty queue or timer does not establish continuous quiet observation. A wholly absent/unknown empty window is a failure. Meaningful retained partial data can be saved with explicit gaps. Full empty quiet history needs an actual qualified continuity observation; the present source owner supplies none. Pre-copy coverage is retained separately so later post-window progress cannot backfill an earlier gap. Retention begins at the earliest possible included acquisition, max(sourceStartedAt, t0-before), never the save click or upload.

Stopped-source selection uses a distinct retained SourceSnapshotTarget: original immutable Request/Pin plus the exact source/node/boot/process binding. A separate bounded regional lookup reads that exact node/source report, without a Pod API request or a freshly stamped PodResolution. The existing15-second status reports original natural SourceStoppedAt and SnapshotUntil=min(grace,currentleaf). Current original-workload entitlement remains independent; namesakes are never selected. Missing legacy target provenance cannot be reconstructed from current objects. API execution expectations retain their existing empty node fields; physical source identity is independently bound by the source digest and retained/current source tuple.

The original source session retains the full default audience under its existing permission-root lock and binds its canonical digest in SourceBinding. Legacy sessions lacking that immutable projection remain unable to Save; current owners are not a substitute for the original audience. Save intersects that original full projection with current entitlement and retention, never unions it. The optional zero digest leaves historical source-arm bytes unchanged and cannot authorize a snapshot.

Manual selection must retain reviewed recordingSaves opt-in, the original team executor's authority and the current initiator's independent whole-pod collection entitlement. The same policy/workload cooldown and occurrence/output/processing budgets govern manual and automatic saves. Inventory and previews are passive. A save selects 1–16 exact sources in one accepted policy/workload scope; it cannot invoke other recipe actions. Request idempotency retains the original t0. Recurring policy sharing instructions are not inherited. History/settings/repeat use the distinct recordingSave operation and fresh source selection.

Complexity: zero new services, credentials, CRDs, watches, polling cadences or user knobs. One typed work/operation and authenticated result extension reuse the existing process-owned node channel, holder, upload, Store/Collect, custody, publication and native-download paths. One timer and at most16 MiB of payload arenas per concurrent maximum-size snapshot; existing limits may refuse admission before that allocation. One upload, existing three wraps/four ciphertext objects per output, no crypto or Kubernetes call per packet. Exact aggregate SQL/WAL and installed CPU/network costs remain qualification work; component tests do not establish installed Gadget/readiness/clock/loss behavior.

## Immutable completion projection (schema 106)

An accepted snapshot binds its requested window, original source, audience,
retention and processing deadline before copying. Actual coverage arrives later.
The accepted expectation and execution digest remain unchanged. Three nullable
columns on the existing capture retain at most 8192 bytes of authenticated
coverage metadata, its SHA-256, and the independently derived final expectation
digest. They contain no native hash, packet bytes or filename.

The execution adapter derives final lifecycle coverage from the original
expectation and the authenticated regional result. One transaction records the
stored execution, immutable coverage and the positive joined writer completion.
SQL requires the same capture/attempt and final digest; exact retries reuse the
original coverage. Finite context and recording completion keep their existing
expectation digest. A snapshot cannot use the finite completion method.

Publication, verification, native retrieval and retained download readers validate
the original admission and audit first, then recompute the final expectation from
retained coverage. Initial key wrapping still uses the accepted expectation;
verification unwrap checks that original execution digest before applying the
completion projection. The completed execution remains provenance for the
original accepted operation, while the semantic verification receipt binds the
final manifest expectation. Neither projection changes scope, keys, timestamps,
retention or authority.

This uses one additional bounded UPDATE per successful snapshot and no extra
watch, service, credential, timer or configuration. The existing API execution
role receives UPDATE on those three columns, and the existing verification-key
reader receives SELECT. Downgrade refuses retained snapshot completions that the
older schema cannot represent. Unit/race checks cover projection integrity and
finite behavior. The owned real SQL/storage component qualification is recorded
in implementation-progress.md; full installed Save qualification remains pending.

The encrypted detailed manifest also retains the exact accepted canonical
source-window scope and original source binding. Their independently supplied
PlanDigest and SourceBindingDigest are checked before key preparation, native
validation and manifest verification. This preserves the original node UID,
node boot, collector Pod and collector epoch after source metadata retirement;
a source-session digest lookup alone is insufficient. The scope is bounded to
16 KiB and binding to 4 KiB inside the existing manifest object. This adds no
objects, keys, SQL reads, services or cadence. Domain values hold bounded bytes;
JSON and SHA checks stay in application/adapter code. Snapshot-only JSON encoding
preserves canonical scope characters such as `<` and `&`; finite bytes retain
their existing encoding.

Snapshot artifact startedAt/completedAt describe the original source observation
interval: max(requested start, original source start) through the earliest of
requested end and a known natural stop or observation close. They do not move
to save admission or upload time. Requested bounds remain in actionLifecycle;
authenticated coverage CompletedAt separately records snapshot processing.
The existing source close callback records SourceClosedAt without another timer
or public state enum. It remains distinct from natural SourceStoppedAt and does
not invent targetGone for an authority/error closure. Final projected lifecycle
retains both timestamps, allowing manifest/native verification after SQL reads
to enforce the original observation interval independently. Nonempty copied
partial history survives source close under its original processing deadline.


## Original source provenance (schema 107)

Three nullable immutable columns on the existing source row retain the full
original audience, its canonical digest and the original minimal target. First
arm derives the full audience under the existing permission-root lock; owners
alone do not represent it. Replays and quiet renewals keep that original
projection. Legacy NULL rows cannot Save and cannot be backfilled. Admission
and execution validate the retained target/source binding and intersect the
original audience with current full entitlement. Automatic snapshots bind t0
to the existing occurrence created_at returned by its original INSERT. No new
clock or query samples the trigger again.

Audience JSON is bounded to 96 KiB, target JSON to 8 KiB and the complete source
record to 112 KiB within the existing minimum 128 KiB record allowance. There
are no new tables, roles, credentials, providers, watches, timers or settings.
Two existing duties each gain SELECT plus UPDATE(root_id) on the source table
for the existing locking read; its immutable guard forbids changing the root.
They gain no source insertion, credit, end or deletion authority. Save admission
reads the original source once per transaction; execution reuses its existing
source read. Arming and maintenance add no query for these fields.

The existing maintenance SELECT reads the added JSON. A local controlled codec
check of 20 sources serialized 69,401 bytes with four audience refs each and
228,541 bytes with 32 refs each. Twenty local decode/hash operations took
0.760 ms and 3.410 ms respectively without race instrumentation. These are DTO
and local codec samples, not PostgreSQL wire measurements or composed runtime
overhead. The 112 KiB record bound across the 1,025-row safety limit permits
117,555,200 bytes of record data per list. No cache or additional query is
introduced without evidence that the typical combined cost requires it.

Downgrade refuses populated original provenance instead of discarding it.
Terminal source metadata retirement remains unimplemented; retaining audience
references and names adds to that known gap. No finite metadata-retirement or
public-readiness claim follows from this implementation. Local codec, audience,
legacy, tamper and grant tests pass. The owned automatic source-to-snapshot SQL,
encrypted publication and native-stream component run also passes; manual,
installed-source and full Save qualification remain pending.

Observed stop/close and snapshot-processing completion timestamps retain their
actual nanoseconds in authenticated coverage JSON and projected lifecycle.
Rounding an observed event to microseconds could exclude a valid final packet
or place processing completion before a stop in that same microsecond. This is
separate from the unchanged microsecond source start, accepted authority, t0,
deadline and SQL writer timing contracts. It does not qualify native clock
mapping or hub/node clock placement, which remain public enablement blockers.
