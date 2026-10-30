# ADR-267: encrypted descriptive reasons for recording saves

Status: accepted; backend and public composition implemented locally, SQL/provider
qualification pending. Date: 2026-10-30. Implements REQ-SAV-004.

## Decision

Support the already canonical optional 1–512 Unicode-scalar reason on
`preview_recording_save`, preserving text verbatim. It is descriptive user data,
not justification, consent, collection authority or another approval. Absence
needs no reason-key operation. The collection scope, grant, source binding,
submission preview-ID identity and repeat settings remain unchanged. Repeating
selects fresh sources and never restores an earlier reason.

Seal once after the full parent/single reviewed selection exists, using the
hub's existing audit/control Sealer. A distinct inner format binds root, genuine
parent/single capture ID, original requester/client digest and complete scope
digest. Tink AES256GCM ciphertext and opaque wrapped key/reference use byte/base64
fields. No plaintext reason or plaintext reason hash enters SQL. The reference
hash covers encrypted envelope bytes only.

The private preview blueprint contains the immutable reference. Its separate
nullable ciphertext column is copied into the existing mandatory operation
journal during real atomic admission. Capture rows keep only one nullable
immutable `reason_ref`; every grouped child has the same parent-bound reference.
After all real child journals own the exact envelope, a deferred constraint
trigger erases the preview ciphertext in that same committing transaction. It
runs after the original final authority checks and cannot start collection or
rewrite the immutable blueprint. Admission rollback rolls back both copies and
that erasure. An erased preview cannot initiate another reason-bearing admission;
accepted replay resolves the original receipt before loading the preview.

The inner ciphertext passes opaquely through both existing audit phases. New
closed `capture-intent-reason/v1` records and phase-specific object formats have
32KiB plaintext limits; legacy 16 KiB intent/24KiB outcome formats and absent-field
bytes remain unchanged. The minimized CaptureIntent remains 8 KiB. The existing
capture-specific provider compatibility bounds remain key-reference 256 bytes and
wrapped key 8192 bytes; generic SealedKey/Transit16384 bounds do not change. Each
object remains 64 KiB and the funded pair remains 128 KiB. No additional object,
service, credential, key, timer, quota pool or collector privilege is introduced.

Current original-writer claims, joined PUT→exact GET→semantic verify→close,
phase-bound immutable completion digest, acknowledgement and finite unknown-write
reconciliation remain mandatory. A reason-bearing record includes the exact
opaque envelope in its canonical private digest. Its full outcome contains its
exact frozen intent; it does not substitute for intent persistence. Reason
validation after admission uses the immutable journal, so preview expiry/deletion
does not become capture-audit authority.

Authorized `get_capture` opens the inner reason once, after existing current
capture metadata authorization for every real child. A dedicated read-only
`read_capture_reason(uuid,uuid)` projection carries current trust/incarnation, an
original five-second read interval and audit OriginalPurgeAt through the unwrap.
It adds one fixed EXECUTE grant to the existing capture-journal credential; no
new role or table SELECT is added. The original writer/reconciliation read keeps
its WriteUntil bound. The projection preserves the original
initiator and parent/scope binding and repeats the existing final identity and
original-freshness checks after the blocking read. Available text is returned
once on the parent; a retired/unavailable reason is descriptive metadata
unavailability and does not withhold otherwise authorized capture status.

## Lifetime and cleanup

Remove the earlier agent-added coupling between reason expiry and collection
freshness/deadlines. Zero reference expiry means no separate TTL; the existing
mandatory audit lifecycle governs its body. It is not a forever-availability
promise. Capture metadata may outlive that audit and then report the reason
unavailable. Source deadlines, retention, executor and current initiator rights
are unchanged.

Unsubmitted expired previews use the existing bounded expiry-delete adapter.
The existing joined hub history-maintenance loop also runs that cleanup at most
once per 30 seconds, with an original call deadline of at most five seconds
and a page of at most 1000 rows.
It runs even when history publication is unavailable or the history service is
otherwise unconfigured. There is no new timer/goroutine/configuration or SQL
credential: it uses the existing capture-preview role's root lock and delete.
These are two application SQL statements plus existing transaction housekeeping;
actual cleanup latency under contention remains unqualified.

SQL110 preserves legacy predicates and makes32KiB journal caps conditional on the
closed reason version. Downgrade refuses while reason bodies/references remain;
empty downgrade restores the old functions/views/SELECT grants. The audit intent
view adds only the reference, preserving exclusion of mutable coverage/cancel
fields and the exact existing role boundary.

## Cost and evidence

The study and implementation tests distinguish local real Tink crypto from
synthetic wrapping representations and unrun providers. Maximum studied opaque
inner envelope is14140 bytes. Exact typed maximum grouped audit intent/outcome
are below32KiB; the32KiB streaming cipher is32824 bytes and the maximum wrapped-key
encoded object55133 bytes (pair110266), below the unchanged 64/128 KiB caps.
Serialized journal size is not measured PostgreSQL heap/TOAST/index/WAL cost.
Existing row/transition backing and supported backup/replica retention must be
qualified with the new format before claiming those guarantees.

Additional key work: 1 wrap per reason preview, 0 reason unwraps on admission or
per-child audit persistence, 1 unwrap per authorized display. A 16-source Save
copies the same envelope into 32 already funded phase records. Existing outer
wrap/verification counts do not increase. Extra background cost is at most two
preview-cleanup application statements per 30 seconds per existing owner loop;
zero direct Kubernetes requests or watches added. New key effects inherit
the provider's existing authorization work; indirect API counts/latency remain
unqualified. Each progress poll displaying a reason performs its own unwrap;
there is no new cache. Startup reuses the existing SQL pool and key
ports. No cache or degraded plaintext fallback is added.

The initial/follow-up studies record the11-point cumulative complexity review.
The abandoned clear-body proposal would have added32 unwraps for16 children and
was rejected. A separate reason service/object or limit increase is unnecessary.
Actual remote KMS effects, full five-second preview latency, SQL/WAL/backing,
downgrade/erasure composition and installed end-to-end behavior remain pending
qualification; local tests do not enable public source acquisition.
