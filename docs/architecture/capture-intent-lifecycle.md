# Capture-intent persistence lifecycle

This implements ADR-132 for the bounded context profile. `CaptureOperationPublication` accepts only an exact already admitted capture ID. `NewAuditedContextAdmissions` selects the protocol from protected backing, atomically reserves its pair, and preserves original IDs and accepted replay. No public collection route or installation source producer is added.

## Admission and capacity

Migration 00052 adds three fixed tables: one `capture_audit_root` per permission root, `capture_audit_allocation` per configured permanent storage allocation, and `capture_audit_binding` per new capture. `context_capture.intent_operation_id` is immutable, nullable for old captures, and equals the original capture UUID for new ones. The transient binding has one digest and exactly four optional reconciliation cutoffs; it carries no reason, credential, evidence, native hash or fresh identity claim.

The root pins eight distinct purpose-specific non-superuser, non-inheriting SQL logins. Protected source configuration binds the permanent allocation to the exact audit account HMAC and qualified lifecycle policy. Guaranteed records cover the complete configured context-control account limit, and the common capture-lane pool backs the union of configured accounts. Different humans or clients cannot consume another workload's account. Configuration CAS may renew original source observations or pause admission; it cannot reset counters, change the account identity, forget unknown work or remove another workload's backing. Root/account retirement and HMAC rekeying require separate qualified composition.

The lock order for new admission is recovery, permission root, capture-audit pool/backing, custody pool/allocation/binding, context-control pool/account, capture/attempt and pair/lifecycle. The purpose-specific prefix is acquired before custody. Pair cleanup uses recovery, audit pool, account, operation/lifecycle and never subsequently locks permission or storage. Admission rounds only the live caller cutoff down to SQL microsecond precision; it never rounds expiry up or changes accepted capture/write/retention dates. Every supported effect checks the original deadline after blocking work and after commit; SQL write/read claims return the original minimum cutoff to the caller. No read, lock or exact replay extends it.

A deferred constraint rejects a capture under configured backing unless its pair and exact immutable payload were reserved in the same transaction. Legacy admission cannot omit the protocol for that allocation. Rollback of an uncommitted transaction leaves no charge; an ambiguous committed admission remains charged.

## Bounded records and effects

The private operation is `persist_capture_intent`, input format `capture-intent/v2`, lane `capture`, layout `capture-intent-history/v1`. It preserves the actual accepted human actor, exact target, original capture/case/occurrence/artifact/attempt IDs, scope/expectation/submission digests, permission revision and original dates. The minimized payload is at most 8 KiB. The separate intent/outcome framing permits at most 16/24 KiB plaintext and retains the existing 64 KiB ciphertext limit per object. JSON encoding disables HTML escaping only for these new private formats. Old operation formats, absent-field bytes and their limits are unchanged. Capture completion uses SHA-256 of the exact bytes `asservat-capture-completion/v1`, NUL, the closed `intent` or `outcome` phase, NUL, and that phase's typed bounded JSON (Go field order, UTF-8, HTML escaping disabled, no trailing newline). The same function is used by the closed producer, independent acknowledgement adapter and stored lifecycle verification, including pointer-valued decoded records. SQL retains the exact nonzero digest as immutable completion data; it does not reinterpret JSONB key order as this canonical encoding. Legacy operation/certificate completion digests retain their previous JSON encoding. Qualified opaque wrapping strings retain bounded non-control text; strings are never truncated.

The pair reserves two ciphertext objects at peak. Its qualified SQL/history record footprint includes the pair, lifecycle and transient binding, plus the existing bounded common account/history residuals; the capture row itself remains charged independently by context-control accounting. The private layout requires at least 128 KiB per retained slot and transition and counts 32 fixed transitions plus three per bounded purge lease. These are accepted qualification inputs, not measured production PostgreSQL/WAL footprints: an operator profile must independently qualify its complete transaction, heap/TOAST/index pages, rollback/lock WAL and supported logically recoverable backup/WAL/replica horizon. A positive number alone is not qualification.

Only an acknowledged first durable claim allows one PUT. Intent starts before the original request cutoff; outcome starts before the original write cutoff, at most 30 seconds from admission and never beyond the original capture deadline. Frozen outcomes describe accepted intent persistence, not acquisition. Each phase permits two irreversible exact GET/unwrap claims. The original deadline of each claim remains independently stored, so a later attempt cannot authorize completion of an expired earlier one.

The closed object producer returns completion only after its actual successful PUT, exact verification and joined synchronous owner. A lost claim/PUT response permits bounded lookup, not another PUT. Lookup may recover a receipt but cannot create writer completion. Independent receipt acknowledgement and positive completion are distinct SQL columns/roles. Two exact acknowledged receipts permit `intent_audited`; unknown writer completion still prevents refund/healthy retirement.

Private refusal diagnostics identify the fixed persistence stage: retained
read, journal, write/reconciliation claim, object operation, completion,
acknowledgement or pair validation. Only allowlisted dependency labels and
bounded HTTP status labels may accompany that stage; provider text, keys,
credentials and record values are excluded. Failed object operations also
distinguish the original call's cancellation or expiry without renewing it.
The submission reports these
through the existing bounded private logger and retains the accepted
`OutcomeUnknown` result. Diagnostics add no reads, writes, retries or authority
intervals. A spent write whose object is absent remains unavailable; an exact
lookup cannot recreate it or justify another capture.

## Cleanup and boundaries

The private filtered lifecycle views reuse the existing deletion protocol, including separate purger, verifier and finalizer credentials, two prepaid certificate-verifier attempts, original dates, the explicit overdue no-certificate branch and H-backed cooling. The accepted capture does not disappear when its audit pair retires. Removing the transient binding requires the same qualified finalization transaction and independently acknowledged terminal purge; no cascade deletes accepted/execution/replay state.

Historical/unknown writers, restart reconciliation, metadata retirement U13 and backing-source provisioning remain required work. The protected source credential must be provisioned with exact installation scope; fixtures synthesize that root and do not supply production authority. An old receipt never promotes a legacy row. The current incarnation fence is retained; this component does not activate a restored database.

Completed pairs use a separate exact `capture_operation_intents` filtered SELECT view and `NewCaptureOperationIntents`. The reader validates the explicit operation ID equals the original capture ID, original minimized intent digest, acknowledged timestamp/state and exact operation-intent receipt. A legacy key or incomplete row cannot represent this protocol. `CaptureOperationPublication` reads that retained row first under the original caller's at-most-five-second bound, checking cancellation and expiry after the read. A complete acknowledgement returns before opening any writer, journal, KMS or object path, including after its immutable audit write cutoff or independently qualified pair retirement. Malformed or unavailable reads do not fall through to effects. The retained result is historical provenance; current collection/disclosure permission, recovery and the original capture deadline remain mandatory at the consuming bridge. Only exact pending rows enter the active path with the unchanged original request/write cutoffs.

The existing UI and MCP admission receipt/progress/resolve behavior remains. A downstream failure retains the known admission. Historical replay never starts collection. The next public composition must expose fresh-current same-key continuation, measure admission through durable intent to actual acquisition under the original request, and connect the existing regional runner/native transfer boundaries. Until those qualifications pass, public collection remains disabled.

## Verification status

The capture-specific domain/application/objectstore/framed races pass, including maximum valid complete writer records, private framing and final original acknowledgement deadlines. Completion-digest, final-acknowledgement and completed-read-after-write-cutoff regressions were reproduced against the prior code first. The actual maximum-text complete pair used 24,125 ciphertext bytes; the maximum opaque wrapping-envelope test used 36,646/37,143 bytes per object, within the unchanged 65,536-byte cap. These are synthetic loopback TLS/Tink measurements, not production storage qualification.

The combined exact SQL51/52 five-package race run passes, including embedded migration history/head tests and the existing connector/processing regressions. The latest integration helper source compiles, and six affected packages pass vet. SQLc parsed and generated the exact integrated schema51 plus additive52; generated bytes were compared with the staged bindings. The unchanged Go architecture checker passes with sparse-overlay file reads (51 packages, 269 internal edges). A prior broader Postgres unit run rejected the deliberately incomplete schema50/52 embedded composition in two bundle tests; those failures remain recorded and the combined rerun passes without relaxing the checks. The corrected real SQL/S3 fixture subsequently passed eleven named entries in 112.324 seconds, with 1,333 unchanged source hashes and complete cleanup ([recorded native run](../../test/results/capture52-native-after-storage-lock.log), as recorded in the implementation progress report). Its source/identity/retention and backend qualification inputs remain synthetic; it does not establish complete runtime qualification.

The new custody fixture targets atomic admission rollback, role separation, same-live-request persistence timing, concurrent claims, finite reconciliation, actual two-object inventory, direct empty-digest denial and positive H=0/H>0 retirement. Its H>0 path rolls back a completed SQL transfer to cooling, then races two finalizers and proves that draining the healthy record leaves a separate same-account unknown writer charged. It also waits past a genuine original 30-second audit write cutoff while the original 40-second capture interval remains open, and verifies passive provenance after pair cleanup. Its source/identity/retention roots and accepted backup profile are explicitly synthetic. Actual collector acquisition, production backend IAM/backup measurement and regional routing are outside that SQL/S3 fixture.

The separate ADR-134 acquisition fixture exposed two admission-boundary defects before any capture or audit row committed: a nanosecond live request cutoff failed the SQL-precision record check, and its configured 60-second audit retention left the original purge at admission +14 seconds while the capture required a +30-second write interval. Deterministic regressions reproduce both. The correction truncates only the live request cutoff downward and configures 120-second fixture audit retention, placing original purge at +74 seconds with the same 30-second write interval, 15-second cleanup budget, one-second proof and H=0. Collapsed sub-microsecond intervals still fail. The [corrected native acquisition run](../../test/results/continuation134-native-after-admission-fix.log) passes preview/request, original encrypted intent acknowledgement and explicit continuation into one API acquisition. It verifies, publishes and reads 362 native bytes after target/executor deletion. Its terminal report records two passing entries, 1,348 unchanged source hashes and complete cleanup. Fixture human/bootstrap/retention facts remain explicit; installed regional/public transport qualification remains pending.

## Deferred-validator role correction

Migration 00058 corrects the execution context of the two read-only deferred
retirement checks. Their original predicates read the shared lifecycle/history
tables after a capture cleanup view or fixed function returns. Running those
checks as the restricted caller caused SQLSTATE 42501, including on otherwise
valid cleanup transactions. They now use their existing migration owner, fixed
search path and fully qualified relations. Runtime roles gain no base-table
privileges or direct EXECUTE permission. The same deferred checks still reject
stranded retirement markers at commit; original deadlines, recovery checks,
private filtered views, fixed effects and charge-release conditions are unchanged.

The failed full regression and its exact SQL errors are retained in
[implementation progress](../implementation-progress.md). The
[corrected full custody run](../../test/results/custody-regression-20261013-2/result.json)
passes both healthy-retirement paths, restricted-role checks and the shared
stranded-retirement rejection, with unchanged sources and verified cleanup.
This is native component qualification; no installed workflow is enabled.

## Descriptive recording-save reason variant (ADR-267)

SQL110 adds one immutable nullable capture reason reference and a separately
erasable preview ciphertext column. The encrypted envelope is copied into the
existing mandatory operation journal and both audit objects; no plaintext reason
or its hash enters SQL. The legacy minimized CaptureIntent limit stays 8 KiB.
Only `capture-intent-reason/v1` selects the new 32 KiB intent/outcome format, with
byte-key outer envelopes and the same existing8192-byte capture-provider wrap
bound. Generic16384-byte SealedKey limits and legacy16/24KiB encodings remain
unchanged. Object/pair limits remain64/128KiB. Existing joined completions,
phase-specific opaque record digests and bounded reconciliation remain required.
After all child journals own the exact body, a deferred constraint trigger
erases the preview copy at commit; later validation does not require that
preview. Existing expiry cleanup covers abandoned previews. Actual SQL/WAL and
provider/runtime qualification for this variant is pending.

Historical reason display uses `read_capture_reason(uuid,uuid)` on the existing
capture-journal role with one additional fixed EXECUTE grant and no new table
SELECT. It returns only the original capture/ref, opaque envelope and the
original at-most-five-second current trust/incarnation/OriginalPurgeAt interval.
That interval also bounds the unwrap. It never extends the original writer or
reconciliation WriteUntil, whose existing lookup is deliberately unsuitable for
post-completion descriptive metadata. All real children are authorized by the
existing progress reader before this projection is called.
