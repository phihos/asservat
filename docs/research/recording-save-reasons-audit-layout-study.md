# Recording Save reasons: closed audit layout follow-up

Preimplementation only, same isolated base `5ca61018`. This follow-up supersedes
the outcome-only/clear-body direction left open by
[the initial size study](recording-save-reasons-study.md). Neither production nor
SQL/schema code has changed. No provider was launched.

## Decision supported by the measurements

Prefer an **opaque inner reason envelope in both existing mandatory audit phases**,
with a new closed reason-bearing format capped at32KiB plaintext. Preserve the
legacy16KiB intent/24KiB outcome formats byte-for-byte. Keep CaptureIntent itself
reference-only and bounded8KiB. This is a purpose-specific audit serialization
update for the accepted512-scalar field, not a native evidence/capture limit
increase. Do not use an outcome as a substitute for persisting intent.

The inner reason envelope is produced once at passive preview. Carry exactly
those bytes into the existing `operation_audit.intent` journal at admission;
`outcome.Intent` contains that exact frozen intent. Copy it opaquely into the
existing two encrypted objects. Admission, audit persistence and acknowledgement
perform **zero added reason unwraps**. Authorized display alone opens the inner
reason, after current requester rights for every child. No cache is needed.

The initial clear-body candidate would require up to32 extra reason unwraps per
16-child Save (two phases each); reject it. It is not the selected design.

## Existing lifecycle and exact binding

Current owners and sequencing:

1. `application/audit/capture_operation.go:15` builds the immutable minimized
   CaptureIntent and MAC input. Admission creates its real capture row, reserves
   the mandatory operation journal and binding in the same SQL transaction
   (`migrations/00052_capture_intent_lifecycle.sql:259–285`).
2. `CaptureOperationPublication.AcknowledgedCaptureIntent` checks the independent
   accepted row, claims the original one-use intent writer, then freezes the
   outcome only after the original intent receipt is acknowledged. Its outcome
   is success/prepared/accepted and explicitly says nothing about acquisition
   (`application/audit/capture_operation.go:210–238`).
3. `objectstore/operation_lifecycle.go:91–128` requires successful PUT, exact
   independent GET, full semantic verification and synchronous close before
   returning `OperationWriteCompletion`. Unknown/412 is not joined completion.
4. `domain/audit/operation_lifecycle.go:146` binds root/operation/store/phase,
   receipt, record digest and original times. `OperationLifecycleDigest` binds the
   exact phase and typed record; SQL adapter validates it independently
   (`postgres/capture_audit.go:182,198`). Unknown writes can use only the existing
   finite reconciliation claims, never repeat the writer or renew deadlines.
5. Both phase receipts are required before acknowledgement. Existing retirement
   removes the encrypted objects and journal under the qualified lifecycle
   (`00044_operation_audit_overdue.sql:185–186` and
   `00052_capture_intent_lifecycle.sql:599–620`). Reason data follows that lifecycle;
   no separate deletion object, timer or erasable capture-body column is needed.

Proposed closed variants, with names still subject to implementation review:

- `capture-intent-reason/v1` private input; separate
  `asservat-capture-reason-intent/v1` and `...-outcome/v1` object formats.
- Optional immutable `CaptureIntent.ReasonRef` matches the one nullable
  `context_capture.reason_ref` SQL110 field. Reference identifies the exact
  parent/single preview envelope and digest. Every group child binds the same
  parent reason. It is not collection/grant authority.
- `OperationIntent.ReasonEnvelope` is service-produced encrypted metadata outside
  the8KiB CaptureIntent. Its format/key fields, ciphertext digest and ref must
  agree, with no caller-supplied arbitrary reference accepted. SQL checks that
  the capture-row ref agrees with the payload and that the envelope is unchanged
  in `outcome.Intent`. LegacyNULL means the original protocol only.
- Compute new private completion-domain bytes over the typed **opaque** intent or
  outcome, including the exact encrypted envelope/ref. No plaintext reason hash
  is put in SQL. Outer decrypt/semantic verification compares those same expected
  opaque bytes. Current joined completion, acknowledgement, replay and two-read
  reconciliation semantics stay intact.
- Collection scope/grants and repeat settings remain reason-free. Preview-ID
  submission idempotency and immutable blueprint bytes remain the binding; no
  reencrypt/change on replay. Reason expiry/unavailability affects metadata
  display only, never accepted capture/source/processing authority.

This avoids relying on a live preview after admission: the existing pending
operation journal retains encrypted reason material through its original audit
retirement. After reason audit retention ends, a still-retained capture may
report the descriptive reason unavailable. It does not become unauthorized.

## Existing wrap bounds, without a new global narrowing

The generic SealedKey/Transit ports accept16384-byte wrapped ciphertext. However,
the **existing capture-specific audit encoder already requires8192 bytes** and
256-byte key reference (`objectstore/framed/capture_operation.go:30`);
`sealControlAudit` has the same8192-byte bound. The reason path proposes this
same existing provider compatibility bound, leaving generic SealedKey/Transit
unchanged. A backend returning>8192 for this capture key was already unsupported
by mandatory capture audit; this does not exclude a previously compatible
capture-audit provider merely to fit reasons. Test both8192 and generic16384
representations explicitly; never claim they are interchangeable.

Use version-specific byte/base64 fields for opaque wrapped-key/reference strings,
round-tripping the original bytes before KeyOpener. This avoids JSON quote/slash
escape amplification without truncation. Reject unknown fields/invalid byte
lengths/format mismatches in the new closed decoder. The legacy string envelope
and limits remain unchanged.

## Actual local results

Selected tests in
`internal/adapters/objectstore/framed/recording_reason_envelope_study_test.go`
use existing **real local Tink** `newKey`, `encrypt`, `decrypt`, and `keys(t)`.
Maximum wrapped strings are synthetic representations, not a provider response.
No KMS/server, latency or physical SQL claim follows from these tests.
The final combined three-package study also passed (exit0):
`/home/phil/.cache/asservat-build/recording-save-reasons-final-study-1.log`.
Time fractions and random ciphertext-digest digits make a few sample JSON sizes
vary; that run measured intent29837B/outcome30159B and objects51224B/51653B,
with combined compact/whitespace-inflated journal59996B/61126B.
The fixed32/36KiB ceiling measurements are unchanged.

```
TMPDIR=/home/phil/.cache/asservat-build go test ./internal/adapters/objectstore/framed -run '^TestRecordingReasonOpaqueFrameStudy$' -count=1 -v
```

Actual exit0, package0.009s. Log:
`/home/phil/.cache/asservat-build/recording-save-reasons-opaque-study-1.log`.

| Representation / bound | Actual bytes |
|---|---:|
| Inner512 supplementary-scalar reason, max8192-byte wrap/reference256, byte fields | 14140 |
| Full maximum-width grouped opaque intent / outcome | 29823 / 30143 |
| Actual encrypted intent / outcome objects, same max outer wrap | 51204 / 51633 |
| Combined compact journal JSON / whitespace-inflated diagnostic JSON | 59966 / 61096 |
| Full32KiB plaintext -> actual streaming cipher | 32768 -> 32824 |
|32KiB ceiling encoded object / two-object pair | 55133 / 110266 |
| Full36KiB plaintext -> actual streaming cipher | 36864 -> 36920 |
|36KiB ceiling encoded object / two-object pair | 60593 / 121186 |
| Existing object cap / existing two-object reservation | 65536 / 131072 |

The32KiB candidate leaves roughly2.6KiB over the studied full outcome, with a
conservative512-byte reference placeholder. It is preferred over36KiB because
36KiB is unnecessary for the observed shape. This is not an exhaustive proof of
all future DTOs; production implementation must build the exact typed reference,
strict new codecs, maximum accepted-field fixtures and negative boundaries.

Preserved prior experiments:
`recording-save-reasons-envelope-study-1.log` failed due to an uninitialized local
test key, corrected by using existing `keys(t)`; `...-study-2/3.log` passed.
At generic16384-byte key plus24KiB plaintext, the old string representation
measured66225B (over64KiB), while byte-key representation measured55132B.
Clear-body metadata intent/outcome17487/17859B fit24KiB but that direction is
rejected for its added per-child key work.

## SQL, reservations and qualification boundary

Current SQL52 explicitly limits capture journal intent16KiB/outcome24KiB, plus
`reserve_capture_audit`, writer/reconciliation/acknowledgement checks have matching
literal limits. A new format needs closed version predicates across all of them;
changing only the object codec is incorrect. Proposed new-format journal bound:
32KiB each, legacy predicates unchanged. Actual PostgreSQL `jsonb::text` includes
spaces; it must be measured against the exact new DTO, not inferred from compact
Go JSON. The whitespace-inflated diagnostic is a size probe, not PostgreSQL.

Current backing is at least128KiB maximum row footprint and128KiB maximum WAL per
transition; `OperationHistoryQualification.SlotBacking` covers two residual
generations and32+3*leases transitions for capture history
(`domain/audit/operation_lifecycle.go:43–60`). The two ciphertext objects are
separately limited64KiB each. The measured candidate fits **serialized** object
and journal byte budgets; it does not prove actual heap/TOAST/index/WAL and
backup/replica cost. Existing profile acceptance needs actual new-format SQL
qualification within its funded bounds, with no increased pool/slot/native cap.
If physical costs exceed a current profile's promised maximum, refuse that
profile or review its real accounting; do not call the minimum a measured pass.

No new role or credential is inherently needed: public composition already owns
`capture-journal`, `capture-ack`, independent capture-reader and audit key ports
(`public_context_compose.go:402–414`). A narrow application metadata reader can
use the existing exact capture journal read only after all real child rights,
then verify ref/digest/parent/requester/scope and unwrap once. It cannot expose
arbitrary operation records. That new use requires tests, not a blanket SQL read
grant or reuse of metadata projections as authority.

## Updated cumulative cost / cheaper alternatives

- 0 new service, credential, key, object, timer, watch, config knob or SQL column
  containing an erasable body. Exactly one nullable immutable capture ReasonRef
  column; encrypted body lives in existing bounded preview/journal/audit objects.
- 1 added key wrap per reason preview.0 added admission/per-child audit unwraps.
  Authorized display: one exact journal read and one unwrap (after all rights).
  Existing outer audit wraps/verification unwraps do not increase in count.
- For16 sources, same reason is copied into32 existing phase records. With the
  maximum wrapped representation this is at most452480 bytes of repeated inner
  JSON before outer encryption, within the16 separately funded audit pairs.
  Actual ordinary-provider size/total five-second workflow cost remains unmeasured.
- No new transitions or fallback state; existing invalid/unavailable paths. Format
  alternatives are closed by input/version, not trial fallback. New-row rollback
  must refuse populated downgrade; legacy absent-field bytes stay unchanged.
- Cheapest alternatives: leave reasons explicitly unavailable, or use the
  accepted opaque-format update with real qualification. A new cache/object/
  reason service or32 additional unwraps has no demonstrated benefit here.

The initial study's11 complexity answers otherwise remain applicable. Before
production, root review should settle the closed32KiB variant, exact ReasonRef
and SQL110 predicates; then implement RED/GREEN codec/replay/ref-tamper tests,
followed by existing real-service provider/SQL qualification. No such
implementation or external qualification is claimed by this study.
