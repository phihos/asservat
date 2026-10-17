# ADR-132: Atomically backed capture-intent persistence

Status: accepted implementation contract; qualification is recorded separately.

The first context request bridge must not call the historical conditional-PUT publisher. That publisher has no irreversible pre-I/O claim, and an exact object lookup does not establish that an earlier writer has finished. An accepted capture must retain its identity and remain recoverable when intent persistence or acquisition fails.

New explicitly configured admissions reserve a purpose-separated `persist_capture_intent` audit pair in the same transaction as capture/custody/control admission. The operation uses the original capture ID and actual human actor. Its capacity account is a protected installation/root/storage-allocation HMAC, independent of the requesting human or client. A capture-specific qualified history layout covers its bounded additional records and transitions. Existing captures are not promoted.

A separately credentialed journal grants one original PUT per phase. Exact reconciliation has two prepaid read claims per phase, each with an immutable original cutoff; later claims cannot renew earlier acknowledgement. Only the actual successful, independently verified and joined producer returns writer completion. An exact lookup can recover persistence but never writer quiescence or a capacity refund. Independent acknowledgement of both encrypted records permits the existing `intent_audited` state; it does not report acquisition success.

The accepted pair reuses the existing positive-completion, independent deletion verification, terminal certificate/overdue and delayed-history-release protocols. Original dates, recovery incarnation and conservative uncertain spend remain binding. Its transient SQL dependency can disappear only in qualified retirement; accepted capture/execution/idempotency metadata remains under its existing control charge.

Completed acknowledgement reuse is a separate exact bounded SELECT, without journal/KMS/object effects or a write-cutoff extension. The retained accepted-capture acknowledgement survives qualified audit-pair retirement, while current acquisition/disclosure authority remains independent. Pending persistence retains its original deadlines and malformed/failed reads cannot fall through to effects.

Public accepted replay stays passive. Runtime composition must add an explicit fresh-current continuation of the original request for a persisted admission whose first start reply was lost. It must preserve the original capture/attempt and never infer that an unknown start had no effect. The current private bridge is not enabled until intent lifecycle, same-request timing, regional start and native transfer are actually qualified.

See [the concrete runtime contract](../architecture/capture-intent-lifecycle.md). This decision adds no public request parameter, regional transport, background acquisition queue or recovery activation.
