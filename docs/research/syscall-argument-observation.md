# Syscall argument observation composition

Status: implementation in progress; arguments remain unavailable. Requirements:
REQ-SYS-002, REQ-AUT-006, ADR-261/279/281. Migration 128 follows the pending
profile-summary migration 127; it must not be published ahead of that chain.

The approved scope already includes `maxObservedEvents`, but the existing ad hoc
observation pool debits only bytes. Argument sessions must prepay both before
kernel attachment. Extend that same monotonic grant row with event spend and
one atomic function for both amounts. Existing packet debits call it with zero
events, sharing the byte pool without consuming or resetting the event pool.
Keep independent approved-grant/current-recovery/target checks and the original
immutable session, process binding and deadlines. A pool debit alone never
authorizes observation or creates a replayable session.

The first SQL regression uses 32 concurrent real database callers against a
ten-event pool. Exactly ten five-byte/one-event debits may succeed, then packet
debits can consume only the remaining byte balance. Refused calls change neither
counter; deletion, lowering either counter, revoked/pending grants and rollback
over retained event spend must refuse. The current approved grant is checked
again after the pool lock so waiting cannot renew its expiry.

Complexity assessment: event accounting is an explicit first-release requirement
and demonstrably absent, not a speculative restriction. Existing packet and
policy observation spending supplies the precedent. One additional bigint per
grant row and one existing row lock per debit; zero new tables, watches, jobs,
credentials, network paths or retry states. One narrowly scoped function grant
extends the existing hub role. There is no operator tuning. Kernel enforcement,
fixed ABI definitions, exact session bindings, raw publication/download and
installed Stop/revocation remain required before compiler activation.

The owned PostgreSQL regression first failed because the combined debit function
was absent (2.442 seconds). After implementation, the original byte-only pool
and concurrent event pool passed in 5.352 seconds. The final run also observes
a real blocked pool lock, waits past the original approved expiry, and verifies
that neither counter advances; rollback over retained event history refuses.
All three cases pass in 12.468 seconds with unchanged tested sources and no
cleanup failures. Reports are retained as `test/results/syscall-event-pool-*`.
An intermediate fixture compilation failure used a nonexistent grant field;
the final expiry case uses the existing reviewed result-access NotAfter.
It does not alter grant expiry rules to shorten the test.

SQL generation, specification (13,486 assertions), architecture (1,330 checks)
and Go dependency gates (69 packages/426 edges) pass. Full schema/binary
qualification remains pending insertion of the independently implemented
migration 127; this isolated worktree intentionally does not fabricate that
predecessor. Event counters are not yet wired to production argument sessions.

## Finite argument authority composition candidate

The internal `Recording.Arguments` tuple pins the independently resolved engine,
ABI definition and accounting rule, maximum pre-read probe charge, requested byte
rate, per-event width and buffer selection. Names, event rate and tracked-thread
limits remain in the syscall selection. Its native type is distinct raw
`syscallArguments` / `asservat-syscall-arguments/v1`; metadata records and packet
cBPF program identities are unchanged. The optional field is absent from legacy
JSON. These structural values grant no execution authority or public capability.
The ordinary compiler continues to refuse arguments until the whole path passes.

A distinct `ArgumentObservationPermit` carries exact original scope, source,
node boot, collector process, session and fence. Both cumulative event and byte
credits are irrevocable; the engine's effective event rate is the lesser of the
requested event rate and byte rate divided by the pinned maximum probe charge.
A finite run supports the specified 1–60 seconds within at most ten seconds of
original start slack; the total at most 70 seconds intersects all reviewed grant,
policy, capture and retention bounds. There is no lease renewal or rearming.
This does not implement ongoing argument observation.

The next SQL128 extension reuses the existing observation session and API
preparation transaction: additive argument fields, independent policy acceptance
and grant event counters, atomic event/byte debit and immutable replay. An
explicit legacy digest DTO must preserve every packet v1 field despite generated
model growth. Downgrade must refuse retained nonlegacy sessions/counters.

| Complexity question | Numeric or yes/no answer |
| --- | --- |
| 1. Observed benefit | Required argument capture is currently disabled; zero production frequency claimed. |
| 2. Accepted risk | Yes: ADR-281's narrow patched-engine exception, with native qualification. |
| 3. Typical path | Opt-in sensitive diagnostics; no additional legacy-path authorization reads. |
| 4. Precedent | Existing packet finite observation preparation, grant pool and immutable SQL session. |
| 5. Exposure | Zero new credentials, network destinations or collector permissions. |
| 6. States | Zero new lifecycle states; existing prepared/refused/uncertain/ended handling. |
| 7. Tuning | Zero mechanism-only configuration. |
| 8. Dependencies | Existing PostgreSQL transaction and qualified fixed kernel engine. |
| 9. Aggregate cost | One existing locked preparation transaction; seven session fields and two aggregate counters; zero new tables, jobs or watches. |
| 10. Rollback | Must reject retained argument state; restore exact legacy definitions on empty history, with actual SQL proof still pending. |
| 11. Smaller fix | Byte-only reservation cannot enforce the required pre-read event ceiling; reuse current sessions and grants. |
