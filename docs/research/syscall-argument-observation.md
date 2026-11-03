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
