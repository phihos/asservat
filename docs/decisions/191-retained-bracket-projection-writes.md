# ADR-191 — Worker projection writes under one retained bracket

Date: 2026-10-15. Status: accepted; implemented for the permission
projection and natively qualified ([continuation run 26](../../test/results/adr183-continuation-native-26/result.json));
the capacity and cleanup projections follow.
Requirements: REQ-DEP-005, S-02; TASK-11.
Builds on [ADR-186](186-operation-scoped-public-role-proof.md),
[ADR-187](187-replay-after-guard-bridge.md) and
[ADR-189](189-installed-permission-stream.md).

## Context

A worker projection (capacity, cleanup, permission) records a claim and a
receipt in the original resource journal and creates one immutable Secret.
Its publication runs inside a public role operation, because the Secret
carries role passwords that must match the SQL-verified role snapshot
within its original five seconds.

Each journal access used `readInstalledWorkerResources`. It runs two
complete bridge reads, and each of them includes the configuration role
source proof (about 40 API requests). The journal write repeated it before
its CAS. Native continuation run 25 measured about 3 s for one such read,
and the permission claim write ran out of time with 27 ms left. The
capacity and cleanup projections share the structure and have never run
natively.

## Decision

1. **One retained bracket per publication.** The publication reads the
   resource journal once, through `readRetainedOriginalResources`:
   - one complete handover proof with the bridge's fixed retained guard;
   - the bridge journal;
   - phase-policy reads before and after a plain resource journal GET.

   It keeps that bracket's original deadline.
2. **The role operation supplies the runtime proof.** The enclosing public
   role operation's opening proof already covers the owner workload guard
   with its probes, the owner Deployment, the accepted owner configuration
   and the worker binding. The publication checks the journal's worker
   receipts against that binding, as before.
3. **Writes are CAS against the bracket.** The claim and the receipt are
   `PUT`s that carry the read resource version, the receipt against the
   claim's acknowledged version. No re-read precedes them. An unknown
   reply stays lookup-only.
4. **A closing policy read.** After the last write the retained phase policy
   is read again and must be unchanged, inside the original deadline.

## Consequences

A publication costs one handover proof and about eight journal, policy and
Secret requests, instead of up to eight complete bridge reads. Nothing is
renewed: the role operation, the bracket and the claim keep their original
deadlines.
