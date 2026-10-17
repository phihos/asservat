# ADR-188 — Configuration role proof after the SQL locks and the bridge

Date: 2026-10-15. Status: accepted; implemented. Native qualification passed
([continuation run 23](../../test/results/adr183-continuation-native-23/result.json));
diagnostic runs 19–22 are retained failures.
Requirements: REQ-DEP-005, REQ-DB-005, S-02; TASK-11.
Builds on [ADR-186](186-operation-scoped-public-role-proof.md).

## Context

One configuration role operation ran three full source proofs:
- the claim's opening proof;
- the role step's root read after the SQL locks;
- the completion's root read.

The unit fixture measures 118 API requests and 4.55 s at 20 QPS against
the original five-second claim, so a native pass had almost no margin.
Raising the client limit or the claim lifetime is not allowed.

Native continuation runs 19–22 stopped at the first configuration role.
Every replay found a claim without a role, which stays lookup-only, so the
installation stopped. With fixed check codes (runs 21–22), the first
attempt failed at the post-lock recheck with
`source.deployment-final-bound`: the worker Deployment's resource version
changed during the operation. Until the bridge's retained step, the
namespace-wide initial guard denies the Deployment controller's status
writes. Once released, the controller's backed-off status write lands a
few seconds later, inside the first role operation.

## Decision

1. **The post-lock recheck guards the effect.** The role step's root read
   after the recovery and installation locks keeps its full recheck. It is
   the last proof before `CREATE ROLE`.
2. **The completion records under that proof.** Its root read reuses the
   operation's latest proof when a recheck followed the opening proof. It
   still fetches the journal, and the CAS write and the original deadline
   are unchanged. Without such a recheck it proves afresh, so it never
   reuses the opening proof.
3. **The projection follows the same rule.** The readback after the
   immutable projection create reuses the post-verification recheck before
   it records the Secret UID.

4. **Settle after the bridge.** After the retained step, the continuation
   waits, for at most two minutes, until the worker and owner Deployments
   have observed their generation, report a complete rollout, and keep the
   same resource version across two reads a second apart. The role proofs
   still compare exact resource versions. The wait only orders the first
   claim after the controllers' released writes.

The public runtime roles keep ADR-186's order, which puts the fresh proof
before the completion instead. Aligning them is a separate change.

## Consequences

A configuration role takes 83 requests (3.25 s in the fixture). The final
inventory and projection operation takes 85 requests instead of 120. No
deadline is extended, and a change between the post-lock recheck and the
receipt write is caught by the next operation's proof and by the final
inventory verification.
