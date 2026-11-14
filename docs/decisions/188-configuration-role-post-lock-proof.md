# ADR-188 — Configuration role proof after the SQL locks and the bridge

> Superseded (2026-11-13): The configuration role proofs, their post-lock rechecks and the Deployment identity comparisons verified installer-created objects at runtime. Administrators are trusted inside the namespace; the `setup` hook Job creates roles idempotently and components read their configuration under RBAC.

Date: 2026-10-15. Status: superseded by ADR-328 (administrator-only namespaces); the mechanism is removed by the Helm-native installation plan. Formerly accepted; implemented. Native qualification passed
(continuation run 23);
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


## 2026-11-12 correction: Deployment status is not a source change

A fresh all-bundled installation at `f8b7de46` stopped after the acknowledged
worker launch PUT, before its receipt. A retained bounded API watch recovered
five versions of that same Deployment: each had generation2, one replica, the
recorded running Spec digest and identical metadata except resourceVersion and
managedFields. The controller advanced observedGeneration and Ready/Available
status during the original five-second claim. The exact two failing GET versions
were not logged; the historical events establish status-only evolution in that
window. Go1/179.337s and harness1/297.764s remain failed results.

The earlier settling wait does not prevent later legitimate status writes.
[Kubernetes resourceVersion identifies object modifications](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions),
including status. Requiring exact resourceVersion across read-only Deployment
observations was an implementation restriction, not a maintainer product
requirement. Replace it in configuration-role source/native/current/recheck, the worker-input final
bracket and the owner projection/identity comparisons with complete Spec plus metadata
identity, ignoring only resourceVersion, managedFields and Status. UID,
generation, labels, annotations, owner references, finalizers and deletion state
must remain unchanged. Generation retains detection of a spec change and reversal.
Accounts, source/guard/journal objects and their original checks remain unchanged.

Retain the latest validated Deployment and its actual resourceVersion for the
existing launch claim and exact UID/resourceVersion write CAS. This correction
never retries a PUT, adopts a replacement, renews a claim or treats a late reply
as a new operation. Read-only observations retain their earliest original dates.
The failed launch's original claim and absent receipt are not rewritten by tests.

Complexity: one observed fresh installation failure, routine controller behavior,
no added privileges, credentials, network/API calls, watches, background tasks,
configuration or fallback states. One private operation-local Deployment snapshot
and the existing bounded Spec/metadata comparisons replace a raw version string;
there is no global cache. The smaller correction avoids retrying an entire
protected proof or waiting longer for controllers. Rollback is a normal binary
rollback and restores the former availability failure; stored contracts and SQL
schema are unchanged. Focused positive status-only and negative identity/spec/
metadata/generation cases must pass before fresh installed qualification.

The corrected source passed the fresh all-four installed workflow at `15501a6a`
(Go0/616.790s, harness0/746.610s), including launch receipt completion, real public
login, PostgreSQL restart and both original/new artifact expiry/deletion. All
5,009 inventoried source hashes matched and owned cleanup was independently
verified. See the implementation ledger for focused regressions and prior failures.

PR226 review identified the worker-input final bracket as one further occurrence
of the same raw-version comparison. Its correction uses the same helper; the
actual Advance/post-lock/receipt-effect/final/completion component regression
failed before the change0.491s and passed with race detection12.641s, including
refusal of genuine generation/Spec/metadata changes and original-bound checks.
The corrected integrated source `d6cc0ea9` subsequently passed Go0/651.947s and
harness0/789.669s through the complete restart workflow; all5,010 inventoried
source hashes match and owned cleanup is independently verified. Eligible-head
CI is required for that delivery.
