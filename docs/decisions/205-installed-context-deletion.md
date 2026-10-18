# ADR-205 — Installed context deletion

Date: 2026-10-18. Status: accepted; implementation in progress.
Requirements: S-02 (expiry and deletion in the installed journey); REQ-EVD-006,
REQ-PRV-004, REQ-DEP-003; TASK-03.
Composes [ADR-111](111-positive-context-writer-deletion.md) into the installed
layout. Follows ADR-204 (installed downloads), whose worker configuration
child is the pattern used here.

## Context

ADR-111 implements positive deletion of a context artifact: a cleaner purges
the attempt's evidence objects, records an immutable checkpoint, writes a
signed and encrypted deletion record to the audit bucket, has it acknowledged
by a separate audit login and releases the storage charge with a third login.
Nothing in the installed product runs it:

- no product SQL login holds the cleanup, audit or finalize grants; only the
  test fixture creates them;
- no credential may delete from the evidence bucket: the publisher and the
  download workers read, and the regional writer may only put;
- the installed hub-worker's provider login can seal, open and write audit
  objects, but cannot sign. The deletion signatures accept only an in-process
  Ed25519 key;
- nothing lists attempts whose effective access has ended.

The hub-worker's capture cleanup child cannot host it either: no installer
step produces its projection (it waits for one), and its layout uses static
OpenBao tokens that installed workloads do not have.

An installed capture therefore stays in the evidence bucket after it expires,
and its storage charge is never released.

## Decision

1. **A deletion child in the hub-worker's permission worker.** Like the
   worker configuration child (ADR-204 decision 7), it runs beside the
   permission stream under the hub-worker's scheduling lease, and exists only
   when the permission projection carries the optional `ContextDeletion`
   section. Each sweep advances each due attempt with `privacy.ContextCleaner`;
   a failed or unknown step stays pending for the next sweep, as ADR-111
   requires. A sweep runs every thirty seconds.
2. **Three SQL purposes.** `context-cleanup` (89), `context-cleanup-audit` (90)
   and `context-cleanup-finalize` (91), in the hub-worker compartment, with the
   exact grants of the ADR-111 fixture roles. Their logins ride in the
   permission projection after the worker configuration logins. Each pool has
   one connection.
3. **A due list.** A new query lists, for the permission root, at most sixteen
   attempts with a positive writer completion, not deleted, whose
   `effective_expires_at` has passed and whose deletion lease is absent or
   ended, oldest first. Each scheduling pass fixes its cutoff from database
   time and advances a process-local expiry/attempt cursor after a successful
   page read, including when cleaning every listed attempt fails. A short or
   empty page wraps the next sweep to the oldest candidates. Continuous new
   arrivals cannot extend that pass; shortened or newly eligible rows behind
   the cursor return on the next pass. Otherwise sixteen failed oldest rows
   could permanently hide later expiries. The cursor confers nothing and
   changes no dates: `BeginContextDeletion` still checks the cutoff, the lease
   and recovery under its own locks. A persisted purge awaiting audit remains
   retryable.
4. **Its own evidence credential.** `installer-provider-apply` gains
   `--evidence-delete-credential`: list object versions, list multipart
   uploads and list objects on the evidence bucket's `v1/` prefix, and delete
   object, delete object version and abort multipart upload on `v1/*`. No get
   or put. It is stored only in the immutable Secret
   `asservat-<id>-evidence-delete`, which the hub-worker Pod projects; a
   session token is refused. The child re-reads it for each purge.
5. **Audit record.** The record is sealed and opened with the hub-worker's
   audit Transit key and written with its audit storage credential. The
   hub-worker's audit prefixes gain `context-deletion/v1/<root>/`.
6. **Signing through Transit.** The provider setup creates the Ed25519
   Transit key `asservat-<id>-context-deletion` on the audit mount, and the
   hub-worker's audit-wrap policy gains update on its `sign` path, as ADR-204
   extended the wrap and unwrap policies to the worker configuration key. The
   setup readback records the key's public keys, and the section pins the key,
   its version and those public keys. `jose` gains a remote constructor for
   context deletion signatures, like the operation retirement one. The key
   signs only `asservat-context-deletion+jws` records.
7. **Optional runtime composition in a fresh-install layout.** Without the
   section there is no deletion child, no cleanup login in its permission
   projection, no signing key or signing policy path and no evidence-delete
   credential. Omitting the optional fields preserves the original provider
   selection/configuration bytes. The fixed SQL role inventory and installed
   worker template do change: fresh installations reserve the three purposes
   and optional projected file paths. Their role/template digests change even
   when the child is disabled.
   `installer-continue` fills the section exactly when the publisher is
   installed.

## Options not taken

- **Delete from the publisher.** It would gain list and delete rights beside
  its unwrap authority; ADR-181 and ADR-203 isolate that process.
- **Compose the capture cleanup child first and add deletion to it.** Its
  layout depends on static tokens; installing it is a separate change, and
  deletion does not need its capture operation queue.
- **Share the hub-worker's or another workload's signing key.** No installed
  hub-worker key signs today, and a key for this one record type keeps a
  compromised deletion signer from producing any other signed record.
- **A separate `deletion-sign` provider role.** It would add a login and
  token lifetime to the hub-worker for a path the audit-wrap token, held by
  the same process, can carry; ADR-204 chose the same for its audit key.
- **Share the download workers' or the publisher's evidence credential.** Both
  are read-only by design; deletion needs list and delete, and nothing else.

## Consequences

- An installed capture's evidence objects are removed after its effective
  access ends, with an acknowledged deletion record, and its storage charge
  is released.
- The operator supplies one more storage credential.
- The worst-case SQL connection plan for one hub (two retained hub-worker
  processes during a rollout) rises by six connections, from 101 to 107. An
  installation with deletion needs `max_connections` of at least 110.
- Copies a user downloaded are outside managed deletion, as before.
- Capture operation audit cleanup is still not installed; it remains a
  separate gap.
- Existing installation upgrades and restart with this changed binary are
  unqualified. Resource journals retain their original template digests and
  SQL role pins; the continuation rejects an older pinned template instead of
  rebinding it to this one. This change provides no journal rewrite, workload
  image replacement or upgrade protocol.

## Progress

- **SQL** (#35, unit tests and `sql-check`; the context suite's deletion
  fixture passed on CI run 39113937237): purposes 89–91 with the fixture
  grants, the worst-case plan at 107 connections, and
  `ContextDeletions.DueContextDeletions`.
- **Provider, signing and credential** (#36, unit tests): the optional
  `ContextDeletionSigning` key in the hub-worker's provider selection, the
  audit-wrap `sign` path, the setup readback of every version's public key,
  `jose.NewRemoteContextDeletionSignatures`, and
  `installer-provider-apply --evidence-delete-credential`. *Amended during
  implementation:* the recipe cannot name the permission root, which is
  created after phase 1, so the audit prefix is the fixed
  `context-deletion/v1/`, as `authority/v1/` already is; the writer accepts
  only its own root.
- **Composition** (unit tests; native runs pending). *Amended during
  implementation:*
  - The evidence store ID is chosen at capacity qualification, after the
    permission projection is published, and the hub-worker's phase-1
    inspection token is gone by then. So the permission projection carries
    only a `contextDeletion` flag for the three logins (decision 2), and the
    section (decision 7) rides in the capacity projection, which is
    published after phase 3. The deletion child takes the section and the
    qualification's single evidence store ID from the capacity child once
    that has verified its projection; until then it skips its sweeps.
  - The installer reads the signing key's versions and public keys back with
    the phase-3 inspection token: the owner artifact that lists the evidence
    delete credential also lets that token read this one key. Key IDs are
    `v<version>`.
  - `installer-continue` steps `deletion/credential` (the immutable Secret)
    and `deletion/verify` (the readback) run after `publisher/verify`; the
    hub-worker Pod projects the Secret, optionally, under `evidence-delete/`.
  - Both legacy and provider-backed installed capacity startup hand off the
    immutable section only after the final native projection proof. The
    original startup deadline still applies after waiting for the handoff
    lock. A missing or ambiguous backend qualification refuses startup;
    subsequent capacity restarts cannot replace the store or signing pins.
    The provider-backed path previously omitted this handoff entirely, so
    the deletion child would have waited indefinitely. Unit regressions
    also cover immutable returned pins and cleanup after failed preparation;
    they do not establish installed deletion success.
