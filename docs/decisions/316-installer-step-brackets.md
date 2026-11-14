# ADR-316: Installer step brackets

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded (2026-11-13): The brackets reduced repeated handover, root and
> owner-identity proofs between installer continuation steps. ADR-328 removes
> those proofs and the continuation Pod. Helm renders the runtime objects and
> the `setup` hook Job provisions SQL roles idempotently under plain RBAC.

Status: superseded by ADR-328 (administrator-only namespaces); the mechanism is removed by the Helm-native installation plan.
Previously: accepted (agent decision under the maintainer's 2026-10-20 proportionality
rule and the merged [test runtime plan](../reviews/test-runtime-plan-2026-11-08.md),
option 4). Generalized [ADR-315](315-batched-initial-schema.md) beyond the
schema phase and amended decisions 3 and 4 of
[ADR-186](186-operation-scoped-public-role-proof.md) and the per-step proofs of
the runtime resource producer.

## Context

After the schema batch, the installer continuation Pod still took about 181 s
per installed CI job and per real first installation. Per-step Kubernetes
request counts (now printed after each `installer continuation: <step> done`
line; `continuation-manual-logs` run 42482871889 at `34436e2b`, before this change):

| Step | Time | Requests | Repeated proof |
| --- | ---: | ---: | --- |
| `resources/advance` | 26.2 s | 3154 | five full handover proofs (`currentPhase`, about 33 requests each) per item, 19 items |
| `owner/installation` | 22.3 s | 2452 | one native preflight, one post-lock current scope and one final bracket per operation, 26 operations |
| `public/roles-provision` | 26.3 s | 1405 | three full root proofs (about 27 requests each) per role, 43 roles |
| `owner/selection-complete` | 4.2 s | 493 | |
| `capacity/initialize` | 6.9 s | 360 | kubelet projection refresh, not proofs |
| `worker/roles-provision` | 3.4 s | 339 | |
| `bridge/settle` | 9.0 s | low | Deployment controller backoff, not proofs |

No limiter waits were recorded: the requests are sequential round trips of
about 8 ms, so the time is the count. The proofs repeated between the items
of one step check the same protected root, guards, administrator,
configuration and journal that the previous proof just checked.

## Decision

An installer step whose items are independent fixed effects under the same
protected root runs them in **brackets** (`fleet.Bracket`):

1. one opening proof with its original deadline (at most five seconds, never
   renewed);
2. items in order, each with its own effect checks, claims, CAS writes,
   independent lookups and deadlines, while at least the reserve (2 s) of the
   opening proof remains; the first item always runs, as under the former
   per-item proof;
3. one closing proof after the last item that did work. A failed closing
   proof fails the step exactly as a failed per-item trailing proof did.

A failed item ends the bracket without a closing proof; its uncertain-result
rules are unchanged and the next bracket resumes at the recorded state.

Converted steps:

- **Runtime resources** (`InitialRuntimeResources.Advance`): the opening
  proof is `currentPhase` plus the journal read; claim and receipt CAS writes
  use that phase-0 proof (`writeProved`) instead of proving twice more; the
  proofs before CREATE and after the lookup are dropped. Each claim's `Until`
  is still the opening proof's deadline, at most five seconds after its
  claim. Lookup-only replay of an unacknowledged claim, the independent GET,
  the template verification, the re-read before the receipt and the CAS on
  the journal Secret are unchanged.
- **Public runtime roles** (`PublicRuntimeSQLRoles.Provision`): one
  `WithPublicRoleOperation` per bracket of roles instead of per role. The
  completion no longer proves before and after its write inside an operation
  (ADR-186 decision 3 and the last point of 4); the bracket ends with
  `ClosePublicRoleOperation`. Each role keeps its own SQL transaction with
  the recovery `FOR SHARE` and advisory locks, the SQL trust check, the
  independent root read, the fresh SCRAM login and the original claim
  deadline.

Dropped: the full proofs between items of one bracket. A revoked
administrator, changed guard or changed configuration is now noticed at the
bracket's closing proof, at most one opening proof (five seconds) later,
instead of before the next item. The work done in that window is the fixed,
compiled inert objects or roles that the opening proof authorized; the next
bracket and every later step still fail closed. Journal changes by anyone
else are still rejected by the per-item CAS writes and re-reads.

- **Owner installation** (`ProviderOwnerInstallation.Run`, amended
  2026-11-08 below): the driver runs its fixed sequence as one operation per
  step: open the role journal, each role phase, the role verification, each
  projection execution with its finalization, each launch execution with its
  finalization. The opening proof is one complete
  `readOwnerIdentityOperationNative` (handover proof with the phase-two
  guard, source guards and independent probes, administrator, owner account
  and Service, accepted configuration, role journal); the bracket's deadline
  is the earliest of that call, the handover proof, the source observation
  and its fleet administration. Inside a bracket the operations' native
  preflight, post-lock scope, SQL-callback current and final reads become
  the bracket read: bridge journal, resource journal between two
  phase-policy reads with its fixed inventory, owner Deployment, accepted
  configuration (re-read, it bounds that operation) and role journal. The
  resource journal may differ from the opening proof only in the owner
  identity and launch claims. Each operation keeps its SQL bridge lock, role
  and projection claims, CAS writes, child-object reads, provider
  observation, finalization, unknown-result inspection and deadlines. The
  closing proof is another complete native read, compared with the opening
  proof's originals.
  The launch, which starts the owner workload and is the one effect here
  that is not an inert object or role, always opens its own bracket, so a
  complete proof directly precedes it.

`capacity/initialize` and `bridge/settle` wait for the kubelet and the
Deployment controller and are outside this rule.

## Complexity checklist

1. Problem: every first installation and every installed CI job (36 per full
   dispatch), about 50 s each; not hypothetical.
2. Maintainer-accepted risk: none reopened; the protected root, the
   five-second original deadline and every effect check are kept.
3. Typical deployments: yes, every first installation.
4. Precedent: ADR-315 for migrations; ADR-186 already scoped one proof to one
   role operation; Goose, Flyway and Liquibase apply many changes under one
   lock acquisition.
5. Privileges, credentials, network access: none added.
6. New failure states: none; a bracket that runs out of reserve ends early
   and the caller's existing loop opens the next one.
7. Configuration: none; the reserve is a constant.
8. External dependencies: none new.
9. Cost: Kubernetes requests of the two converted steps fall from 4559 to
   473 per installation (measured below); no new watch, memory or SQL cost.
10. Upgrades and rollback: no persisted format changes; a journal written by
    either version is read by the other, and resume is per item as before.
11. Smaller fix: caching the proof result across items is the same change
    without an explicit closing proof; keeping per-item proofs costs about
    50 s per installation for no protected invariant.

## Qualification

`fleet.Bracket` unit tests cover a short lease (stops at the reserve and
resumes with later brackets), the first item below the reserve, a lost
closing proof, a failed item without closing proof and an expired opening
proof. `TestPublicRoleBracketProvesOncePerBracket` runs four roles under one
bracket within two proofs' requests and fails a bracket whose closing proof
is lost to a revoked administrator, keeping its exact receipts.

Installed `continuation-manual-logs`, before (run 42482871889) and after
(run 42483849394, `6b41158c`):

| Step | Before | After |
| --- | ---: | ---: |
| `resources/advance` | 26.2 s, 3154 requests, 95 proofs | 1.4 s, 160 requests, 2 proofs (one bracket) |
| `public/roles-provision` | 26.3 s, 1405 requests, 129 proofs | 4.7 s, 313 requests, 4 proofs (two brackets) |
| Continuation Pod steps (sum) | 145 s | 92 s |
| Go test (start to end) | 507 s | 454 s |

The "before" Go test time is the passing ADR-315 run 42481403687 (same step
timings); run 42482871889 failed later in the focus at the known
`preview_capture` readiness tail that PR #185 addresses.

The remaining largest step is `owner/installation` (22.3 s, 2452 requests).
Further installed results are in [implementation progress](../implementation-progress.md).
