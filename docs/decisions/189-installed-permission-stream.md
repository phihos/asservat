# ADR-189 — Installed permission stream

Date: 2026-10-15. Status: accepted; steps 1–7 implemented and natively qualified
([continuation run 26](../../test/results/adr183-continuation-native-26/result.json)):
a fresh stream with acknowledged initial and epoch audits. Step 8 (retention)
pending; runs 24–25 are retained failures fixed by ADR-191.
Requirements: REQ-AUTH (C-01 permission acceptance), REQ-DB-004, REQ-CAP-004,
S-02; TASK-11.
Builds on ADR-050 (in the [index](README.md)),
[ADR-091](091-protected-configuration-reconciliation.md),
[ADR-141](141-protected-capacity-production.md) and
[ADR-183](183-installer-runtime-continuation.md).

## Context

The SQL `permission_stream` is the only source of ordinary eligibility. The
protected capacity setup also requires it: `InitializeCapacity` records the
stream's root, and the setup and the audit profile reads require the stream
to be fresh with acknowledged initial and epoch audits.

`BindingReconciler` and `AuthorityPublisher` exist and pass real Kubernetes
and SQL tests. No product process runs them:

- No installer applies the permission admission policy or records its pin.
- No product SQL purpose can write the stream. `permission-read` is
  read-only, and only the test fixture role `authority_runtime` writes.
- The hub-worker has no RBAC for `AccessBinding` or `PermissionSource`.
- No provider operation scopes audit object credentials to
  `authority/v1/`.
- The owner selection mints `PermissionRootID`, but nothing creates its
  stream.

ADR-091 places leader-leased configuration reconciliation in the
hub-worker, and the applications catalog lists audit outbox publication under
A-HWORK. Capacity readiness already follows a later projection into the
already launched hub-worker.

## Decision

1. **The hub-worker runs the stream.** A fourth installed child supervises
   `BindingReconciler.Run` and an `AuthorityPublisher` ticker under the
   existing scheduling Lease.
   - It starts when its projection Secret appears, like capacity.
   - `Run` ends on any failure. The child restarts it with a bounded
     backoff that respects the 30-second SQL controller lease, and never
     returns early, because a returning child tears down its siblings.
   - A new epoch suspends the projection, as ADR-050 requires.
2. **Root.** The stream root is the owner selection's `PermissionRootID`.
   The continuation's permission step runs after the selection and before
   capacity initialization, and does not mint a second root.
3. **Guard.** The continuation applies `PermissionAdmission(plan)` and its
   binding, create-only, with the fixed name
   `asservat-<id>-permission-guard`, and records the pin from the
   acknowledged objects.
   - Administrators are the installation administrators.
   - `StatusUsers` is the hub-worker account.
   - Delegations come from the new chart values `permissions.delegations`,
     empty by default.

   Changing the plan later is a new guard revision that fences the stream
   (ADR-050). That procedure is out of scope here.
4. **Probe.** The guard's non-administrator probe is the hub-worker's own
   account, as for the source guards (ADR-092, ADR-094). Its dry-run
   CREATE of an `AccessBinding` must reach the permission guard:
   - RBAC grants `create` on `accessbindings` for that reason alone;
   - the namespace workload guard's existing worker dry-run CREATE
     exception (the capacity probe) also admits `accessbindings`, dry-run
     only, for that exact account.
5. **SQL.** Two hub-worker-only public runtime purposes:
   - `permission-accept` (ordinal 72): the stream, basis, assignment and
     acceptance writes and the `authority_audit` insert used by
     `PermissionStore`;
   - `permission-audit` (ordinal 73): the pending read and the
     acknowledgement used by the publisher.

   Both are provisioned with the other public roles and stay out of the
   hub-api projection, like `capacity` and `capacity-capture`. The
   permission projection carries their logins.
6. **Audit.** The publisher writes `authority/v1/<root>/<event>/record`
   with the hub-worker's audit-only object credential and Transit audit
   key. These are audit roles, never evidence roles.
   - A new provider audit operation is a sibling of the owner
     configuration audit operation, which stays bound to the accepted owner
     configuration. It has its own admission purpose, and one lease admits
     one record.
   - The phase-1 worker recipe asks the operator to scope the audit
     principal to the owner configuration prefix and to the fixed
     `authority/v1/` prefix. The stream root is minted in phase 3, so the
     principal cannot name it. The writer refuses records of any other
     root, and conditional create forbids overwrites.
7. **Initial review.** On an empty installation no review is needed. If
   bindings already exist at the first acceptance, the reconciler waits for
   an administrator-created review ConfigMap with a fixed name. The
   installer never accepts existing bindings on the operator's behalf.
8. **Retention before enablement.** Permission changes and epochs grow the
   outbox and the audit namespace. A finite retention and cleanup policy,
   qualified against the restore horizon, is a separate decision. It must
   pass before Helm or public enablement, not before this installed
   composition runs for qualification.

## Consequences

The public role count grows from 66 to 68, and the hub-worker gains a
permission child, its RBAC and a projection mount. The continuation gains a
permission step (guard, roles, projection) between the owner selection and
capacity initialization. Ordinary eligibility and capacity setup then have a
real, fresh, audited stream.

## Implementation

1. Contracts: `PermissionDeployment`, the projection name, keys and hint.
2. SQL purposes 72 and 73, with grants derived from the permission adapter
   queries, a connection budget and plan tests.
3. Guard installation, pin recording and hub-worker RBAC.
4. The provider audit operation for `authority/v1/<root>/`.
5. The hub-worker child: supervisor, publisher ticker, projection hint.
6. The continuation permission step and its projection.
7. Native qualification: a fresh stream with acknowledged initial and epoch
   audits, and a restart that resumes under a new epoch.
8. The retention ADR and its cleanup.

Revision (2026-10-23): an accepted stream observation is now current for
30 seconds after its own observation, not five (migration 00074, see the
[ADR-200 revision](200-on-demand-capacity-refresh.md#revision-2026-10-23)).
