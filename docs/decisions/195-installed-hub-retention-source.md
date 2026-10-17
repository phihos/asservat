# ADR-195 — Installed hub retention source

Date: 2026-10-17. Status: accepted; steps 1–4, 5a, 6 and 7 implemented and
natively qualified ([continuation run 8](../../test/results/adr195-continuation-native-8/environment.json)).
The hub retention source becomes Ready with the baseline policy, read
through the hub's `retention-read` login. An administrator's baseline edit
is accepted (sequence 3), and after a hub-worker crash the source returns
to Ready under a new epoch. Step 5b (the lifecycle signer) is deferred to
the capture composition.
Requirements: REQ-PRV-002/004, REQ-DEP-001/003/005, S-02; TASK-11.
Productizes the retention components of ADR-055–057 for the installed hub,
following the permission stream of
[ADR-189](189-installed-permission-stream.md). Precedes the regional catalog
entries of [ADR-193](193-installed-federation-and-regional-enrollment.md)
step 7.

## Context

Every capture admission reads retention through `AcceptedRetentionReader`.
A topology names a mandatory hub retention source, and that source must be
current and accepted in SQL:

- a `retention_source` row with matching hub flag and protection digest,
  a live lease and a fresh observation;
- an acknowledged receipt for each checkpoint, with its catch-up job
  completed;
- an acknowledged receipt for each linked lifecycle decision;
- exactly one baseline policy.

The components that produce these rows exist and were natively qualified,
but only with fixture authority:

- the `EvidenceRetentionPolicy` observation and journal;
- the reconciler with its protected initial review;
- the checkpoints, catch-up and lifecycle publication;
- the retention guard and its probe;
- the topology reader.

The installed product runs none of them. Its role layout has only
`retention-read`, the writer grants exist only as test fixture roles, and
nothing writes a `RetentionTopologySettings` document. So no installed
capture can pass retention, on the hub cluster or any regional one.

The hub-api needs no change for the hub source itself: its capture targets
come only from catalog clusters, and each regional topology names the hub
source.

## Decision

1. **A fifth hub-worker child.** The hub-worker runs, under one 31-second
   restart supervisor like the permission child:
   - the reconciler: its `EvidenceRetentionPolicy` LIST and watch, the
     guard and the source journal;
   - the acceptance publisher (one record per lease);
   - the catch-up pager, run until idle;
   - the lifecycle publisher.

   `BeginRetention` locks `permission_stream`, so the child starts only
   after the permission stream exists.
2. **Four SQL purposes** (ordinals 78–81): `retention-source`,
   `retention-source-audit`, `retention-catchup` and
   `retention-lifecycle-audit`. Their grants are derived from the fixture
   roles and the adapter queries. The unused ordinals 67–69 are not reused.
3. **Audit.** The hub-worker's audit principal also covers
   `retention-acceptance/v1/<root>/` and `lifecycle/v1/<root>/`, under a new
   recipe format (installed v3). Retention records share the authority audit
   admission and operation: the same audit-only principal and material, one
   record per lease, with the leases alternating between the two
   publishers. *Amended during implementation:* the first draft gave
   retention its own admission purpose; checkpoint and lifecycle records are
   rare, so a second ticket class adds nothing.

   The lifecycle audit needs a signing key. The lifecycle writer signs with
   an in-process Ed25519 key, while installed signing elsewhere uses a pinned
   OpenBao Transit key (ADR-062, the hub-api's work signing). Step 5b adds a
   Transit-backed lifecycle signer and the lifecycle publisher. Decisions
   only arise when catch-up shortens retention for existing evidence, so
   until 5b a shortening leaves the source unavailable, which fails closed.
   The JOSE side exists (`NewRemoteLifecycleSignatures`, signing through a
   context-bound Transit signer). The provider side follows the owner's
   public recipe precedent: a separately pinned extension recipe with the
   lifecycle key and its sign role, read back into the retention section.
   It is deferred to the capture composition, because before any installed
   capture exists there is no evidence a decision could shorten, and no
   native run could exercise it.
4. **The guard (D1).** The continuation creates the retention guard after
   the permission step, through the shared `ensureAdmissionGuard`.
   - Administrators: the installation administrators.
   - Status users: one reserved name,
     `system:asservat:retention-status-unused`. No built-in Kubernetes
     authenticator issues it. The retention probe must not be a status user,
     and the hub-worker's probe is its own account, so the ADR-189 choice
     (the hub-worker as status user) is not possible here.
   - Its protection digest is exported, so the continuation and the worker
     compute the same value.
5. **The permission projection carries it (D3).** `PermissionDeployment`
   gains a `Retention` section with the guard pin, and the projection adds
   the four retention logins after the two permission logins.
   *Amended during implementation:* the first draft used a separate
   projection, to keep the permission projection bytes unchanged. That would
   duplicate its journal claim, hint and projection operation (about eleven
   files). Both children run in the same hub-worker process, under the same
   permission root, from the same mount, so a separate projection adds no
   isolation, and nothing has been released that the old bytes would serve.
6. **The initial policy set (D2).** The first acceptance covers an empty
   policy set, which needs no review. Afterwards the continuation, acting as
   administrator, creates the baseline policy from required chart values
   that have no defaults. Without a baseline value it creates none, and
   captures fail closed until the operator applies one. A protected review
   is not used: it expires within an hour, and pinned inside an immutable
   projection it could not be recovered.
7. **RBAC.** The hub-worker gets `get`, `list`, `watch` and `create` on
   `evidenceretentionpolicies`, and `get` on the retention guard. The
   workload guard gets the matching dry-run exception, and the chart's
   continuation ClusterRole the same rules.
8. **Readiness (D5).** The continuation does not wait for Ready. The native
   test asserts that the hub source becomes Ready through a `retention-read`
   login, and returns to Ready after a baseline edit and a restart under a
   new process epoch.
9. **Regional topologies come later.** The owner input pins the hub source
   reference (`Native.RetentionHub`), and each catalog entry pins its
   cluster's topology in a fixed slot. That is part of the catalog-entry
   decision, not this one.

## Consequences

The hub runs one more reconciliation child and holds four more SQL logins.
Captures stay unavailable until the regional catalog entries, regional
capacity and the key service exist. The baseline policy is now an operator
choice the chart must ask for.

## Implementation

Native runs 1–3 are retained failures. All three stopped at
`retention/first-acceptance (deadline)`:

- Run 1 showed no hub-worker cause. The retention child now reports each
  retried epoch with fixed stage and check names, and the test prints the
  worker diagnostics when the continuation fails.
- Run 2 named only `reconciler (unavailable)`. The guard proof and the store
  calls now carry their own check names.
- Run 3 named `guard.dry-run-not-denied`. The test had not installed the
  shipped `EvidenceRetentionPolicy` CRD, so the probe's dry-run create was
  not denied by the guard. The chart ships it; the test now installs it too.
- Run 4 completed the continuation. The test's readiness read used the
  superuser pool, which the product ledger refuses.
- Run 5 used the `retention-read` login without the verified TLS the ledger
  requires; the test now connects through the TLS bridge.
- Run 6 passes (exit 0, no cleanup failures, source unchanged).
- Run 7 added the edit and restart checks. The runner held no right to edit
  the baseline; the chart now grants `update` (never `patch`, by the chart
  rule). The restart stops the hub-worker container on its own kind node,
  because the namespace guard refuses API Pod deletion to everyone but the
  controllers and the kubelet.
- Run 8 passes (exit 0, no cleanup failures, source unchanged).


1. SQL purposes, grants, layout digest and connection budget.
2. Contracts: `RetentionDeployment` in the permission deployment, the
   status user and the guard name.
3. Guard: `EnsureRetentionGuard`, the exported digest, RBAC, the workload
   guard exception and the chart ClusterRole.
4. Audit prefixes, the recipe format and `BeginRetentionAudit`.
5. The hub-worker child: (a) reconciler, acceptance publisher and catch-up
   pager; (b) the Transit-backed lifecycle signer and publisher.
6. Continuation: the guard and projection after the permission step; the
   baseline after the first acceptance.
7. Native qualification of a Ready hub source.
