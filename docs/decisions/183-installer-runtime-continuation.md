# ADR-183 — Installer runtime continuation

Date: 2026-10-15. Status: accepted; implemented. Native qualification passed
([run 10](../../test/results/adr183-continuation-native-10/result.json));
replay after the guard bridge remains open.
Requirements: REQ-DEP-001/003/005, S-02; TASK-11.
Builds on [ADR-149](149-fresh-provider-installed-pair.md) and
[ADR-182](182-installed-owner-promotion.md).

## Context

The product installer stops after first activation. Every step from the
activation to running hub-worker and hub-api exists only as product
adapters driven by native tests:

- the 19 runtime resources and the guard bridge;
- the configuration SQL roles and worker inputs with their launch;
- owner selection, projection and launch.

Each of those tests uses the test's own cluster-admin user, the fixture
superuser and a synthetic OpenBao root token. The resource journal ends 30
minutes after its creation. The provider recipes need identities that the run
itself creates: account UIDs, the owner source UID and the accepted pool.
ADR-149 keeps external IAM operator-owned. The product emits exact,
automation-ready recipes and only inspects the provider. Administrative
provider credentials never reach a runtime.

## Decision

1. **An in-cluster continuation Pod.** `asservat installer-continue` runs as a
   fixed-name Restricted Pod under the chart's bootstrap runner ServiceAccount.
   That account is the only Kubernetes administrator the installed guards
   admit. The chart grants it the extra runtime resource RBAC for this step.
   Its inputs are:
   - the operator's superuser `postgres-administrator.json` Secret, the same
     operator-owned original the bootstrap used;
   - public provider selections and the owner plan, as chart values.

   It never receives provider administration credentials.
2. **Phases with an outbox and an inbox.** The continuation runs the existing
   adapters in the native order:

   | Phase | Steps | Waits for |
   | --- | --- | --- |
   | 1 | resources, bridge, configuration documents | — |
   | 2 | configuration roles, worker inputs, worker launch | worker recipe |
   | 3 | owner selection | — |
   | 4 | owner projection and launch | owner recipe |

   - **Outbox.** Before each wait, it publishes the exact recipe it needs to
     a fixed public outbox ConfigMap. The recipe holds no credential.
   - **Inbox.** The operator applies the recipe and writes the result to a
     fixed inbox Secret: a short-lived provider inspection token and the
     scoped audit storage credential.
   - **Verification.** The continuation inspects the provider through the
     existing `SetupReader` before publishing or launching anything.

   Everything stays inside the original 30-minute journal end. A lapse ends
   the attempt exactly as today. Unknown outcomes keep lookup-only behavior,
   and no producer restarts.
3. **A product applier on the operator's side.** `asservat
   installer-provider-apply` runs on the operator's workstation with the
   operator's own OpenBao and S3 administration. It:
   - reads the outbox;
   - creates exactly the recipe's mounts, roles, policies and storage scope,
     with create-only, compare-after-write semantics and no upsert of
     foreign objects;
   - mints the inspection token;
   - writes the inbox.

   This keeps administration credentials outside the cluster and keeps the
   workflow low-effort and scriptable within the window.
4. **Later layers.** The public runtime roles, the backend and public
   projections (ADR-182) and the remaining runtime producers are later phases
   of the same continuation. They are added with their producers.

## Implementation refinements

Recorded with the first implementation (2026-10-15):

- **Release namespace.** The outbox ConfigMap and the inbox Secret live in
  the chart's release namespace. The installation namespace guard admits
  only the runner, so an operator cannot write there.
- **Outbox payload.** The outbox carries the product's existing setup
  artifacts:
  - phase 1: the installed worker2 artifact
    (`ConfigurationProviderPairSetupArtifact`);
  - phase 3: the owner artifact (`OwnerProviderSetupArtifact`).

  Each lists exact apply requests, the named inspection paths and the audit
  storage requirements.
- **Applier scope.** The applier creates only ACL policies, auth roles and
  PKI roles. It refuses any other path before writing, never overwrites an
  existing object, and leaves exactness to the continuation's own named
  readback. It then installs a read-only inspection policy over the
  artifact's paths and mints a ten-minute non-renewable token.
- **Storage credential.** S3 principals differ per backend (AWS IAM, the
  SeaweedFS IAM subset, MinIO administration). The applier therefore takes
  the operator's scoped credential file rather than creating the principal,
  in line with ADR-149. The artifact states the exact prefix, operations and
  denials. The continuation fills the original empty audit Secret only while
  it is empty; an exact-content replay is accepted.
- **Continuation Pod.** Its `produce` init container re-projects the
  preparer inputs from passive history. The continuation reads Kubernetes
  tokens from its own kubelet-rotated projection, not from the one-time copy.
- **Runner RBAC.** A separate continuation ClusterRole, bound only when the
  continuation is enabled, adds:
  - the runtime objects it creates and launches: Deployments, Services and
    Leases;
  - exactly the rules of the runtime Roles it creates: ReplicaSet get,
    EndpointSlice list, Lease update and the two capacity resources.

  RBAC admits a created Role only when its creator holds every rule, so the
  runner needs neither `escalate` nor `bind`. Probe tokens act as the
  runtime accounts and need no runner rule.
- **Role operation budget.** One configuration role operation proves the
  guarded source three times inside its original five seconds at the
  unchanged 20 QPS. In-cluster SQL through the provider proxy can overrun
  it after the role exists. The continuation replays `Provision` for at
  most one minute: a non-fresh claim verifies the existing role and never
  recreates it. The bridge steps likewise repeat for at most 30 seconds
  while the API applies each policy.
- **Diagnostics.** A stop names the fixed step, any fixed provisioning
  sub-step with timings, and an error class. Progress lines give step
  durations. Neither carries provider, SQL or Kubernetes text.
- **Inbox lifetime.** Each phase deletes its consumed inbox. A rerun needs a
  fresh apply, because the inspection token expires.

## Open: replay after the guard bridge

Resolved by [ADR-187](187-replay-after-guard-bridge.md).

The guard bridge advances the workload guard by two generations. The
preparer's handover check pins the original generation, so every later
`ReadHandover` reports a change. This affects:

- the passive `initial-bootstrap` completion check;
- a continuation rerun, because the resource producer's constructor reads
  the handover too.

Until the handover readers accept the bridge's retained guard (the existing
`currentHandoverWithFinal` alternate, bounded to two generations), neither
the bootstrap hook nor the continuation can replay after the bridge. A
`helm upgrade` would stop at the bootstrap hook. The first continuation run
reads the original installer input once, from the resource producer that
verified it before the bridge.

## Consequences

An installation now needs one more operator command per provider wait, or
the operator's own automation driving the applier. Operators without
automation must complete each wait within the remaining journal time, so the
applier is designed to finish in seconds. The chart's runner account gains
runtime-resource RBAC for the continuation only.

## Implementation

1. **Command:** `installer-continue` phases 1–4 over the existing adapters,
   with the outbox and inbox contracts.
2. **Applier:** the `installer-provider-apply` command.
3. **Chart:** the continuation Pod template, RBAC and values.
4. **Qualification:** a native run from a completed bootstrap to a running
   worker and owner, with only product commands and the applier.
