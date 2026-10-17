# ADR-192 — Capacity readiness before download paths

Date: 2026-10-15. Status: accepted; steps 1–3 implemented and natively qualified
([continuation run 43](../../test/results/adr183-continuation-native-43/result.json):
capacity root `ReadyAt` set). Runs 35–42 are retained failures, listed below.
Requirements: REQ-CAP-004–006, REQ-DLD-003, REQ-DEP-003, S-02; TASK-11.
Amends [ADR-190](190-capacity-readiness-and-promoted-owner.md) decision 5 and
its consequence on download paths.

## Context

ADR-190 published the capacity projection after the owner launch and noted
that `CapacityDeployment.Processing.Paths` references worker configuration
revisions. A path is protected placement: target cluster, evidence store,
acquisition and connector clusters, hub cluster, and the worker and hub
configuration revisions. Tracing what one installed path needs showed:

- **The acquisition cluster is the connector cluster.** `DownloadPath.Valid`
  requires `ConnectorClusterID == AcquisitionClusterID`. The worker's
  `worker.json` v2 names the connector's native worker endpoint. The
  installed layout deploys no connector yet; that is regional provisioning.
- **Real downloads need the v2 worker.** The native runtime requires a store
  credential Secret, so `worker.json` v2 needs the evidence store (endpoint,
  bucket, server roots, a read credential) and the artifact key service.
  None of these has an installed producer.
- **No production server answers the worker.** Nothing serves
  `WorkerEnrollmentPath` (the handler is imported only by tests) or the
  connector's `NativeWorkerPath`.
- **The worker namespace cannot be the hub namespace.** The worker
  configuration source must share the workers' namespace, and the owner
  workload guard denies the hub-api's Job create and delete in the hub
  namespace.
- **No product observer accepts worker configuration.**
  `WorkerConfigurationObserver` has no product caller or SQL purpose. The
  hub-api would fail its five-second freshness check.

Separately, the capacity setup's claim binds the setup input's digest. The
qualification mints fresh UUIDs and uses the current time for `ValidUntil`.
A continuation replay after a committed claim therefore builds a different
input, fails the claim comparison, and can never complete.

## Decision

1. **Capacity identities come from the public role setup.**
   - Every installer-minted capacity identity derives from the role setup's
     operation ID and a fixed label (a SHA-256-based UUID). Examples are the
     qualification, store, policy and processing-epoch identities.
   - The setup time is the role setup's `CreatedAt`. It is earlier than any
     capacity step, so the capture root still stays closed until the reserve
     phase.
   - A replay rebuilds the identical input and recovers the committed claim.
     These identities are not secrets. The role setup operation is unique per
     installation attempt.
2. **Capacity becomes ready with zero download paths.**
   - The capacity processing source and the hub-api's download environment
     accept an empty set of installed paths. Pinned paths can only narrow a
     source, so an empty set makes every download resolve no path, and it
     fails closed.
   - Capture, the audit lanes and processing state no longer wait for a
     download path.
3. **Download paths are part of regional provisioning.** The first path
   comes with the connector installation in its acquisition cluster. It
   needs:
   - a dedicated worker namespace holding the source;
   - the account, PriorityClass, immutable control ConfigMap and store
     Secret;
   - hub-worker acceptance through `WorkerConfigurationObserver`, with new
     purposes and an audit prefix `download-worker-configuration/v1/<installation>/`;
   - the owner serving enrollment;
   - the evidence store and key service inputs.

   That ADR also decides how a path joins after the first launch. Paths are
   pinned in immutable inputs today. Either path acceptance moves to runtime
   verification of each referenced revision, as ADR-185 did for clusters,
   or adding a path requires a new owner input.

## Consequences

Capacity readiness (ADR-190 steps 7 and 8) can be completed and qualified
now. Downloads remain unavailable in the installed layout until regional
provisioning adds a path.

The duplicate download environment sources stay as they are, each with its
own guard: the hub-api's `-download-environment` and capacity's
`-processing-source`. When paths are added, both must carry the same
settings.

## Implementation

1. Derived identities and setup time in `buildCapacityQualification`, with a
   replay test.
2. Accept an empty installed path set in the processing source constructor
   and the capacity inputs.
3. ADR-190 step 7: the capacity projection after the launch, under the
   ADR-191 bracket; the hub-worker publishes `ReadyAt`.
4. Native qualification: `ReadyAt` set and audit profiles readable.

## Qualification findings

- [Run 35](../../test/results/adr183-continuation-native-35/result.json) and
  [run 37](../../test/results/adr183-continuation-native-37/result.json): the
  launched owner exited at `provider-prime`.
  - `Prime` ended the process on the first failed provider-slot refresh.
  - Each refresh runs the owner's current proof twice within five seconds.
    That now overlaps the continuation's post-launch Kubernetes reads.
  - **Fix:** `Prime` waits for the slot's own backoff (1 s, 2 s, 4 s, ...)
    inside its original 30-second bound. A refusal without new backoff
    stays final.
- [Run 36](../../test/results/adr183-continuation-native-36/result.json):
  the capacity projection was published, but the workload did not reach
  `ReadyAt`, and the hub-worker gave no stop detail.
  - **Fix:** the hub-worker now prints the stopped child, the stage and the
    error class.
  - The native test dumps Pod restarts, the logs and the capacity workload
    phases.
- [Run 40](../../test/results/adr183-continuation-native-40/result.json):
  the hub-worker stopped at `capacity/open/deployment/control`.
  - The capacity deployment named the hub-worker as a status user of the
    capacity guard, but the guard was created with none. The rebuilt
    admission plan therefore missed the pin.
  - **Fix:** the deployment carries the installed plan. Namespace keys are
    sorted once.
- [Run 41](../../test/results/adr183-continuation-native-41/result.json) and
  run 35: the owner launch finalization failed once at `final-native`.
  - A new projection controller cannot continue an already claimed launch,
    so the attempt is terminal by design.
  - The code now carries the failure class and elapsed time. This failure
    stays an open reliability item.
- [Run 42](../../test/results/adr183-continuation-native-42/result.json):
  the test waited on `capacity_workload`. That table stays empty without
  labelled application workloads; `ReadyAt` lives in the source's root
  configuration.
