# Protected configuration reconciliation worker

[ADR-091](../decisions/091-protected-configuration-reconciliation.md) adds the initial `asservat hub-worker` entry point for the A-HWORK application. C-04 owns the two observation loops; C-08 retains owner-configuration audit verification; C-21 supplies native admission, scheduling and scoped storage adapters. Bootstrap composes them. This process has no browser/MCP endpoint, capture mechanism, evidence unwrap key or recovery activation method.

## Installation inputs and privilege boundaries

The command accepts no flags and reads `/run/asservat/hub-worker/deployment.json` under [hub-worker-deployment.schema.json](../../specs/contracts/hub-worker-deployment.schema.json), at most 256 KiB. It names one installation/hub cluster, the exact control namespace, distinct fleet and owner ConfigMaps with UIDs, independently pinned admission plans and one precreated scheduling Lease. Explicit API/PostgreSQL/S3/OpenBao endpoints and public roots follow the [owner deployment](owner-deployment.md) transport rules. Constructors do not accept recovery or configuration merely because those files exist.

| Fixed credential file | Scope |
| --- | --- |
| `sql-fleet.json` | Existing fleet observation role: insert only blocked roots, refresh qualified current settings and fence failed observations. No recovery/epoch/source replacement. |
| `sql-configuration.json` | Existing owner-configuration observer role: monotonic source head, immutable revisions and negative watermarks. No audit acknowledgement. |
| `sql-audit.json` | Exact immutable owner-configuration audit acknowledgement. No source freshness or recovery writes. |
| `kube-observer.token` | Observation client for the exact namespace, two sources and their admission policies/bindings. |
| `kube-probe.token` | Independent non-administrator probe client. Runtime source updates are dry-run only and must be denied by the expected admission rule. |
| `kube-leader.token` | Scheduling client for the exact namespace and named precreated coordination Lease. Scheduling never creates/deletes or writes sources. |
| `audit-storage.json` | Explicit configuration-audit bucket credentials; no evidence bucket grant. |
| `audit-wrap.token`, `audit-unwrap.token` | Separate fixed configuration-audit Transit paths; no certificate issuance or artifact unwrap. |

[ADR-094](../decisions/094-native-hub-worker-projections.md) supplies native Pod-bound projections for all three Kubernetes client files using one process ServiceAccount with the union of those exact permissions. These facets never provided process isolation while their credentials were readable by the same process. Source-policy qualification still requires a non-administrator identity and its exact dry-run denial. SQL and key-service credentials remain separate. API-token audience is the API server default, with a requested 600-second lifetime and no subPath mount.

File shapes, byte ceilings, confinement and current credential reads reuse ADR-090. The three SQL usernames must differ. Connections have the same finite pool bounds and verified TLS; new connections reread passwords while preserving username. HTTP calls reread current projected credentials. No ambient kubeconfig, PG settings, AWS chain, provider token or proxy is accepted. Initial connection construction has a thirty-second bound and closes partial resources on failure. Process-local core suppression occurs before secrets are read.

## Protected sources and observations

Fleet source protection uses the same native ConfigMap guard mechanics as owner configuration with a distinct purpose-specific policy/denial. It checks current namespace and pinned enforcing policy/binding, confirms the probe identity is not an administrator, proves its update RBAC, and requires the exact native admission denial on a dry-run resubmission. Read canonical source content twice and recheck the guard. Preserve the original maximum five-second observation through all I/O. Source names, UIDs or administrator identities never come from developer requests. When these sources share the protected private workload namespace, [ADR-092](../decisions/092-independent-source-admission-probes.md) requires exact installer-owned nonpersistent probe exceptions in that namespace policy. Never accept the namespace denial as proof of the source policy.

`ConfigurationReconciler` independently invokes `TrustObserver.Reconcile` and `OwnerConfigurationObserver.Observe`, each serially with a five-second caller bound and a one-second delay after completion. There is no unbounded retry queue, accumulated work or successful-observation cache. Failed source reads use the existing observer's denial/fencing path. SQL downtime leaves the original expiry in force. Owner audit may complete independently only under its existing historical/current acceptance rules; it cannot refresh time or enable an old head.

Fleet observation still cannot clear RecoveryBlocked. First observation inserts a blocked root. After separately qualified initial/recovery activation, ordinary observations can keep current protected settings fresh. The application never substitutes a periodic SQL timestamp UPDATE for reading the source. Database time is checked after blocking locks. Equal timestamps at PostgreSQL precision cannot extend validity, advance revision or revive a fenced observation.

## Scheduling and shutdown

The client-go leader-elector uses a fifteen-second Lease, ten-second renewal deadline and two-second retry period. A fresh process UUID is the scheduling identity. The adapter permits only exact pinned Lease get/update under the original namespace, preserves resourceVersion and UID during CAS, and refuses create/delete/replacement. A valid empty installation-created Lease can be acquired. Coordinated-election extensions are unsupported. There is no Kubernetes Event writer or configurable remote callback.

The Lease reduces redundant polling; it is not proof of uniqueness or authority. Source/SQL invariants tolerate old and new candidates overlapping. Loss or inability to renew cancels both observation loops; each keeps its original source deadline. The leader wrapper and reconciler cancel and join every started callback before returning. The deployment closes SQL and provider resources only after its active Run has joined. A process supervisor may terminate a stuck process, but a timeout is not successful local shutdown and does not release owned work. A callback scheduled after shutdown cannot begin provider work. No early Lease release precedes joined cleanup. Missing/deleted Lease remains missing rather than being silently re-created. Temporary unavailability during takeover is possible and must be shown by future whole-hub health composition.

## Qualification boundary

Unit tests and native integration evidence are recorded in [implementation progress](../implementation-progress.md). The fixtures create actual protected ConfigMaps/admission rules and scoped roles against real PostgreSQL/S3/OpenBao. ADR-094 adds a separate case running the compiled role in a Restricted Pod through native projected credentials. See implementation progress for the whole-case result and any teardown failures. Initial recovery acceptance remains an explicit fixture administrator transition. Owner pool member identities in this configuration-only test are fixture inputs; actual Pod-to-certificate qualification remains the separate owner suite. No background fixture refresh supplies source freshness in the new worker case.

Still pending: complete installer orchestration, scheduled native token-renewal qualification, initial installation/recovery/restore protocols, checkpoint completeness and independent detection of database restores (a restored unblocked row alone cannot authorize startup), whole-hub health/status, public flows and production scheduling/load qualification. This entry point implements only configuration reconciliation; A-HWORK's other audit/outbox/sharing/lifecycle workloads remain to be composed. The official chart must not advertise a complete hub on the basis of this path.

[ADR-093](../decisions/093-bounded-hub-scheduling-permission.md) composes scheduling with the private workload namespace guard: the installer lists the exact same-namespace scheduling account/Lease pair, allowing only coordination Lease UPDATE. The runtime still has named get/update RBAC and original UID/CAS/record checks. Its native fixture now installs source and namespace policies together and tests forbidden operations, including with broader fixture-only rights that are removed before runtime starts. Do not list the worker as an installation administrator. Actual terminal results are recorded in implementation progress; production installation remains separate from the source-matched in-Pod lifecycle fixture.

The C-21 `BuildHubWorkerWorkload` builder returns an inert zero-replica Restricted Deployment and exact native RBAC. Protected startup inputs and explicit launch remain installation responsibilities. Only fixed keys are projected; no token minting or Secret-read RBAC is granted to the process. The source ConfigMaps cannot alias the startup input. See ADR-094 and implementation progress for native image/projection evidence and remaining installation boundaries.

## Fresh provider-installed runtime candidate

The separate ADR-149 worker2 candidate retains both independent source loops at
actual-call plus one second and all original five-second observation ends. Its
fixed fleet projection wrapper calls the actual PostgreSQL observer, then emits
a scheduling notice only after acknowledged success and a current original end.
Known source change, unavailable reads and unknown writes clear hints and cancel
active work before negative SQL fencing can block. No notice is a recovery
proof, SQL acceptance, provider permission or authority to bypass current reads.

Five fixed purposes share one FIFO: wrap refresh, unwrap refresh, owner audit,
capacity source and cleanup. Each has one ticket, active or pending, five total
and only one globally active. Queue waiting is bounded by the original outer
caller and five seconds. Provider/owner pre-selection source waiting consumes
that same fixed scheduling interval. It waits for an independent acknowledged
source read begun after grant, then caps work at that source's original end.
Exactly one current recovery selection still follows; no selected proof is
refreshed. Capacity retains its already-created observer deadline, and cleanup
obtains its real permit after admission. Active cancellation retains the ticket
until the effect and response owners actually join.

Owner audit chooses a pending observation only after scheduling. A newer
independently observed same-revision notification may replace only an unselected
candidate. The selected observation and semantic audit record remain immutable
through provider/store I/O and acknowledgement. Later source change, failure,
expiry or caller cancellation closes it; unknown writes retain uncertainty and
use the existing exact-version reconciliation protocol on a later independent
operation. No queue result declares an uncertain write absent or refundable.

The explicit B+A resource experiment sets the single existing worker observer
to 40 QPS/burst 20; the other five existing clients stay 20/20. Independent source
readers and all effect readers retain those exact shared client/limiter aliases.
This yields at most 140 QPS/burst 120 per HWORK process and 280 QPS/burst 240 for
the original two retained processes, including closing work. It creates no new
client, route, scope, credential or configurable limiter. Original v1/default
clients remain unchanged. Cluster load must include separately budgeted owner,
installer and regional actors.

The 20-QPS baseline failed with an aged persisted source and remains recorded.
No source/code component result can substitute for actual provider and SQL work,
first encrypted owner audit, uninterrupted capacity readiness and useful cleanup
progress with admitted workload. Normal token maintenance cadence, coincident
refreshes, both source loops and pending hints belong in qualification. The
fresh command candidate stays unselected until its complete original-generated
Pod transition passes; active capacity/cleanup qualification remains separate.

## Failed unchanged fleet persistence

[ADR-155](../decisions/155-unchanged-fleet-persistence-contention.md) preserves the concrete wrapper's any-error invalidation of pending/active scheduling notices. A qualified unchanged-source persistence lock conflict remains an error and supplies no committed notice. Only the observer's additional SQL suspension may be omitted after exact current source/row/incarnation checks under the original bounds; the prior expiry and current recovery checks remain. The next cadence reads independently. The [component package](../../test/results/fleet-persistence-contention-package/component-1/result.json) passes 119 top-level / 605 named race cases, including pending/active scheduling cancellation. The [focused native package](../../test/results/fleet-persistence-contention-package/native-1/result.json) passes all ten SQL cases; this does not establish the full installed worker/owner transition or broad fleet regression. [Integration metadata](../../test/results/fleet-persistence-contention-integration.json) preserves exact source and historical failure provenance.
