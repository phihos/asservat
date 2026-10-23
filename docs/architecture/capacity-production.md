# Protected capacity production

C-07 owns the allocation plan and bounded enrollment coordinator. C-01 supplies
accepted permission/source facts; C-24 supplies immutable value contracts;
C-20 owns private DTOs and adapters. Existing C-08/C-15 lifecycle protocols own
audit/copy spend. A-HWORK supervises the source, root and candidate loops under
its existing protected scheduling Lease. See [ADR-141](../decisions/141-protected-capacity-production.md)
and [REQ-CAP-004 through REQ-CAP-006](../../specs/capacity.md).

## Inputs and authority

The local control reader loads complete pool/policy sets with typed canonical
schemas and original Kubernetes resource versions. A separate native guard
proof precedes SQL source acceptance. Discovery returns candidates only; exact
namespace/workload UID, approved selector labels and ownership are reread before
enrollment. Accepted maintainer assignments identify eligible scopes without
turning a group, candidate or capacity account into collection authority.

Workload candidate pages use one bounded, typed LIST in the selected namespace,
without separate namespace GETs before and after it. The page can contain a
candidate from a replacement namespace with the same name; it cannot establish
namespace identity or authorize enrollment. The later exact workload observation
still checks the original namespace UID and protected labels around its reads,
and the workload UID, ownership and generation independently. This removes two
API calls per candidate page (three calls become one), including empty pages;
it changes no cursor, retry policy, API rate, request deadline, guard or SQL
authority check. The call reduction is an operation count, not a measured
installed latency improvement.

Admission needs a binding refreshed within the last five seconds, and a
discovery pass revisits a workload only once per pass, which takes minutes on a
regional cluster. Under [ADR-200](../decisions/200-on-demand-capacity-refresh.md)
the capture preview and request path records a short refresh demand
(`demand_capacity_refresh`, capture-preview role, ready workloads only) and
waits within its original deadline. The worker's demand lane
(`read_capacity_refresh_demands`, capacity writer) reconciles demanded workloads
back to back through the same guarded path as discovery. A demand names a
workload and confers no authority.

[ADR-213](../decisions/213-storage-readiness-at-consumption.md) carries the
same owned readiness operation from its early hint into final storage
selection. If a valid binding has lost the required one-second margin,
the consumer may wait at the existing 250 ms interval for an independently
refreshed binding with the same selection. One demand attempt and all
original non-storage authority deadlines bound both phases. Changed storage,
invalid observations, errors or expired retained facts stop consumption;
neither the demand nor the wait supplies authority or retries admission.

`capacity-root-setup.json` is a private generated administrator input. It binds
original installation/activation, permission root, public role-root UID/setup,
control namespace/guard, account-key version and a closed qualified backing
description. SQL setup verifies the original ten fixed role receipts, exact
OID/name/provenance/ACLs, current recovery and acknowledged permission root.
Its one irreversible claim and exact paired-root receipt are retained on the
original private role root. Unknown creation is lookup-only; receipt recovery
may verify the same committed pair but cannot create replacements.

`capacity-deployment.json`, `capacity-roles.json` and the account-only key are
private installation-owned A-HWORK inputs, not public API/Helm user settings.
Only original purposes70/71 appear in the capacity SQL compartment. The separate
ordinal34 reader checks its independently pinned original receipt and complete
ACL after locks before returning Normal/Resolution audit profiles. A selected
profile is current input for a new audit operation, never a new policy for an
old persisted intent. Neither a projection filename nor a historical receipt
activates capacity.

The component loader keeps its separate direct-cluster profile. The named
installed loader requires a `localOwner` carrier containing the original
`OwnerConfiguration`, immutable `OwnerDeployment` and source name/UID. The
administrator assembler verifies original resource14 source, resource12 Service,
resource10 Deployment and resource0 account receipts, positive owner projection
and launch, complete guard/activation and actual original public input before
including the carrier in the capacity projection digest. The entire deployment,
including duplicated public provenance and encoded roots, retains the original
256 KiB limit; oversize inputs fail before any Secret effect.

The original source body is installation provenance. Current independently
accepted same-pool revisions may advance while exact source, pool, template,
image, guard and original issuer trust remain compatible. A single operation
requires the same accepted revision through its last response. The carrier
contains no URL override, remote Kubernetes credential or private provider key.

The installed loader opens the optional capacity compartment only after an
exact positive public-journal/Secret receipt and rechecks the original worker
input. It reuses this worker's existing local API observer/probe and its rotating
600-second, dedicated-audience token. The concrete local observation client
uses the original Service on private port9444 with independently derived common
TLS name, actual current SQL registry, Ready endpoint and native workload proof
before reading or sending that token. Its bounded typed request then reaches
the remote cluster's delegated local observer over the separate authenticated
connector observation purpose (ADR144). No hub kubelet is expected to project
a remote service-account token and capacity SQL credentials stay in A-HWORK.

Role70 adds only the existing owner configuration/registration read graph and
immutable-key column UPDATE privileges required for FOR SHARE. It gains no
owner issuance, enrollment insertion or activation effect; role71 stays
unchanged. Its MaxConns1 pool completes those reads before capacity transactions.
The local client owns at most two active conversations and joins them before
SQL/input closure. Existing Lease loss still cancels and joins all children.

Fresh installed worker Role/ClusterRole templates include namespace-scoped
get/list/create on the two capacity CRDs, named reads of deterministic capacity
and processing guards, and get/update of the exact processing source ConfigMap.
RBAC cannot distinguish dry-run: ADR145's exact original namespace branch and
independent capacity/processing guards remain mandatory. There are no capacity
UPDATE/DELETE/status grants, remote credentials or added Secret privileges.
Legacy configuration-only templates keep their original bytes; old retained
Role receipts cannot be adopted as the new installed graph.

The capacity publisher retains the actual completed bridge, original role root
and resource lifetime through its sole CREATE and final receipt. Only a positive
first claim owns CREATE; unknown replies permit exact original lookup only.
The receipt-gated installed path remains unenabled pending combined producer,
role70, authenticated observation and runtime native qualification. Component
SQL and dry-run guard passes do not supply those missing qualifications.

## SQL ownership and phases

Five private tables retain accepted source, pool, cluster, namespace and workload
state. Recovery/permission/source locking precedes parent and child accounting.
Every returned shorter interval narrows the remaining transaction and COMMIT.
The original source observation is not renewed by an RPC result, row lookup,
new leader or configuration receipt.

1. Role70 reserves fixed root funding and then exact workload rows, retaining
   generated account/attempt/allocation identities and charges.
2. Role71 installs only the original capture root/account backing and its
   once-set phase acknowledgement. It cannot publish general readiness.
3. Role70 verifies all original storage, context, control, normal/resolution,
   capture, download, native and Stop backing before publishing Ready.

`capacity_managed_admission_until` is the common managed admission fence.
Early context bindings and paused physical allocations cannot authorize a
legacy consumer before phase3. A failed or uncertain phase keeps all original
charges. Exact committed SQL configuration can continue under a new current
observation with unchanged identities and compatible backing; it does not
repeat an expired permit or any external effect.

Root funding includes fixed rows, accounts and maximum retained records, object
copies, history/backup/WAL and bounded key/configuration work. It is established
before individual enrollment; per-workload creation never revises shared
capture funding. Pool/cluster/namespace checks retain all unused protected
commitments alongside global burst use. Missing funding or malformed inventory
fails the whole root; ordinary incompatible scope configuration stays isolated
when the complete remaining accounting is known.

SQL-produced lifecycle policy cutoffs use UTC RFC3339 JSON with PostgreSQL's
original microsecond precision and no trailing fractional zeroes. This matches
the existing Go time encoding; it changes no instant or original expiry.
Managed capture, processing and current normal/resolution policy projections
use the same encoding at creation and renewal. SQL52 still compares the complete
capture policy exactly. The native stored-policy diagnostic reproduced unequal
JSON despite identical non-time fields and cutoffs; the producer correction's
real SQL boundary matrix is tracked separately from its local vector preflight.

## Renewal and retained history

First admission dates derive from the actual protected root observation inside
the fixed AdmissionSeconds ceiling. Compatible renewal advances configuration
revisions with original attempt/funding identities; role70 cannot rewrite
role71's phase fields. Partial renewal remains unavailable until all phases
agree. Existing sessions use exact closed, digest-bound original control/native
snapshots; effective reads never use a new parent cutoff to fill missing fields.
Private SQL markers are not caller-set GUC authority. Original privacy decisions,
session charges and cleanup identities remain independent.

The current finite configuration counter does not replenish itself. Sustainable
operation requires a bounded cooling-window transition and independently
qualified exact-marker primary/backup coverage. The primary observer's positive
MVCC result alone supplies no complete backup coverage. No configuration charge
is released by elapsed H, configured provider retention, an empty status field
or a synthetic native-fixture qualification.

## Verification scope

The immutable V6 snapshot passed exact migrations1..54 SQLc generation, affected
selected races (73 top-level tests;396 named PASS entries), integration-source
compilation and eight-package vet. It retains actual failing-before evidence for
unbound first configuration dates, expired partial renewal and premature leader
return before callback completion. These are component results, not actual SQL
acceptance or installed authority.

The owned `TestCapacityProducerWithRealPostgres` matrix, including ADR146, passed with 87 named
PASS entries (Go73.917s), unchanged source hashes and clean teardown. It covers
actual administrator setup, separate scoped logins, all three phases, two
workloads, current source/refresh, unknown replies, lock expiry, managed capture
publication and renewal retaining original sessions. Kubernetes witness/guard/
metadata and physical history facts remain synthetic. This does not qualify the
LocalOwner composition above, backend window reuse, sixteen-account worst-case
timing or public runtime enablement. The additional coverage cases exercise
actual purpose15 reads, purpose40 rejection before charges and original
permission-lock expiry. The original positive encrypted publication and session
remain covered; the proposed role70 owner graph below is a separate unrun case.

## Session-specific read projections

Native-read and download-window queries use ordinary SELECT access to the exact
already-locked session and its shared backing. They return the session's original
capacity snapshot, digest, account identity and deadline alongside current shared
counters. The existing closed Go snapshot decoder validates those original bytes;
only the original native policy/date fields and control/audit-write deadlines
replace their renewed parent values. Current charged/reserved counters, residual
retention and overdue state remain unchanged. An absent, damaged or mismatched
managed snapshot cannot fall back to the latest parent. Unmanaged sessions require
absent snapshot and digest and retain their original behavior.

These reads do not execute private SQL trigger validators or add privileges.
SQL effect triggers retain their independent validation, and current authority,
recovery, session locks and post-blocking deadlines remain required. The projection
is historical configuration, not a permit or freshness renewal. The real-service
failure and corrected qualification are recorded in implementation progress.

Migration 55 retains migration 54's complete native-key trigger and distinguishes
its original-session variable from the current response-session table alias.
The previous collision caused PostgreSQL SQLSTATE 42702 on an otherwise valid
native key INSERT. All generation, scope, current-window, authority and original
capacity checks remain unchanged; the runtime schema head advances to 55 without
rewriting migration 54 or stored sessions. Real transfer qualification is recorded
in implementation progress.

## Original-installation query extension

[Shared query capacity](context-query-capacity.md), under ADR-219, adds a closed
original setup extension and one immutable logical residual reservation. Existing
root and workload publication transactions accept it; the separate query source
observer and four-deployment requirement are removed. Queries and downloads use
the actual installed acquisition/hub/key/provider limits with distinct authority
and charged query history. Base totals stay exact, each plan binds the exact
workload and current accepted worker profile, and renewal/expiry/restart never
replenish the original query budget. Installed qualification is recorded separately.
