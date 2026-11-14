# ADR-141 — Protected capacity production and managed renewal

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded in part by ADR-328 (2026-11-13): CRD-status-versus-source-protection checks, guard authority, installer receipts/journals, the installer verifier and denial-probe RBAC defended against writers in Asservat namespaces or served the installer Pod; they no longer apply. Budget derivation, purpose-separated capacity credentials, SQL accounting and managed renewal remain valid.

Status: accepted implementation direction; actual SQL54 component matrix passed.
Installed projection/local-observation composition and multi-cluster runtime
qualification remain pending. This decision enables no runtime or public route.

Automatically enroll exact workloads from accepted permission scopes and the
administrator's protected `EvidenceStoragePool`/`EvidenceBudgetPolicy` inputs.
Derive pool, cluster, namespace and workload budgets from the same complete
plan. Shared burst is serialized globally; unused protected commitments are
never lent. A caller cannot choose an account or use CRD status as input. Backend/history
qualification is installation configuration, not an assurance string accepted
from a workload administrator.

Migration 00054 adds bounded retained source and enrollment state to existing
custody machinery. The `setup` Job initializes the paired capacity/capture roots
for the current database incarnation. It cannot adopt existing unrelated roots. Runtime uses two separate purpose credentials: capacity
ordinal70 reserves and publishes; capacity-capture ordinal71 provides the
SQL52 capture backing. Neither may impersonate the other's phase. Original
ordinal34 is a separate read-only accepted audit-profile credential.

The original implementation made a spent setup claim lookup-only even when its
first SQL transaction had never committed. This was an agent-authored one-shot
restriction, not a separate maintainer requirement. The retained `f9412540`
installer failure had an immutable unacknowledged claim with 1.763939 seconds
remaining at creation and neither paired row; subsequent attempts could never
finish. The exact first postclaim failure was not retained, so this does not
establish which loaded operation consumed that interval.

A later invocation may finish the first atomic pair under fresh role,
permission and recovery authority only when the original exact claim has
no acknowledged receipt and both rows remain absent under the existing locks.
The claim's identifiers, input digest, database incarnation and timestamps stay
unchanged and supply no fresh authority. A committed pair is exact lookup-only;
half-pairs, foreign state and missing roots after an acknowledged receipt remain
refused. Runtime projection still requires the receipt. This adds no schema,
role, provider request, timer, retry loop or configuration: it uses the existing
bounded invocation, locks, two atomic INSERTs and post-blocking/commit checks.

Fund the root once from a fixed compiled plan covering all permitted accounts,
records, system objects, SQL/history, backup/WAL copies, key attempts and bounded
configuration work. Enrollment does not resize the shared capture pool. Keep
one exact normal-lane lifecycle shared with processing and public operation
audit. Stable account identities derive from the original account-only HMAC
seed; capacity receives no audit input key or user-selected account.

Reserve, capture backing and publication are three purpose-separated phases.
Physical child rows remain paused until final publication verifies every exact
prepaid row under current source, permission and recovery locks. All managed
storage/admission readers consume the same Ready fence. A lookup or an early
physical binding is not readiness. Unknown replies preserve identifiers and
charges; the next invocation first reads exact committed state.

A new independently current observation may continue compatible committed SQL
configuration after the first phase expires. It is not a replay of the old
permit. Preserve first observation/deadline, identifiers, original debits and
once-set phase facts. Incompatible inputs remain unavailable; corrupt or unknown
root accounting stops root effects. One incompatible scope alone need not block
other completely accounted compatible scopes.

Managed renewal changes admission configuration dates only. Every previously
issued session retains its original policy digest, dates, counters, native and
Stop limits in a closed snapshot. Missing/malformed managed snapshots never fall
back to current parent cutoffs. Private transaction markers, inaccessible to
scoped runtime roles, distinguish these transitions from arbitrary SQL updates.
Locks and commit checks retain the earliest original caller/source/recovery
deadline, at most five seconds. Legacy rows are not silently promoted.

The existing A-HWORK application owns serial capacity reconciliation beside
configuration reconciliation. One desired worker and two retained processes
bound rollout/closing work; each purpose uses MaxConns1 and SQL LIMIT3. Lease loss cancels and joins every child
before resources close. Scheduling is not authority. The provisional sixteen
account S02 envelope requires measured worst-case lock qualification; it is not
a universal workload limit or measured safe operating size.

Finite configuration charges remain consumed. Sustainable window reuse needs
positive exact-marker primary and backup history coverage, retaining rollover
transaction identity and post-commit settlement evidence. Configured retention,
wall-clock expiry, a fixture fact or successful VACUUM alone cannot refund it.
The complete provider and managed processing date branch remain follow-up work.

Private source/setup/worker contracts and verification boundaries are documented
in [protected capacity production](../architecture/capacity-production.md).
Remote cluster observation requires a concrete authenticated local-producer
path; static remote service-account token files are not an installed solution.
No capacity credentials enter hub-api, collector or a public request.

The installed capacity configuration is Helm-rendered and read by fixed name. It uses the
existing fixed private observation listener and local kubelet token after current
owner authentication, not remote service-account files or a public-listener
startup dependency. The original source revision establishes provenance while
compatible independently accepted same-pool revisions may advance; every request
holds its exact revision through delivery. Role70 receives only the existing
owner registry read/lock graph, never owner issuance or activation. Worker RBAC grants only fixed source reads. Combined installed native
qualification remains mandatory before selecting this composition.
