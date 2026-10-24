# Asservat design and ADR complexity review

Review date: 2026-10-20. Source baseline: `c8fc5460a7b8892e1ddcb817e42138111921c2ee`
plus the existing working-tree changes captured in [the source manifest](source-manifest.json).
This is an evaluation and recommendation, not an amendment to the product contracts.

**The product direction is coherent, but the implementation architecture has accumulated
more security and coordination machinery than its demonstrated benefits justify. The
immediate problem is excessive work on the critical path, compounded by validating
components before checking whether the complete workflow can succeed. Preserve the
product and its substantive protections; simplify the mechanisms before expanding them.**

This conclusion does not mean that all security is speculative or that nothing works.
Installed capture, encryption, verification, publication and authorized case retrieval
have passed. The first complete installed investigation, including native download and
expiry/deletion, has not. Most of the broader diagnostic capabilities remain designed or
partially implemented. The [current implementation status](../../implementation-status.md)
records that distinction without a completion percentage.

## Scope and method

The review covers **all 210 ADRs present in the catalog**: 159 standalone records and
51 inline records. The highest number is ADR-213; numbers 142, 143 and 154 have no
record in the catalog. They are inventory gaps, not three invented decisions or three
unreviewed records. [The inventory](inventory.json) records each source and location.

The governing guide is HAPTIC's
[Rule 5](https://github.com/haproxy-haptic/HAPTIC/blob/0a8fba329ed100c56ef09c05a86e570c4770c0e4/CLAUDE.md#complexity-must-pay-for-itself-rule-5)
and [complexity gate](https://github.com/haproxy-haptic/HAPTIC/blob/0a8fba329ed100c56ef09c05a86e570c4770c0e4/docs/agents/complexity-gate.md),
as adapted in [AGENTS.md](../../../AGENTS.md). The maintainer's latest clarification
explicitly allows relaxed, bounded permission rechecks during downloads. Earlier ADRs
and tests cannot turn stricter timing back into a maintainer requirement.

Each ADR has a disposition, provenance assessment, qualification boundary, answers to
all eleven questions, rationale, action and evidence. The readable evaluations are:

- [ADR-001–095](adr-001-095.md)
- [ADR-096–164](adr-096-164.md)
- [ADR-165–213](adr-165-213.md)
- [Complete disposition index](adr-index.md)

The whole-design assessment also uses the product definition, security trust model,
implementation slices, 24-component catalog, application/interface boundaries, current
source and recorded qualification failures. It is not a line-by-line code audit, a new
penetration test, or a fresh production qualification. “Documented maintainer choice”
means the project records identify a choice as such; this review did not independently
reconstruct every historical conversation. Unknown frequency, overhead and deployment
coverage remain unknown.

**Keep** means the benefit justifies the mechanism at its present level of abstraction.
**Simplify** preserves the outcome while reducing implementation cost. **Defer** changes
implementation order, not accepted first-release scope. **Superseded** identifies a
decision displaced by later choices. **Remove**, if used, is a recommendation to retire
the named machinery, not permission to erase evidence or user requirements. A record
can contain useful and excessive elements; its detailed action takes precedence over
the one-word label.

The dispositions are **76 keep, 121 simplify, 4 defer, 8 superseded and 1 remove**.
The removal recommendation concerns the already withdrawn ADR-209 experiment, not a
requested capability. These counts are not a quality score or 121 separate rewrite
tasks: many records describe successive parts of the same mechanisms, grouped below.

## Findings that determine the next work

### 1. The download fast path has a demonstrated budget contradiction

The focused [policy request measurement](../../../test/results/resumed-c62e02ac-download-policy-budget/README.md)
finds 14 observer requests and three probe requests per complete policy read. A current
download environment evaluates policy twice. The first new-worker preparation path has
ten complete gates: **280 observer requests**. With the configured 20 QPS and a full
burst of 20, the observer requests alone have a **13-second rate-limit lower bound**.
That excludes probes, SQL, object audit, scheduling and competing work. The authority
window is five seconds.

The separate [whole-phase reproduction](../../../test/results/resumed-c62e02ac-download-whole-phase-budget/README.md)
fails after **4.951 seconds**, with **119 observer and 27 probe requests**, before worker
creation. It uses the actual coordinator and Kubernetes policy reader with immediate
synthetic downstream ports. This establishes a composition defect; it does not prove
that every millisecond of the installed failure has the same cause. The installed
[native50 result](../../../test/results/resumed-c62e02ac-native50/result.json) independently
records an unavailable preparation after 4.433 seconds and no emitted native bytes.

The measured repeated reads reconstruct the protected installation `DownloadPolicy`
and its admission guards. Extending a human permission lease alone will not remove
those calls. The fix must explicitly cover the policy observation's lifetime and reuse,
as well as the cadence for checking the user's continuing rights.

**Recommendation:** use one bounded accepted policy observation across the preparation
phase and a periodic check during transfer. Start qualification with a **60-second
permission observation/recheck bound** as a concrete candidate, then retain or adjust it
from complete-path measurements. This number is a proposed engineering starting point,
not a newly accepted requirement or a measured optimum. It is already authorized to
relax this timing; no further product decision is needed to perform that work.

Keep exact target/grant identity, transactional spend and generation checks, explicit
expiry, cancellation, retention cutoff and recovery fencing at their appropriate effect
boundaries. Do not mechanically replace every five-second deadline with 60 seconds:
request cancellation, lock waits, token expiry, object identity and permission-source
freshness describe different risks. An observed denial should still stop work; normal
operation need not repeatedly rediscover unchanged source protection at every helper call.

Measure full preparation and sustained transfer with ordinary background refresh and
concurrent requests at the declared deployment size. A larger timeout alone is not the
complete fix if duplicated work continues to grow with call depth.

[ADR-208](../../decisions/208-context-opening-client-burst.md) shows a related pattern:
separate clients and higher bursts expanded into several 50-QPS/burst-100 client groups
to fit repeated protection reads into the same window. These changes helped named
installed operations, but do not qualify aggregate API pressure. Kubernetes API Priority
and Fairness is a server-side control, not evidence of Asservat's acceptable total load.
Evaluate ADR-197/200/207/208/213 together before adding another limiter exception.

This pattern predates the current download failure. The historical
[ADR-150 counterexample](../../decisions/150-operation-owned-native-observation-proof.md#measured-counterexample)
recorded 118 observer and 30 probe requests before failure at 4.914 seconds.
[ADR-153](../../decisions/153-operation-owned-connector-enrollment.md) then identified
9.8- and 12.6-second observer-only floors for operations constrained to five seconds.
Those records introduced corrections to their respective paths; their old counts are
not measurements of today's implementation. The recurrence in a new path is evidence
that local fixes did not resolve the architecture's aggregate freshness/cost model.

### 2. Credential separation has grown beyond the actual process boundaries

The current fixed inventory contains **87 public-runtime SQL purposes**, including
**52 in the hub's public-purpose list**; separate owner logins are outside that count.
These are credentials, not 87 simultaneously open connections. The existing governor
caps physical connections. [Metrics and extraction scope](design-metrics.json),
[role source](../../../internal/contracts/public_runtime_roles.go),
[compartments](../../../internal/contracts/public_runtime_compartments.go).

[ADR-177](../../decisions/177-hub-sql-connection-governor.md) explicitly acknowledges that
a process compromise exposes all purpose credentials in that process. It also records
TLS/SCRAM setup for cold transactions, serialization within each purpose, and a prohibition
on nested governor acquisition because that can deadlock. Its tests address real faults;
they do not establish that the underlying number of credentials is necessary.

**Recommendation:** retain migration, key, privileged collector, untrusted analyzer,
deletion and evidence-reading privilege boundaries where they actually differ. Some
are separate processes; current deletion runs in hub-worker and this recommendation
does not require another deployment. Within one trusted process, evaluate fewer SQL roles
organized around concrete compromise or query-injection boundaries. Keep narrow methods,
transactions and grants. Compare the benefit of a purpose login against its provisioning,
rotation, connection and recovery cost. A single universal database credential is not the
recommended replacement. Existing `session_user` checks make consolidation a deliberate
schema/credential migration, not a pool setting change.

### 3. Some process splits compensate for earlier machinery

[ADR-170](../../decisions/170-federation-compartment.md) motivates its extra federation
process using the exhausted 32-connection hub budget. ADR-177 subsequently distinguishes
purpose logins from physical connections. The original arithmetic is therefore no longer
sufficient on its own to justify a permanent extra deployment, certificate lifecycle and
projection bundle. Network direction, blast radius or independently measured load may
still justify it.

In contrast, [ADR-181](../../decisions/181-asynchronous-publication-verifier.md) gives the
publisher a concrete boundary: it verifies encrypted artifacts without giving hub-api
unwrap authority or giving the key service evidence-store access. Keep that distinction
while simplifying its internal role/proof plumbing.

**Recommendation:** consolidate deployment units only where the privilege set, trust
boundary and scaling needs permit it. First measure the existing path and remove repeat
checks. Do not make a broad service rewrite a prerequisite for the first usable download.

### 4. Bootstrap and recovery need a smaller operational story

The database-incarnation fence addresses a reproduced stale-authority problem. Replay-safe
provisioning, rejection of foreign objects, credential retirement and an explicit restore
boundary also have concrete value. Their combination with witnesses, pristine-inventory
proofs, staging and final admission proofs, one-use journals, multiple SQL credentials
and handover receipts creates many states an operator must recover from.

The declared [trust model](../../security.md#trust-model) already trusts cluster, KMS and
root-capable infrastructure administrators. Admission guards can still protect against
less privileged writers and accidental mutation; repeating proof of those guards does
not establish integrity against a fully compromised trusted administrator.

**Recommendation:** consolidate bootstrap into one trusted desired-state coordinator
with stable installation identity, bounded replay and clear ownership. Preserve the
database recovery fence and independently retained information needed to avoid restoring
revoked authority. Define and qualify normal restart, failed-install resume, upgrade,
rollback and restore as operator outcomes. An ordinary lossless restart should be
automated under the existing durability contract, rather than requiring another manual
ceremony. This is a staged simplification proposal; deleting journals without mapping
their unknown-outcome behavior would create a real regression.

### 5. Worker ownership and certificate delivery need proportionality

The acquisition/owner series (especially ADR-068–095 and subsequent native routing)
protects real things: exact workload identity, no browser credentials in workers,
short-lived certificates, constrained native evidence access and cancellation. It also
introduces process-owner locators, discovery, multiple proof phases and a live relay
whose lifetime is coupled to delivery of a public certificate.

**Recommendation:** preserve the implemented bounded interruption behavior while
removing repeated source checks that merely reconstruct the same authority. Once the
installed journey works, compare the existing per-download Job design with reuse of a
bounded acquisition reader that still receives an exact per-artifact permit. Keep the
accepted processing location: the first installed profile uses hub-local acquisition;
write-only regional connectors must not gain decrypt authority. Such a reader must not
gain arbitrary evidence/key access or leave plaintext on disk. No performance or security
equivalence has been demonstrated for that alternative;
do not begin another replacement framework before measuring the current implementation.

### 6. Audit and retention guarantees are valuable; their finest granularity is negotiable

Auditing sensitive collection/disclosure, bounding retained control metadata, preserving
deletion obligations, and refusing capacity refunds before cleanup address real product
requirements. Separate durable receipts and narrow acknowledgements are useful at
irreversible external effects. The same rationale does not automatically require a new
pair of encrypted objects, credential set and retirement protocol for every harmless
poll or read-only control operation.

**Recommendation:** distinguish effect audit from routine access/operational events.
Evaluate bounded batches of immutable records for the latter and a shared cleanup lifecycle
for compatible metadata classes. Retain an acknowledged durable intent before sensitive
effects and exact replay/accounting semantics. Preserve finite retention, original
deadlines and honest overdue reporting; do not claim that an inaccessible object has
been deleted. The review makes no legal claim that a particular per-call object scheme
is required. See the detailed ADR-110/112/115 and later lifecycle evaluations.

Immutable audit versions are explicitly documented as a maintainer requirement in
[ADR-149](../../decisions/149-fresh-provider-installed-pair.md) and enforced by
[ADR-151](../../decisions/151-initial-audit-version-requirement.md). Preserve that choice
when changing event granularity or cleanup; it is distinct from one object pair per poll.

The current [ADR-208 audit-reader account](../../decisions/208-context-opening-client-burst.md#extension-after-native-62)
records about 50–70 sequential Kubernetes reads per encrypted operation-audit object,
twice per audited request. This is a concrete example of audit implementation overhead,
not an argument to omit audit.

### 7. Broad accepted scope has been mixed into first-workflow prerequisites

Multi-cluster operation, native files, capture profiles, recurring policies, packet/syscall
recordings, runtime profiles, cores, sharing and local deployment alternatives are
documented product choices. Calling those features unnecessary would silently change
the product. Their complete generalized machinery does not all need to block a bounded
pod-status investigation.

**Recommendation:** use the existing S-02 exit as the immediate delivery boundary,
including two workload clusters, UI/MCP approved content, native bytes and managed-copy
expiry/deletion. Complete optional backend/identity alternatives and later collector
families in the existing slice order. Do not represent this internal milestone as the
entire first release. Prefer extension of one working flow to building more disconnected
foundations for every future mechanism.

There is also disproportionate machinery inside S-02:
[ADR-206](../../decisions/206-bounded-context-projection.md) and its
[capacity contract](../../architecture/context-query-capacity.md) build a separate query
worker/enrollment/audit lifecycle and four deployment-capacity proofs for the bounded
4,096-byte context projection. Evaluate a typed approved-projection operation using the
existing isolated acquisition reader and resource lifecycle, with distinct operation
authorization. That preserves in-product inspection without assuming a second complete
delivery system is necessary. The current contracts forbid that reuse; revising them
requires explicit design work and validation. It is not already an implemented shortcut.

### 8. Verification has been thorough locally and late globally

Native50 took **1,226.986 seconds** and failed before native download. The focused
whole-phase reproduction fails in under seven seconds of recorded wall time. Both have
value, but running the long installed fixture repeatedly to discover call-budget defects
is an expensive feedback loop. Component tests with synthetic current authority do not
exercise the same request volume as the installed authority composition.

**Recommendation:** retain tests for real failure modes, add complete-path request and
deadline accounting to the short composition checks, then run the installed journey for
the stable candidate. Cover successful availability as well as correct denial. Do not
require a new bespoke test for every document edit or repeat unchanged native qualification.
Record usable outcomes as progress; ADR count, source lines and fixture count are not a
delivery metric. There is no evidence here to assign every week of elapsed work to one
cause, but these observations substantiate a major source of wasted iteration.

### 9. Decision records have become a second implementation log

Many later ADRs document legitimate bug corrections, test harness boundaries, exact
startup projections and deployment increments. Preserving that evidence is useful.
Treating every increment as another permanent architectural constraint makes the current
design difficult to discover and raises the cost of revising an agent-authored choice.

**Recommendation:** retain historical ADRs and qualification reports, mark superseded
choices clearly, and maintain one concise current contract per subsystem. Reserve new
ADRs for consequential alternatives such as trust boundaries, persistent formats or
operator-visible lifecycle changes. Put routine corrections in the implementation log.
The complexity gate itself should be a short decision aid, not eleven pages of mandatory
ceremony for every fix.

The current [application catalog](../../architecture/catalog.yaml) also illustrates
documentation drift: it describes `asservat publish` as a Job and has no federation
application, while ADR-181 specifies `asservat publisher` as a Deployment and ADR-170
adds the federation process. Its passing design checker verifies the declared catalog;
it does not prove that the catalog describes every current deployed process. Reconcile
the current overview rather than adding another competing architecture summary.

## Assessment across the complete component design

These recommendations cover the catalog's 24 components. Module boundaries are not
automatically process boundaries. “Later” preserves accepted scope and follows the
[implementation slices](../../architecture/implementation-slices.md).

| Component | Assessment and concrete direction |
| --- | --- |
| C-01 Configuration | Keep Kubernetes as the configuration surface. Simplify repeated live guard proofs into bounded accepted observations; keep protection from unauthorized writers and explicit invalidation. |
| C-02 Identity | Keep standard OIDC/session/CSRF and workload identity. Consolidate lifecycle plumbing; finish one installed provider before qualifying alternatives. |
| C-03 Authorization | Keep current entitlement, exact grants, independent intrusive approval and retained audiences. Separate cheap effect checks from expensive policy-source refresh; use the authorized relaxed download cadence. |
| C-04 Fleet | Keep central multi-cluster and outbound regional connectivity. Reassess owner/federation process and proof multiplicity against actual trust boundaries. |
| C-05 Targets | Keep UID/process pinning and no silent target replacement; these prevent concrete wrong-target effects. Implement only the resolution needed by each qualified mechanism. |
| C-06 Planning | Keep deterministic previews, typed capture profiles and no trial capture. Avoid a generalized planner or plugin language before working profiles require it. |
| C-07 Capacity | Keep shared workload/incident limits and conservative uncertain spend. Simplify the number of reservation/proof layers; qualify combined fairness and throughput rather than each counter in isolation. |
| C-08 Audit | Keep durable effect audit and privacy minimization. Reconsider synchronous per-poll object pairs and separate credentials where no independent boundary is gained. |
| C-09 Capture | Keep one immutable accepted request and replay-safe effects. Consolidate preparation and continuation state; make accepted IDs and outcome recovery usable in UI/MCP. |
| C-10 Monitoring | Necessary for the accepted automatic-collection scope, later than S-02. Keep finite trigger types and bounded coalescing; avoid a generic event engine. |
| C-11 Execution | Keep exact target, cancellation and no duplicate intrusive effect after uncertain replies. Share execution infrastructure without forcing cheap reads through every future intrusive-action mechanism. |
| C-12 Recording | Keep bounded packet/syscall rings and explicit save lifecycle. Defer production implementation until the custody/download path works; avoid unnecessary per-event SQL work. |
| C-13 Live observation | Keep approved projections and transient bounded replay. Later implementation; do not let viewer pause/filters alter capture or invent a durable stream store. |
| C-14 Evidence | Keep framed encryption, native bytes, integrity and independently verified publication. Extend the existing format; do not replace proven cryptography to simplify unrelated orchestration. |
| C-15 Privacy | Keep administrator maxima, inherited cutoffs, deletion accountability and restore protection. Consolidate compatible cleanup state machines and qualify actual removal. |
| C-16 Catalog/history | Keep authorization before visible results/counts and repeat provenance. Begin with the working SQL metadata catalog; add regional payload indexing only for an implemented query need. |
| C-17 Sharing | Keep explicit snapshots, owner teams and independent raw rights. Implement after the basic investigation; do not make every future sharing mode a prerequisite for an unshared context request. |
| C-18 Analysis | Keep isolation of hostile evidence/tools and encrypted scratch. Use native local download immediately; add server analysis per supported tool and purpose. |
| C-19 Delivery | Simplify most urgently: one preparation authority observation plus bounded periodic checks, finite transfer budgets and exact native output. Preserve expiry, interruption and original accounting. |
| C-20 Transports/UI | Keep React/TypeScript, Go assets and a shared UI/MCP service. Prioritize understandable progress, approved content and a successful file download over additional protocol generality. |
| C-21 Persistence adapters | Keep PostgreSQL/Kubernetes/object-store ownership. Reduce same-process role and connection churn where measured safety permits; no new broker or storage system is needed for the current blocker. |
| C-22 Crash helper | Keep the narrow Rust helper boundary for kernel-sensitive work. Qualify later in disposable VMs; no workstation-wide collector is justified by this review. |
| C-23 Mechanism adapters | Reuse maintained diagnostic engines, with explicit compatibility limits. Add one useful mechanism through the complete product flow at a time; unsupported mechanisms should remain unavailable. |
| C-24 Domain types | Keep typed finite contracts and dependency direction. Avoid wrappers, ports or variants that merely mirror a single implementation without a real invariant or replacement need. |

The broad technology choices—Go, PostgreSQL, Kubernetes configuration, object storage,
standard cryptographic/OIDC libraries, React/TypeScript and existing diagnostic engines—
are not the principal source of the current delay. Most excess sits in custom lifecycle
composition around those choices. Wholesale stack replacement would introduce more work.

## All eleven questions applied to the combined design

| Question | Project-level answer |
| --- | --- |
| 1. Observed frequency and impact? | Concrete blockers include installed preparation failure, reproduced authority-budget exhaustion, stale-recovery defects and connection cleanup problems. Production incident frequencies and typical deployment distributions are unknown. Hypothetical compromise paths should not be described as observed attacks. |
| 2. Already accepted risk? | Yes: trusted infrastructure administrators, limits of truth on a compromised collector, irretrievable local copies, and now bounded permission-change handling. Reopening these through stricter incidental mechanisms needs justification. |
| 3. Common deployment coverage? | The blocked download affects the first normal investigation. Multi-cluster is explicitly required, not an optional exotic deployment. HA, large-scale tuning and each optional provider need their own evidence; no measured customer distribution is available. |
| 4. Comparable projects? | Standard agent/gateway, workload identity and modular deployment patterns exist; limited primary-source comparisons are below. They support the broad shape, not the necessity of every custom journal, proof or per-purpose login. |
| 5. Added privilege/exposure? | At least 87 fixed public-runtime SQL purposes plus other credentials, guarded projections, peer issuers and multiple processes. Some isolate real privileges; same-process credential multiplication does not isolate a full process compromise. |
| 6. Failure states? | Many: source stale, guard unavailable, activation blocked, audit pending, uncertain create, owner changed, enrollment pending, spent unwrap, unpublished artifact, overdue deletion. Their aggregate recovery and availability cost is not established by separate negative tests. |
| 7. Knobs for the machinery itself? | Freshness, probe, pool, owner and renewal bounds interact. Prefer a small set of documented behavioral budgets over exposing every internal timer. Keep independent bounds only where their risks differ. |
| 8. External coupling? | Kubernetes admission/controller/token behavior, PostgreSQL identity/connection behavior, KMS/PKI, object-store semantics and TLS are all involved. Qualify one supported reference profile first; do not hide unsupported behavior with fallback authority. |
| 9. Aggregate runtime cost? | Download request volume already violates its original five-second window; 13 seconds is a calculated observer-only lower bound. Full normal-load CPU, memory, network and cluster-scale availability remain unqualified. Credential and file counts are not measurements of overhead. |
| 10. Upgrade/rollback/disable? | Bootstrap and selected cleanup/replay cases have evidence. Supported restart/restore, failover, upgrades and sustained operation remain incomplete. A simplification must include migration/rollback and preserve uncertain spend, rather than only deleting old code. |
| 11. Smaller solution sufficient? | Yes for the immediate blocker: reuse bounded observations and relax permission timing, retaining effect checks. Likely for some role/proof/lifecycle duplication, but those changes need targeted validation. No wholesale rewrite or mandatory new infrastructure is justified by current evidence. |

## Limited comparison with established systems

These are comparisons of mechanisms, not claims that another project provides Asservat's
complete security/product model or that the entire industry has been surveyed.

- OpenTelemetry explicitly associates an added agent-to-gateway tier with central
  processing, network isolation and scale, and describes simpler deployment patterns
  when those needs are absent. This supports requiring a concrete reason for each
  Asservat process split, while its regional network boundary is a valid reason.
  [Official deployment guidance](https://opentelemetry.io/docs/collector/deploy/other/agent-to-gateway/).
- SPIRE implements node/workload attestation and delivers cached workload identities
  through a local API. Workload identity and bounded identity reuse are established
  patterns. That does not prove equivalence to Asservat's evidence grants or justify
  installing SPIRE as another dependency without comparing total cost.
  [Official concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/).
- Pyroscope v2 supports a single-process mode for evaluation/small deployments and
  recommends microservices for production at scale. It demonstrates that modular code
  and physical deployment need not have identical boundaries; it is not evidence that
  a single process satisfies Asservat's privilege or availability requirements.
  [Official v2 deployment modes](https://grafana.com/docs/pyroscope/latest/reference-pyroscope-v2-architecture/deployment-modes/).

## Recommended execution order

1. **Finish the existing installed investigation.** Fix the reproduced permission-source
   budget with bounded reuse and the relaxed cadence. Prove preparation and native
   transfer with ordinary refresh/concurrency, then complete Stop, expiry, deletion and
   approved UI/MCP content. Keep the present process topology for this first correction
   unless a measured blocker requires a narrower change.
2. **Make operation routine.** Qualify normal restart, failed-install resume and one
   supported upgrade/rollback path. Simplify installer transitions as part of that work;
   retain explicit restore protection and demonstrate that the operator can recover.
3. **Reduce the largest demonstrated recurring costs.** Measure per-operation Kubernetes
   requests, SQL connections/handshakes, audit writes and latency. Consolidate same-process
   roles, duplicate proof phases and ordinary audit handling where the comparison supports
   it. Revisit federation placement after the connection/trust model is clear.
4. **Extend a usable product.** Add the next accepted capture/recording/profile feature
   through preview, collection, publication, inspection, native download and deletion.
   Keep broad capabilities in the existing first-release scope; stop counting another
   foundation component as a completed developer outcome.

No new maintainer decision is required to apply the already authorized permission timing
relaxation or to complete S-02. Changes that would remove accepted capabilities or alter
actual privilege/retention guarantees should be presented as specific alternatives with
measured cost and a recommendation, only when the implementation reaches that choice.
This review does not ask for blanket approval of a replacement architecture.

## Verification and limits

Review coverage, source preservation and documentation checks are recorded in
[validation.json](validation.json). The ADR JSON files are the structured source for the
readable appendices. Source hashes distinguish this reviewed working tree from HEAD
alone. Existing implementation edits and their intentionally failing budget reproduction
were preserved; no product runtime or original ADR was changed for this evaluation.

This review cannot establish a new completion percentage, delivery date, production
incident rate, safe maximum deployment scale or the performance of proposed alternatives.
It does establish that the current critical-path complexity has a measurable failure,
that several mechanisms lack demonstrated aggregate benefit, and that the next useful
step is a bounded simplification of the working flow rather than another design expansion.
