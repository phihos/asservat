# Full design and workflow review

Reviewed 2026-10-09. This is a whole-repository design review with tabletop simulations and offline contract checks, not a working-product test. The source brief remains unchanged. The [walkthroughs](use-case-walkthroughs.md) trace likely user journeys and failure cases; canonical requirements remain in specs/.

The architecture remains suitable: Kubernetes configuration, PostgreSQL transactional hub state, regional encrypted evidence and bounded local execution. The largest problems were at the boundaries between these parts: which replica gets observed, what exactly approval binds, what an agent can do without manual identifiers, and whether every retained copy obeys its deadline. The changes below repair those design gaps without claiming integration feasibility has been demonstrated.

## Consequential decisions incorporated

The maintainer selected all authorized replicas within administrator observation limits, with independent capture fanout limits; administrator-configurable finite policy approval periods; and whole-pod configuration, permission and filtering, with internal container/process attribution only. Follow-up process selection supports reload-safe executable/runtime selectors and bounded multi-process dumps. See ADR-026–029 and REQ-ACT-008. No new runtime service or container ACL subsystem was added.

## Ranked findings and fixes

P0 means a privilege/privacy invariant could be implemented incorrectly. P1 means a main incident journey could fail or a control contract was incomplete. P2 means avoidable friction or a misleading capability claim. “Fixed” means corrected in the design/contracts; runtime verification remains pending.

| ID | Severity | Defect and practical consequence | Fix / verification reference | State |
| --- | --- | --- | --- | --- |
| F01 | P1 | The basic policy watched at most three healthy/oldest replicas. A failing fourth replica could be invisible, and observation maxPods also limited collection. | Separate all-replica observation from one-contributor capture; retain unready pods and report capped coverage. REQ-TGT-005; UC-02/03. | Fixed; user accepted |
| F02 | P0 | The same capture grant shape required a policy digest even for a manual request, and did not bind a capture UID. A permissive implementation could replay it across requests. | Distinct policy/capture/artifact targets and one accepted capture identity. REQ-EXE-001; schema rejection and UC-05. | Fixed |
| F03 | P1 | Grant references and sharing were hashed into the collection spec. Renewal or a recipient edit could invalidate the very approval being attached. | Submission, execution and sharing digests; late audited matching-grant binding and explicit invalidation rules. UC-06. | Fixed |
| F04 | P1 | selectedPID had no PID/start identity fields. Worker pools and reloads also had no usable logical dump selector. | Exact identities plus executable/runtime/descendant selectors resolved at dispatch; bounded serial batches and individual start accounting. REQ-ACT-007/008; UC-07/08. | Fixed |
| F05 | P0 | Container-level permission/packet/localhost claims did not match shared pod networking. PID 1 could be the sandbox in a shared process namespace. | Whole-pod public scope; runtime identity kept internally, no host-wide fallback; exec inheritance cannot expand partial-container rights. Pod/process manifest variants. REQ-TGT-006; UC-04/09. | Fixed; user accepted simplification |
| F06 | P1 | An agent could submit an expanded capture, but had no target/recipe discovery, preview, capture polling or cancellation tools. It needed human-supplied hashes and had no clear progress path. | Five bounded tools plus request-by-preview, actionable approval links, idempotent status/cancel. REQ-MCP-005; UC-10. | Fixed |
| F07 | P1 | Compound triggers did not define event versus level behavior, initial true, recovery, or cross-replica correlation. Different implementations could dump the wrong pod or never fire after activation. | Pod evaluation keys, explicit workload correlation, three-valued logic, event windows/count/sequence and initial/rearm semantics. REQ-TRG-007; UC-11. | Fixed |
| F08 | P1 | Schedule catch-up/DST handling and file readiness were unspecified; the contract accepted sizeAbove without a size. | No schedule catch-up, stable slot identity, explicit zone/DST behavior; require size threshold; stable file size is not completeness. UC-12/13. | Fixed |
| F09 | P0 | A 16 MiB raw ring capped retained bytes but not terabytes of sensitive traffic inspected before a trigger. Grant action counters did not represent observation. | Finite sensitive observation sessions, cumulative wire-byte/rate/concurrency budgets and prepaid counters before processing. REQ-AUT-006; UC-14. | Fixed |
| F10 | P1 | Zero-history packet collection was unrepresentable; positive before/after were mandatory. Generic packet maxima also disagreed with the frozen-output schema. | before/after may be 0s, at least one positive; explicit staging ring, completion margin and 256 MiB portable frozen maximum. UC-15. | Fixed |
| F11 | P1 | Treating time since last watch event as freshness could stop quiet captures constantly; trusting a quiet socket indefinitely could preserve stale membership. | Independent bounded progress/revalidation, explicit synchronization-loss cutoff and measured API load. REQ-NET-006; UC-16. | Fixed contract; adapter qualification required |
| F12 | P0 | “Finite SQL backup retention” did not bound total lifetime. A day-90 row delete plus seven-day backup retention permits 97 days. | Absolute deadline arithmetic includes maximum residual backup/WAL horizon and cleanup margin; incompatible profiles fail admission. REQ-PRV-008; UC-19. | Fixed |
| F13 | P0 | Filtering expired search hits did not define deletion of index segments, snapshots or obsolete records. | Initial bounded memory index; optional independently expiring durable cohorts, no general evidence-text backup, destructive rebuild on early erasure. REQ-PRV-008; UC-19. | Fixed; storage/overhead qualification required |
| F14 | P1 | Capture-level AwaitingApproval conflicted with the promise to collect cheap context promptly, especially when required intrusive work waited. | Per-action waiting, immediate independent context, original deadlines and explicit Partial outcomes; no replay of context on approval. REQ-EXE-002; UC-05. | Fixed |
| F15 | P1 | Exact OCI image staging was treated as sufficient for an executable that could come from a mount/writable layer or disappear before analysis. | Capture build/mapping identity early; approved bounded companion bundles, exact-symbol retention and mismatch status. REQ-EVD-007; UC-20. | Fixed contract; runtime pack tests required |
| F16 | P2 | Seven-day policy renewal could create repetitive administrator/approver work for unchanged stable policies. | Configurable finite validity, reviewable renewal, unchanged short execution permits; sharing lifetime stays independent. UC-06. | Fixed; user accepted |
| F17 | P1 | Offline checks accepted cross-namespace captures, manual-only Pod policy targets, impossible temporal windows and inconsistent process/frozen budgets. | Stronger semantic/schema negatives, explicit collection-scope examples, atomic grant-counter arithmetic. No claim that Python validates Go regex or live authorization. | Fixed offline checks |
| F18 | P2 | A read-only installation report claimed to verify deletion; expired baselines and missing symbols lacked sufficiently concrete recovery guidance. | Separate configured/inspected/actively verified states; explicit synthetic qualification and analysis-only/new-baseline remedies. UC-01/20/21. | Fixed |

Four defects were reproduced before editing using the prior schemas and semantic checker: selectedPID without identity, a cross-namespace capture, an ad hoc grant with policy-only scope, and a recurring direct-Pod target. They are now regression negatives. Other findings came from specification cross-reading and primary-source reasoning; no failing runtime reproduction is claimed.

## Primary evidence behind the difficult boundaries

Kubernetes documents that containers in a pod share its network namespace, IP and ports. That supports the chosen pod boundary; it does not prove which process serves a named port or isolate hostNetwork traffic. [Kubernetes network model](https://kubernetes.io/docs/concepts/services-networking/).

Shared process namespaces change PID 1: it can be the pod sandbox. Runtime/cgroup identity is needed to locate the actual processes; fixed PID selection alone cannot express a worker pool across reloads. [Kubernetes process-namespace example](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/).

Kubernetes does not promise a watch bookmark at a fixed interval, or any bookmark at all. Our requirement for a separate bounded progress mechanism is an engineering inference; its load and failure behavior must be measured. [API watch bookmarks](https://kubernetes.io/docs/reference/using-api/api-concepts/#watch-bookmarks).

PostgreSQL PITR reconstructs previous state from base backups and WAL. A live DELETE therefore cannot erase every older copy. The absolute-horizon equation is our retention design, not a PostgreSQL automatic feature or legal retention prescription. [PostgreSQL 18 PITR](https://www.postgresql.org/docs/18/continuous-archiving.html).

Bleve's persister handles deleted-document sets and segment merging/removal. That is not evidence of immediate byte removal on a search deletion, so the design uses whole-cache/cohort lifetime controls. [Bleve persister source](https://github.com/blevesearch/bleve/blob/master/index/scorch/persister.go). The GDPR-related controls and limits remain grounded in the [privacy research](../research/privacy-retention.md); no certification is claimed.

Kubernetes CronJobs explicitly discuss time zones, missed schedules and duplicate/missed execution. Asservat uses its own bounded scheduler contract; no catch-up dumps and DST deduplication are product choices, not inherited guarantees. [Kubernetes CronJob behavior](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/).

Executable links can refer to a deleted file; process-exit and mount/writable-layer changes limit later reconstruction. Capturing verified mapping identity and an explicitly approved companion is our mitigation, not a promise that an image supplies all runtime bytes. [Linux proc_pid_exe](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html).

## Remaining risks and deliberate tradeoffs

| Area | What remains unresolved or deliberately limited | Gate / next evidence |
| --- | --- | --- |
| Privileged data plane | Pod scope simplifies the public model but does not prove cgroup attribution, file confinement, runtime exec or host-namespace safety. | EXP-01/04/16; unsupported actions stay unavailable |
| Live packet membership | A seamless healthy map swap and five-second uncertain-membership cutoff need a qualified adapter/CNI profile. Bookmarks alone cannot provide it. | EXP-02, API-load and packet-gap measurements |
| HTTP privacy | Bounded HTTP/1 parsing must prove body/credential exclusion under malformed and fragmented streams; TLS/HTTP2 plaintext remain unavailable. | EXP-03; no raw fallback |
| Fail-closed outages | Long policy approval does not enable hours of disconnected capture: short source/permit leases still expire. This is intentional revocation behavior. | EXP-11/16; show stale/expired coverage |
| Backup compatibility | Very short metadata deadlines may be incompatible with desired PITR/replay horizons or long approvals. No silent retention exception. | EXP-18 and installation RetentionConflict preview |
| Search resource cost | Memory indexes/expiry cohorts can require frequent rebuilds. Structured catalog remains useful during rebuild; supported text capacity needs measurement. | EXP-11/18 and bounded-cache workload test |
| Multi-process consistency | Sequential dumps have different timestamps. This release does not promise an atomic process-group snapshot; batches may be refused by ordinary dump quotas. | EXP-05/19; explicit batch sizing |
| Symbol availability | Build IDs and exact images may still be insufficient for optimized/JIT/corrupt state. Approved companion capture can be unavailable after process loss. | EXP-06/07/15; precise partial analysis |
| Sharing handover | Multiple owners work without creator membership; new historical audiences still require explicit transfer/share. Transfer must retain original registration/budget lineage. | EXP-12; replacement-state migration/query contracts |
| Legal retention exception | Disabled is the current default. Optional reviewed exceptions remain proposed and unapproved; no requirement depends on enabling them. | Maintainer/operator decision before advertising the optional mode |
| Comprehensive release scope | Core handling, grant/audit/retention, network parser and multi-cluster recovery are substantial independent engineering efforts. A spec is not a delivery-time estimate. | Existing ordered TASK-01–11; no scope silently removed |

## Document coverage

All normative capability documents and checked-in contracts/examples were reviewed together, including the newly added execution scope. The offline gate traverses every registered schema/example and requirement mapping; it does not prove every prose invariant. Coverage groups below avoid pretending every historical research statement was rebenchmarked or every dependency reaudited.

| Files / group | Review focus |
| --- | --- |
| AGENTS.md, README.md, docs/product.md | Accepted decisions, scope, public claims and entry points |
| docs/architecture.md, technology.md, operations.md, security.md | Privilege/dependency boundaries, state authority, sizing, failures and retained copies |
| docs/decisions/README.md, docs/implementation-plan.md | Superseded choices, accepted new choices, implementation ordering and pending gates |
| docs/specification-format.md, specs/README.md, specs/traceability.yaml, specs/examples.yaml | Canonical source, agent context, requirement/scenario/task coverage and registered fixtures |
| specs/targets.md, triggers.md, actions.md, profiles.md, packets.md, execution.md | Pod/process identity, observation/capture separation, temporal semantics, bounded action feasibility |
| specs/authorization.md, permissions.md, ergonomics.md, mcp.md | Default audience, automation, grant matching, multi-owner/future sharing and complete user/agent journeys |
| specs/evidence.md, privacy.md, capacity.md, persistence.md, federation.md, apis.md | Lifecycle/accounting/recovery, privacy maxima, single authority and cross-service state machines |
| docs/ergonomics-review.md, docs/validation.md | Existing friction register, measurable UX goals and missing adversarial cases |
| docs/research/findings.md, kubeshark-comparison.md, packet-capture-flexibility.md | Scope/feasibility claims versus explicit qualification limitations |
| docs/research/permission-automation.md, privacy-retention.md, capacity-isolation.md | Primary evidence for inherited authority, retention, physical versus logical capacity |
| specs/changes/postgresql-hub-state/proposal.md | Accepted SQL migration of design authority; no deployed migration claimed |
| docs/research/original-brief.md | Historical requirements/conflicts; preserved verbatim against Downloads source |
| docs/research/dependency-license-snapshot.json | Historical candidate/license metadata consistency, not a new transitive dependency audit |
| specs/contracts/*, examples/*, scripts/check-specs.py, Makefile, requirements-spec.txt | Public shapes, representative valid/invalid data, digest/lineage/budget invariants and actual offline gate |
| docs/research/spec-validation.txt | Prior/current gate evidence; historical counts are not overwritten |

## Handoff

Implement the corrected contracts in the existing TASK packages after maintainer plan review. Start with identity/scope normalization, pod attribution and admission/accounting before enabling intrusive collection. The added [validation matrix](../validation.md#full-review-regression-matrix) names the runtime experiments needed for each change. The actual current offline result is recorded in [spec-validation.txt](../research/spec-validation.txt); no runtime gate has run.

## Guided-selection follow-up

The user identified a further product gap: low-level flexibility still required maintainers to know what to collect and how to set process/packet bounds. [REQ-GDE-001–006](../../specs/guidance.md) add deterministic goal-oriented recommendations, finite discovery, qualified attribution and sizing, and equal MCP/browser access. Important design constraints retained: pure previews, ordinary acquisition/approval and quotas, evidence-derived cache expiry, whole-pod permissions and explicit uncertainty. Added UC-24–26 are tabletop paths, not runtime validation. EXP-20 remains a release prerequisite for the affected classifiers and recommendations.

## Capture-history follow-up

The user requested reuse of previous capture configurations for the same selectors. [REQ-HIS-001–004](../../specs/capture-history.md) add selector-scoped history, immutable private parameter snapshots, explicit new-request repeat semantics and browser/MCP access. UC-27/28 cover rollout, version drift, idempotency, sharing and expiry. The follow-up keeps history retention distinct from evidence/parameter retention and avoids hidden grant or quota reuse; runtime and task-effort qualification remains outstanding.

## Reusable capture-profile follow-up

Integrated REQ-CPR-001–005 and REQ-SYS-001–003 at design/contract level. Addressed risks include publisher privilege inheritance, catalog shadowing/version drift, nested-template execution, hidden duplicate acquisitions, combined quota overspend, stale history dependencies, payload-bearing syscall metadata and raw query/share gaps. Added typed contracts, synthetic catalog/composition/MCP examples and fixture-level rejection/expansion checks. The [walkthroughs](use-case-walkthroughs.md) and EXP-21/22 define remaining runtime, admission, overhead and usability evidence; these have not run. This does not change the original F01–F18 implementation status.

## Action lifecycle follow-up

Corrected the ambiguous single incident-DAG model: ongoing packet/syscall sources now arm before incidents, with separate session readiness/authority/capacity and snapshot dispatch. Contracts reject unsupported ongoing kinds, history on future-only actions and incident dependencies on source startup. Catalog/preview/history expose the categories; crash interception, runtime-retained logs/counters and finite manual sessions are distinguished. REQ-LIF-001–005 and UC-32/33 cover the change; the runtime acceptance matrix remains NOT RUN.

## Impact and data-handling follow-up

Integrated [REQ-ASM-001–005](../../specs/capture-assessment.md), strict preview/artifact notice contracts, examples and negative validation cases. Addressed misleading per-action-only cost, one-incident-pod versus many-observation-pods accounting, limits mislabeled as predictions, pprof/full-heap confusion, stale repeat verdicts, transient versus retained data, expiry mislabeled as deletion and implicit claims of external-agent erasure. Numeric quantities identify coverage/exclusions and shared views cannot reveal hidden-parent notices. Corrected the existing pod manifest fixture's liveCore evidence type from context to coreDump. UC-34/35 are tabletop checks; overhead accuracy, runtime admission and participant comprehension remain pending under EXP-17/18/19/21/22.

## Final review follow-up

The [final correctness review](final-review.md) records further findings, contract regressions, new walkthroughs and the pending analysis-storage prerequisite decision. Earlier fixes remain design corrections; none imply runtime experiments have passed.

## Subsequent missed finding: local tool completion

The maintainer found that a core developer workflow was excluded by the original raw-file rule. This review did not challenge it and did not test the final local-tool outcome. [The correction](local-investigation.md) adds native downloads for every evidence type under REQ-DLD-001–004 and distinguishes static consistency from usable task completion. Prior review coverage is not evidence this workflow was evaluated.
