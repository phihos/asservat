# Context planning and admission

The named-target preview/request coordinator is being composed under
[ADR-103](../decisions/103-durable-context-previews.md). Its read-only
`postgres.ContextStorageReader` obtains one SQL snapshot of the existing workload
binding, allocation and pool using separate SELECT-only credentials. It retains
the original binding observation, shortens availability at pool/allocation
expiry, rejects paused or wrong-class storage and exposes exact revisions for
later admission. It cannot bind storage or reserve capacity. Current protected
configuration producers and atomic admission remain mandatory; this observation
does not turn fixture-seeded bindings into production authority.

Initial C-03/06/07/09/15/21/24 implementation under I-09, TASK-02/03/05/07/11 and S-01/S-02. It implements part of REQ-EXE-001/002, REQ-PRV-001–003, REQ-CAP-004/005 and REQ-EVD-001–003. It is not a completed investigation service or execution permit.

## Protected plan

`planning.CompileContext` compiles one pinned pod into `builtin-pod-status-v1`: one required on-trigger pod-status action, five seconds, 4096 native bytes. It requires the exact projection definition and qualified capability/image input. General snapshot recipes and unknown projections cannot use it.

Canonical `collection-scope/v1` binds capture, actor/client, workload, exact Pod, execution class, original deadline, recipe, collector image, projection and ceiling digests. The historical node class additionally binds node/boot and requires scheduling. The explicit [Kubernetes API class](api-context-execution.md) permits unscheduled Pods and forbids node authority; protected capability and resolver class must agree. Normalized requested retention and `effectiveRetention` bind each action's purpose, class/type, maximum, deletion budget and every applied policy UID/generation/digest. Authored reason, sharing, result-access, grant handle and idempotency key stay in separate authenticated submission/control records. No acquisition runs during compilation.

The initial compiler permits an original request deadline at most five minutes away. Observation timestamps/resource versions do not become approval identity. `CompiledAt` allows immutable-content verification when looking up a retry after its observations expired; it does not freshen them for new work. A future public preview/accept coordinator must refresh observations and compare the frozen scope before admission.

The schema's `effectiveRetention` extension is additive for historical design fixtures. This implemented compiler always emits it and rejects mismatching canonical bytes. Earlier examples without it are not accepted product execution input. Other compilers must resolve per-action retention too. The dependency limit remains 64; overflow fails with a consolidation diagnostic, never truncated provenance. The `collector` dependency is distinct from a diagnostic runtime pack.

## Retention intersection

The pure privacy resolver requires a complete current policy set for the exact target and exactly one installation baseline. All maxima apply, defaults use the shortest default and deletion reserves the largest required budget inside the shortest maximum. Incompatible purposes or a combined budget leaving no usable interval fail. Duplicate policy/rule identities and excessive inputs fail.

Unknown classification receives potential-personal-data restrictions; stricter known classes also match broader personal-data rules. Generic `other` output matches every type-specific cap. Classification comes from the qualified producer. Every matched policy reference survives resolution. Derived evidence inherits the earliest parent anchor/cutoffs, and an expired parent prevents new usable output. `Tighten` cannot lengthen or resurrect evidence.

[Kubernetes observation and protected-fact matching](retention-observation.md) now exist separately. Source/selector qualification, connected policy propagation, preservation and deletion workers are not implemented by this arithmetic. `RetentionReader` must establish protected selector matching and completeness; a caller-selected policy list cannot supply it.

## Atomic admission

Migration `00004_context_admission.sql` adds protected `context_storage_binding` and immutable `context_capture` records. A binding maps one workload identity to its backed context allocation. The initial reconciliation facet only inserts or refreshes the same mapping/revision. Reassignment, replacement and shrink require future draining. The ordinary capture role cannot alter permission content or binding freshness.

`AdmitContext` locks permission root, storage pool, allocation, binding, then attempt. The root also serializes a hard ceiling of 1024 retained capture records, including historical ones; it does not count only pending captures. Finite metadata/idempotency retirement and fair admission remain required to prevent one workload from exhausting future capture capacity for others (review U13). No remote I/O occurs under these locks. After waits, the transaction reevaluates current SQL permissions/denies, membership/scopes and the complete default audience against a verified identity snapshot. It checks storage ownership, capacity and original plan observations, registers four conservative object obligations and saves independently constructed expected manifest facts atomically. Time is checked again after inserts. Failure rolls back admission and reservation together.

Structured actor/client plus original key identifies retries. Exact replay requires the original authenticated submission digest, capture identity and execution digest. It returns the existing record without recollection, new charges, audience replacement or deadline renewal. A new capture cannot adopt generic custody. Different intent conflicts; unknown COMMIT outcomes require original-key lookup, not a new attempt or refund.

SQL stores minimized control provenance, not native evidence, workload configuration, bearer tokens or evidence keys. Production role composition, finite retirement and restore/configuration fencing remain required. C-21 now explicitly depends on C-06 to verify the exact compiler contract rather than duplicate normalization in SQL glue.

## Pending audit is not execution

Admission creates `accepted_pending_audit`. Migration 00005 adds exact encrypted intent receipts and `intent_audited`. The purpose-specific publisher writes an immutable encrypted `asservat-capture-intent-audit/v1` object, reads/authenticates it against the frozen SQL record and acknowledges the exact version/checksum. Root/capture identity, format and expected plaintext digest are authenticated additional data. Failed writes/verification cannot advance state; retries verify the prior conditional object rather than replace it. Receipt replay is exact and idempotent. Audit acknowledgement may explain an expired/revoked request but never renews its authority.

The next coordinator must recheck current execution authority/fleet identity before fenced dispatch. Neither state enables acquisition, catalog publication, key opening or download. The publisher has a separate SQL role without authority mutation, custody spend or accepted-scope updates. Audit retention/immutability credentials and restoration still need production qualification; fixture permissions do not provide it.

`make custody-integration` passed on 2026-10-10 with real PostgreSQL and encrypted S3 authority audit, including 13 context-admission scenarios: concurrent duplicate requests, complete owner audience, altered target/audience/revision, missing membership, expiry during a pool-lock wait, revocation, wrong storage, isolated exhaustion and generic-custody adoption rejection. Existing authority and custody tests also passed. The fixture uses synthetic identity/policy/target provenance and does not qualify a public workflow or signed dispatch. A subsequent run added encrypted intent failure/retry/acknowledgement and replay after plan-observation expiry (15 context scenarios), again with exit 0 and clean source/fixture reports. Evidence: `test/results/capture-intent-check.log`, `test/results/context-admission-check.log`, `test/results/custody.log` and the source-hashed custody environment report; owned fixtures were removed.

The [final retention effect contract](retention-effects.md) now requires the complete accepted source proof inside the SQL effect transaction. Its real SQL/S3 qualification and repository gates pass; it adds no public approval or policy-source selection step.

The [current recovery fence](download-recovery.md#capture-and-publication-continuation) also gates this effect. Private composition binds the installation to its permission root; lock that recovery row before ordinary permission/storage rows and recheck the original proof after waits. A blocked or changed issuer epoch cannot admit or publish new work. Completed recovery activation remains an independent prerequisite.

The [processing coverage check](processing-admission.md) observes current prepaid
root/rule coverage before preview and new collection. Managed admission repeats
it under the existing permission lock without reserving a future publication
slot or extending requested retention. Historical accepted replay remains passive.
