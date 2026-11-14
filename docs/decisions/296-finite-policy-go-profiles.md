# ADR-296: finite policy-triggered Go endpoint profiles

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Status: implemented and qualified for the bounded 10-second CPU policy workflow in PR154;
other native mode/negative qualification remains open.

## Context

REQ-PRF-001/002/004 and S-05 increment 6 require a team policy to start a
bounded Go endpoint profile when its detector fires. ADR-287 implemented the
manual path. Reusing its concrete Pod/endpoint digest as recurring authority
would reject ordinary replacement replicas or invite a fabricated future Pod.
The existing policy compiler, approval, trigger, quota and profile executor can
provide this workflow without another execution engine.

## Decision

1. Accept one finite, onTrigger, uncredentialed Go endpoint profile per policy
   occurrence. Support every currently supported finite Go mode and its existing
   duration, forced-GC, prerequisite, timeout and native-byte limits. Runtime
   traces remain native trace evidence, never pprof summaries/comparisons. No
   pre-trigger profile history, continuous sampler or new schedule is implied.
2. Keep capture-profile catalog provenance in the existing `Profile` field.
   A separate optional `ProfileEndpoint` binds the protected public endpoint
   definition, its existing definition digest, source name/kind and selected
   binding/address mode. A named-port binding retains its name and definition
   port range; an administrator profile retains its fixed port. Freeze no Pod,
   IP, node, resolved numeric named port, endpoint digest or observation time in
   this recurring configuration. Reuse the existing pure catalog selection and
   definition canonicalization. A bounded definition query uses the existing
   regional standby exchange and accepted workload/namespace identity; it does
   not dial an endpoint, read credentials or select a future Pod.
3. Definition/configuration changes require fresh policy acceptance and review.
   Each occurrence resolves the original triggering Pod through the ordinary
   profile preview/request path. Its concrete endpoint must match the approved
   stable definition and binding. The child freezes its own exact endpoint and
   preserves all original deadlines; start revalidates that endpoint as before.
4. Require an independently approved raw policy collection grant, carrying
   `policyCollection` and `liveProfile`, regardless of the optional approval
   setting for ordinary recordings. Present the exact profile parameters and
   stable endpoint scope to the reviewer, with no fictitious concrete endpoint.
   These endpoint profiles have no packet/user-memory observation allocation.
   The existing finite execution and maximum native-byte pools are charged
   atomically with the capture, custody and profile-stream reservations.
5. At child admission, hash-check and decode the full stored accepted grant
   scope, then match the reviewed endpoint definition, action and recipe to the
   concrete child. A recipe digest alone does not bind protected endpoint
   configuration. Keep this check inside the existing authority/quota
   transaction; it adds no external read under locks. Preserve the installation's
   optional `recordingApproval` marker in the frozen child scope, but normalize
   only that marker when comparing collection actions: the profile already
   requires independent raw/liveProfile approval under either setting. No other
   sensitive reason or acquisition field is ignored. Pin the original grant
   through later effects, including after another grant is attached. Failed
   admissions leave no capture/custody residue; uncertain starts stay spent.
6. Reuse the existing ordinary API execution preparation, profile dispatch,
   node exclusion, encrypted streaming, independent publication, Stop and native
   download. The trigger's request interval bounds admission and enqueueing;
   the original admitted action deadline bounds acquisition. Do not reuse the
   packet/syscall observation lease or add renewal machinery. Collection
   approval grants no human raw inspection: a later exact-artifact raw approval
   is still required for policy evidence download.

This extends ADR-287's manual-only implementation boundary, retaining its
profile acquisition/cancellation guarantees. Legacy packet/syscall grants and
configuration bytes are unchanged.

## Complexity and cost

1. Missing policy profiles are an observed product gap, not a hypothetical fault.
2. The maintainer already accepted finite policy profiles and bounded approval.
3. The change serves ordinary automatic incident capture.
4. Reuse Asservat's existing recurring packet/syscall pipeline and Go acquisition;
   no new profiler service or independent policy executor is justified.
5. Added privileges/credentials/listeners/watches: **0**.
6. New execution/fallback states: **0**; existing refused/busy/uncertain outcomes.
7. New user tuning settings: **0**.
8. External dependencies: existing Kubernetes/Go endpoint/SQL/object/key services.
9. At most **1 bounded regional definition query per profile compilation**,
   independent of replica count; current protected configuration is already
   loaded. Each incident retains the existing exact-Pod reads, **1 endpoint GET**,
   **1 native upload**, and pre-existing publication/download work. No background
   process or additional observation budget; memory/native ceilings are unchanged.
10. Disabling/revoking uses existing policy/grant controls; old manual and
    packet/syscall paths remain compatible. Rollback cannot recreate spent pools.
11. Documenting a manual-only limit cannot meet the accepted automatic workflow;
    extending the existing path is smaller than another scheduler or engine.

## Validation

Focused compiler/pin/mode tests, shared browser/MCP review schemas, atomic real-SQL
policy admission/spend and existing profile execution checks precede one fresh
owned disposable-VM workflow: operator configuration, independent policy
collection approval, real restart, native profile publication, separate human
raw approval and exact-byte native download opened by pprof. SQL readback is
verification only, never an authority producer. Source inventory and terminal
cleanup are required. Full S-05 completion is not claimed.

The successful qualification is native run 41771221394 on af33be56 (merged PR154,
main f003deb0 with identical tree): Go exit 0 in 549.808s, all 4,085 source hashes matched,
unchanged sources, empty cleanup failures and removed scratch. Its scoped results
and remaining gaps are recorded in [implementation progress](../implementation-progress.md).
