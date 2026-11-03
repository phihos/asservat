# S-05 increment 3 implementation plan

Continues ADR-285 on branch `feature/s05-profile-acquisition`. [ADR-287](../decisions/287-go-profile-acquisition.md) records the acquisition contract. This is an active plan, not
qualification evidence.

## Scope and ownership

- Typed accepted Go endpoint plan, one action and immutable endpoint definition,
  exact target and original admitted bounds. No packet placeholder parameters.
- Dedicated node work/result kinds; existing authenticated connector/node
  transport and queues. One attempt, one target; uncertain work stays charged.
- Reuse `diagnostics.GoProfileCollector` HTTP/guard behavior through an explicit
  native-stream result API. Nodes hold no artifact keys; the connector's existing
  prepared writer encrypts native output before evidence storage. A native result
  never fabricates an encrypted layout or publication verdict.
- Exact target network namespace dialer, no redirects, DNS fallback or replacement
  Pod, and no new node privileges. Uncredentialed endpoint templates first;
  credentialed endpoints remain the separately planned increment 4.
- Context admission/SQL/start/publication and raw approval children, truthful
  profile readiness, and actual profile producer/semantic verifier composition.
- Real node collector and installed profile workflow qualification after the local
  candidate passes; no privileged collector executes on this workstation.

Root owns the independent multi-frame native-download follow-up (ADR-288),
including native transport, transfer limits and SQL windows. This branch changes
profile served-type eligibility only when runtime composition is complete; final
qualification integrates the download branch. It does not change the existing
packet output caps or the 8 MiB storage frame size.

## Complexity assessment

1. Observed gap: zero installed profile captures; frequency unmeasured.
2. Yes, Go profiles are required first-release scope.
3. Yes, Go workload diagnosis is the supported initial runtime use case.
4. Existing pprof component and S-05 researched endpoint approach are reused.
5. Zero added collector privileges/credentials; connector already owns wrapping.
6. Existing unavailable/busy/expired/uncertain outcomes, no fallback state.
7. No new machinery-tuning setting; endpoint definitions are product input.
8. Kubernetes, existing regional transport and the application's pprof handler.
9. One node work item, one HTTP GET, one capture holder and one prepared artifact
   per capture; node response reservation up to128MiB within existing256MiB aggregate,
   connector working reservation32MiB shared with other holders. No remote multipart
   journal: immutable one-use local state avoids up to38 control RPCs, with durable
   final+temporary charges retained until quiescent complete-prefix cleanup. Measure aggregate
   memory and end-to-end time before claiming supported output sizes.
10. Unknown work kinds fail closed; disabling capability prevents new starts;
    old in-flight attempts retain their original bounds and cleanup accounting.
11. Reuse the acquisition/producer path; no separate profiling service or database.

## Validation order

Failing focused tests, domain/application/transport race tests, repository
pre-push gates, affected real SQL/storage suites with frozen sources, then
owned native collector and installed capture/approval/download/local-tool tests.
Record actual exits, source hashes and cleanup. No component pass completes S-05.

## Stop lifecycle extension

The accepted finite lifecycle reuses `cancel_capture`, its SQL revision and
idempotency journal, and the signed regional control stream (ADR-287). One
explicit Stop adds one durable request, one regional query, at most one original
node cancellation work item and one joined outcome update. Zero new watches,
listeners, credentials, privileges, settings or background loops are added.
Existing pending/unknown/stored/cancelled outcomes suffice. A typed profile stop
and joined proof avoid borrowing source/packet fields; no acquisition retry or
refund follows an uncertain endpoint/backend outcome. Before-start tombstones
share the same 64-holder bound with recordings and snapshots. Migration 124
extends the existing immutable cancellation guard and its Down restores the
previous guard. Native runtime qualification remains separate from SQL tests.
