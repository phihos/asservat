# ADR-208 — Opening limiter for context-start Kubernetes clients

Date: 2026-10-19. Status: implemented with a unit test; revised to 50 QPS after
native 57; installed acquisition and publication observed. Sustained availability
remains unqualified.
Requirements: REQ-EXE-002, REQ-FED-001/003, S-02; TASK-03 / TASK-11.

Current qualification (2026-10-20):
[resumed native48](../../test/results/resumed-c62e02ac-native48/result.json)
and [native49](../../test/results/resumed-c62e02ac-native49/result.json) reached
regional acquisition, storage and installed publication with these selected
clients. Native49 also recovered the accepted capture and completed fresh
authorized `get_capture` and `get_case` reads. These runs do not isolate the
limiter's contribution, measure successful opening latency or qualify sustained
API load and availability. Native49 exited 1 at a deletion-fixture policy
comparison before fault injection or native download; the complete installed
lifecycle remains unqualified.

## Context

Installed native 55 failed preview with every hub refusal in the closing
self-authentication with under 0.5 seconds left. Connector setup marks reached
3.39 s (process proof alone about 1.3 s, each later guard/settings check
150–350 ms), while transport-measured API calls averaged about 1.3 ms. All
product clients use client-go's token bucket at 20 QPS/burst 20
(`newBoundedAPI`). An opening makes roughly 60–80 sequential reads per side, so
past the twentieth each read waits about 50 ms for a token; `x/time/rate.Wait`
also fails at once when that wait would pass the deadline. Separate client
instances (native 54/55) removed cross-path queueing but not this per-opening
cost.

## Decision

1. Only the clients dedicated to context-start openings use the opening
   limiter (`kube.WithOpeningBurst`; 20 QPS/burst 100, revised below to 50 QPS): the regional context observer/probe and the hub
   context-start ingress self-authentication observer/probe.
2. The sustained rate stays 20 QPS per client. A full bucket refills within one
   original five-second window, so sustained API load per client is unchanged;
   only the first 100 calls after idle avoid waiting.
3. Identities, rights, checks, read order and every original deadline are
   unchanged. All other clients stay 20/20, and the configuration worker keeps
   its ADR-recorded 40/20 observer.

## Revision after native 57

At 20 QPS/burst 100 a freshly started hub refused its own protection reads
with at least 2 seconds left after about eight openings, roughly 160 reads:
more than the bucket held. A failed regional opening is retried after one
second, so failing openings add demand faster than 20 QPS refills it. The four
dedicated clients now use 50 QPS/burst 100 (`kube.OpeningQPS`). This follows
the configuration worker's existing 40 QPS observer precedent and stays within
the kube-apiserver's API Priority and Fairness. The hub now reports the
context-start clients' call count beside the other owner clients, so the
measured rate can confirm or bound this choice.

## Extension after native 62

The hub's audit credential reader (ADR-173's own clients) re-verifies the
installed owner identity, the audit credential Secret and the workload guard
for every encrypted operation audit object, about 50–70 sequential calls. An
audited request runs it twice (Begin and Finish) inside its original five
seconds, and at 20/20 each read took 1–3 s (installed native 62), leaving the
preview too little time. That reader's two clients now use the same opening
limiter. Its proofs, identities and the request deadline are unchanged; the
provider refresh reader and all other clients keep 20/20.

## Extension to the hub retention follower

The hub-worker's retention source follower kept the accepted hub source current
only about half the time on the permission worker's shared 20/20 clients (local
reproduction after native 68). Every preview reads that source twice inside
its five seconds. The follower now has its own observer and probe clients with
the opening limiter; observation content and freshness bounds are unchanged.

## Extension to regional capacity observation

The hub-worker's v2 regional observation clients serve both regional
discovery and the ADR-200 demand lane. A guarded demand read took 2.6–3.7 s
against the binding's five seconds, so a refreshed binding had about 2 s left
and previews waited for it. Those two clients now use the opening limiter;
the observations and their bounds are unchanged.

## Extension to the region's capacity and lifecycle clients

Local holds 6 and 7 split the remaining time. The hub's claim (`c-post`) and
the owner's `observe` step spend about 2.2 s waiting on the region, with every
refresh between 2.16 and 2.25 s. One regional capacity cycle makes about 63
API calls (open 19, reads 3/3/13/3/22) on clients limited to 20 QPS / burst 20,
so about 43 calls wait 50 ms each (≈2.15 s); the region's kube-apiserver
answers non-watch requests in about 1 ms on average. The region's target
answers spend 1–3 s in the connector's local proof (`r-local`), which reads
through the lifecycle observer and probe at the same 20/20. The regional
capacity observer, metadata and probe clients and the lifecycle observer and
probe now use the opening limiter. Checks, reads and deadlines are unchanged.

## Alternatives

- Raising QPS (as the configuration worker's 40 QPS observer) increases
  sustained load; burst alone matches the bursty opening pattern.
- Reducing reads per opening (ADR-207 continues this) is retained work, but each
  removal must preserve the same checks; it cannot be completed for this run.
- Extending the five-second window would weaken original deadlines.

## Consequences

The kube-apiserver's API Priority and Fairness remains the server-side bound.
Each dedicated client can send up to 100 calls at once and 50 per
second sustained. A further increase needs the measured context-start call
rate first.

## Revision (2026-10-23)

The hub's proof of its own installed protection is now a process-local reused
observation (`kube.OwnerProtectionReuse`, 30 s): one successful
`OwnerWorkloadProtection.Current` and one successful
`InstalledOwnerIdentityReader.Verify` per exact mounted bundle serve every
caller until 30 s after the proof began, never past the token, guard or
caller bound. A stored proof is renewed once less than five seconds remain, so
a caller never receives an almost expired one. Failures are not stored and
concurrent callers share one in-flight proof.
The trust model ([security.md](../security.md#trust-model)) trusts cluster
administrators, so re-proving the hub's own guard per request added API load
without an integrity guarantee. In-call duplicates are removed: Verify's
repeated tail, the audit credential's third guard read, the second accepted
configuration read in the provider credential paths, the second protection
read in owner authentication and the closing `ObserveOwnerServing` of the
context-start ingress. Per-request identity, authorization, registry/route and
SQL checks, remote-peer token reviews and worker attestation are unchanged.

An audited request's credential reads fall from 51 calls each (102 per
request) to one cold proof plus one Secret GET per read, and one Secret GET once
warm. A hub context-start opening falls from four guard proofs to at most one,
and none within the reuse window. The hub context-start and audit credential
clients therefore return to the default limiter. `kube.WithOpeningBurst`
remains for the regional clients and the hub preview/catalog clients.
