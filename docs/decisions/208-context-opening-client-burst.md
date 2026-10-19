# ADR-208 — Opening limiter for context-start Kubernetes clients

Date: 2026-10-19. Status: implemented with a unit test; revised to 50 QPS after
native 57; installed qualification pending.
Requirements: REQ-EXE-002, REQ-FED-001/003, S-02; TASK-03 / TASK-11.

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

## Alternatives

- Raising QPS (as the configuration worker's 40 QPS observer) increases
  sustained load; burst alone matches the bursty opening pattern.
- Reducing reads per opening (ADR-207 continues this) is retained work, but each
  removal must preserve the same checks; it cannot be completed for this run.
- Extending the five-second window would weaken original deadlines.

## Consequences

The kube-apiserver's API Priority and Fairness remains the server-side bound.
Each of the four dedicated clients can send up to 100 calls at once and 50 per
second sustained. A further increase needs the measured context-start call
rate first.
