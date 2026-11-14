# ADR-285 — Profile actions in manual preview

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded in part by ADR-328 (2026-11-13): Endpoint definitions no longer
> travel through the installer's protected regional deployment projection; the
> connector reads them from Helm-rendered configuration under RBAC. Endpoint
> resolution, review freezing and the acquisition-time recheck remain valid.

Date: 2026-11-03. Status: accepted (agent decision).
Requirements: REQ-PRF-001/002, REQ-CPR-001/003, REQ-ASM-001/003.
S-05 increment 2; acquisition and policy execution remain subsequent increments.

## Decision

The shared recorder compiler accepts `profile` actions and exposes
`builtin/go-cpu/v1`. Go endpoint modes use the ADR-284 type/duration rules:
CPU intervals up to 60 seconds, execution traces up to 15 seconds, heap and
goroutine snapshots or deltas, and other supported counters cumulative or
delta. Forced GC is allowed only for heap snapshots. The eBPF sampler is
`runtime: any`, `type: cpu`, interval 1–60 seconds. Sampling frequency is not
configurable. Every profile runs `onTrigger`, has intrusive impact, a bounded
output, a setup/delivery margin of 5–10 seconds, and the `liveProfile` approval
reason. The native evidence class is raw.

A Go source names a recipe binding or an administrator profile. Each component's
binding names are expanded alongside its action IDs. The hub asks the target's
region once to resolve the source after ordinary eligibility. The region uses
its mounted installation configuration and the exact Pod's port declarations;
it never probes an endpoint or reads a Secret. Namespace restrictions hide
out-of-scope definitions as absent. Duplicate named ports are ambiguous. The
answer contains public definition and endpoint digests, address mode and port,
not an IP, credential or TLS material. The hub records its receipt time and
freezes that answer in the reviewed scope. It is review data, not execution
authority. Acquisition must independently recheck the route and definition.

`cluster.profileEndpoints` supplies at most 64 administrator definitions on
regional executors: templates constrain address modes and port ranges; complete
profiles fix an address mode and port. The connector reads it from its
mounted, Helm-rendered regional configuration, adding no watches, credentials,
permissions or deployments. TLS/credential entries remain for increment 4.
No URL, path or caller-chosen host is accepted in a recipe binding.

Preview reports application CPU/allocation work, forced-GC pauses where selected,
and possible sensitive profile labels and paths. Go traces additionally retain
application task/log text. Heap samples are not described as a full heap dump.
Overhead and sampler attribution remain unmeasured. No trial acquisition runs.
Profile submission and policy execution are refused until their runtime paths
are implemented and qualified; preview does not open an unusable approval.

## Complexity gate

1. The observed gap is complete absence of profile preview; frequency is not
   measured. 2. Profiles are an accepted first-release requirement. 3. Go service
   profiling is the initial typical scope. 4. Named endpoint configuration follows
   the existing endpoint planner and the S-05 plan's Prometheus precedent.
5. Zero added privileges, credentials, external dependencies or deployments.
6. Three explicit resolution refusals: unavailable, ambiguous and denied;
   host-network remains unavailable. 7. No machinery-tuning configuration.
8. Uses the existing Kubernetes API and regional transport.
9. One bounded regional query and the existing exact-Pod observation per preview;
   at most 64 configured entries and 16 recipe bindings; zero background tasks.
10. Empty endpoint configuration disables resolution; old empty configurations
    remain valid. Removal does not activate any capture.
11. Reusing the existing pure endpoint planner and regional query avoids a new
    CRD or discovery service; omitting preview would leave the required workflow
    incomplete.

## Verification boundary

Unit coverage exercises endpoint scope and ambiguity, frozen scope changes,
profile modes/durations/forced GC, assessment and refusal of submission/policy
execution. Helm checks cover installer projection and invalid configuration.
These checks do not qualify installed profile acquisition or native downloads.

## History-repeat readiness composition

Native run 41879675203 demonstrated a normal budget mismatch: the capacity
demand completed successfully in 4.5 seconds, 1.508 seconds after the repeat
preview had stopped waiting. Its five-second inner request, including a
one-second reply reserve, could not fit the existing source operation plus
target, catalog and recorder metadata work. Increasing only that request to
eight seconds still leaves the original target and recovery observations
expired; a local advancing-clock regression reproduces both refusals.

A single-profile history repeat therefore selects an eight-second composition
budget at entry, inside the unchanged fifteen-second public preview request.
Classification and non-profile paths retain five seconds. A possible-profile
hint can begin before catalog classification, but an ordinary consumer cancels
and joins that same hint at its original readiness cutoff, retaining the
750 ms reply reserve (the scheduling adjustment in ADR-213). Initial recovery and
current target review precede the one non-authoritative readiness hint. After
joining it, the existing complete recorder resolution is moved later and its
fresh namespace/workload/Pod result must match the original request and pin.
A warm unsupported mechanism retains the existing plan-only/dependency
handling: history still refuses when its original qualified collector cannot
be reproduced. After a long wait, expired hint facts cannot manufacture a
plan-only preview and the repeat refuses. This avoids an extra recorder RPC
solely for that fallback. Final eligibility, capability, retention and storage are independently read;
no freshness is borrowed from a Pod observation. One additional current recovery
read must retain the initial installation ID, issuer epoch and full revision,
while keeping its own original five-second interval. An expired initial proof
is never extended or relabelled as that new proof. History expiry, original
caller/token/session/policy bounds, cancellation and final checks still win.

Cost: three SQL reads in one additional bounded transaction per such repeat;
zero extra Kubernetes reads, refresh demands, APIs, privileges, watches, caches,
pools, background owners or configuration. Existing required recorder reads are
reordered, not duplicated. At R repeats per second the added SQL load is
3R queries/R transactions per second. The existing 250 ms storage polling may
continue three seconds longer, up to 12 additional logical storage reads per
stalled repeat; concurrency and owner counts do not grow. The browser preview timer matches the already
accepted fifteen-second server window; other capture operations keep ten
seconds. The capacity worker's original five-second source operation and
quotas are unchanged. This is a maintainer-authorized practical composition
choice, not an extension of collection or disclosure authority. Installed repeat
availability still requires qualification of the final integrated source.
