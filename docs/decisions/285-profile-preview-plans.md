# ADR-285 — Profile actions in manual preview

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
profiles fix an address mode and port. It uses the existing installer and
protected regional deployment projection, adding no watches, credentials,
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
