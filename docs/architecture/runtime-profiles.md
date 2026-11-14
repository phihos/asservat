# Bounded Go runtime-profile acquisition

The C-11/C-23 acquisition mechanism serves the `profile` action (REQ-PRF-001/002,
REQ-LIF-001): Go CPU, heap and runtime-trace profiles from a named pprof endpoint of the
selected whole Pod, stored as encrypted evidence and downloadable natively for local pprof/trace
tools. Mechanisms follow [ADR-330](../decisions/330-event-driven-system-design.md).
Qualification is recorded in [implementation progress](../implementation-progress.md).

## Request and authority

`GoProfileRequest` is an immutable, resolved mechanism input: the artifact/attempt binding,
exact whole-Pod and node identity, named source and resolved endpoint digest, profile
parameters, native byte limit and original `NotBefore`/`Deadline`. Its producer derives the
deadline from the earliest accepted capture, action, grant, processing/write and retention
cutoff; the mechanism cannot extend it. `PinnedPod.ControllerUID` is the immediate controller
and is empty for a bare Pod. A profile is an on-trigger action, including a cumulative or delta
profile; it has no pre-trigger history.

Before acquisition the execution service has authorized the operation once (ADR-311), recorded
the start with its operation ID, reserved impact/output quota and the conflicting-runtime slot,
and prepared wrap-only encryption keys. Profile admission defines its own action interval: the recipe's configured recording duration
plus setup and finish margin, with no separate duration ceiling (the remote cost is the
application's own profiler, bounded by admission concurrency and rate limits, ADR-335 D8); it
does not reuse the context-start binding. A started acquisition runs to its original deadline. Stop or cancel for the operation
arrives as a pushed command on the node stream and closes the socket; there is no periodic
authority recheck during the profile. Caller cancellation stays connected through acquisition
and encryption.

The setup/finish margin is the connect plus finish I/O timeout (2 × 5 s, ADR-330 D5) and is
the default; an admitted plan records it. Default recording durations follow Go's
`net/http/pprof` defaults (CPU `seconds=30`, trace `seconds=1`); the recipe may configure
another duration. If the remaining interval (earliest of caller, action and channel
cutoff) cannot fit the recording plus margin, the application is not contacted. Recording
duration sets the server-side `seconds` parameter. Cancellation or HTTP EOF does not prove the
remote profiler stopped. A retry with the same operation ID returns the recorded outcome; there
is no automatic retry and no stop-profiler request.

## Endpoint and network boundary

`GoProfileDialer` resolves only the admitted source/digest, checks the exact Pod/node identity
and credential audience and opens the connection from the target node. Target-loopback enters
the target Pod's network namespace; collector loopback is forbidden. Pod IP and declared port are
routing facts, not serving-process attribution. No container permission or public container
selector exists.

The dialer returns one HTTP/1 connection with its channel/credential expiry (no later than the
action deadline), a fixed administrator-selected Host and an optional Authorization value. A
credentialed endpoint requires a verified TLS peer first. The adapter accepts no address
override, TLS roots, credential reference, URL, port or arbitrary header. The transport has no
environment proxy, DNS, redirects, persistent connections, retry or HTTP/2.

Paths are the fixed Go pprof paths: CPU `/debug/pprof/profile`, trace `/debug/pprof/trace`, heap
`/debug/pprof/heap`. Only `debug=0`, approved integral `seconds` and explicit heap `gc=1` are
generated. Index, cmdline, symbol, sampling controls and stop endpoints are never called.
`forceGC` with a delta profile is rejected because Go serves `seconds` before heap GC. Only the
standard handler's exact busy signature becomes `ProfilerBusy`.
[Go pprof API](https://pkg.go.dev/net/http/pprof),
[implementation](https://go.dev/src/net/http/pprof/pprof.go).

## Evidence

Response entity bytes stream directly into the prepared `evidence.StorageEncoder`; transfer
framing is removed, content encoding and gzip bytes are kept exactly (no automatic
decompression). No plaintext file, object or whole-profile buffer is created. The single-use
sink is owned by acquisition even when validation or endpoint opening fails; acquisition closes
it after joining its source work. The framed format keeps native length/checksum for byte-exact
download. The result is an encrypted layout plus acquisition facts, not a catalog artifact.

Headers are bounded; non-success bodies are classified by a small fixed classifier and never
logged. Accepted bodies have a hard native cap with at most one overflow byte. The cap is the
verification bound, so every collectable profile is verifiable: the regional reader's memory
request divided by its concurrent verifications, default 16 MiB. Empty, truncated,
over-limit or partially consumed responses never report complete acquisition. Host,
authorization and upstream error strings never appear in errors or provenance.

HTTP success does not verify profile semantics. The offline C-18 parser establishes sample
types/units, duration, sampling configuration, labels, mappings and format before publication;
unknown process attribution, disabled block/mutex sampling and remote stop stay unknown. No
parser runs in the network-enabled acquisition process. Originals are raw evidence that may
contain user data: retention, workload quotas, encrypted custody, audit and verification cover
them, no redaction is claimed and managed deletion cannot erase downloaded copies.

## Named endpoint planning

`planning.ResolveGoProfileEndpoint` combines the recipe binding (`name`, `templateRef`,
`addressMode`, `portName`), the administrator endpoint catalog and the selected Pod's network
facts from the connector's informer cache. Administrator profiles with fixed numeric ports need
no declared port.

The catalog and recipes have no entry or binding counts; Kubernetes object limits bound them.
An entry's definition scope names one application namespace or every authorized namespace in its
cluster; entries stored in an administrator namespace may serve application namespaces. Entries
for other namespaces or clusters are ignored before name resolution, and selecting one yields
`ProfileUnavailable`, like an absent name. Duplicate applicable names, duplicate bindings and
binding/profile collisions are ambiguous; there is no shadowing. A template is used only through
an explicit binding. References are valid UTF-8 without control characters, at most 63 bytes.

Named ports resolve across regular and init container declarations, including restartable init
sidecars. Multiple matching declarations are ambiguous. The one matching TCP port must be inside
the template's range. Container names are not part of routing, configuration or permission.
Ephemeral-container ports are rejected.

Definitions fix `go-pprof/v1` path policy, permitted address modes, port range, HTTP Host and,
for loopback, the family (`ipv4`/`ipv6`). `targetLoopback` yields 127.0.0.1 or ::1 in the target
Pod's network namespace. `podIP` uses the primary Pod IP and validates the dual-stack list by
parsed `netip` value; zoned, mapped, loopback, link-local, unspecified and multicast addresses
are excluded. There is no DNS lookup, address fallback, replacement Pod or probe. Host-network
Pods are unavailable for this action.

TLS names a public trust definition and an exact server name. A credential policy is a named
public dependency, never a Secret value or hash; credentials require TLS and a nonempty audience
of exact cluster/namespace/workload-kind/workload-UID roots, and the selected Pod must belong to
one of them through target resolution. Labels, ports and service-account names cannot establish
an audience.

The resolver canonicalizes the selected definition and computes a definition digest and an
endpoint digest over source identity/public digest, policy, TLS/credential references, exact
target/root/Pod/node, route IP, address mode, port/binding, profile parameters and native limit.
`MatchesAcquisition` compares the plan with `GoProfileRequest`; it is not an authorization.
`PodTargets.ObserveProfileNetwork` reads the declared ports and the Pod IPs (at most two:
Kubernetes assigns one per family) from the informer cache, with no environment or free-form workload data; the node verifies the Pod UID
when it dials.

## Endpoint TLS (ADR-299)

Endpoint entries may carry `tls: {serverName, rootsPEM}`. The adapter parses all certificate
blocks, canonicalizes the bundle and records its SHA-256 in the definition, which enters manual
and recurring definitions. `GoEndpointPlan.TLSMaterial` carries the bundle beside the plan,
outside approval scope; the node checks its digest/name against the admitted definition and uses
`tls.Client` with explicit roots, HTTP/1.1 and the original deadline. A bundle is bounded only by
its containing ConfigMap (1 MiB); without one the system trust store applies (ADR-335 D12). The collector announces `profileTLS` in its Hello capabilities; a start
requiring TLS is refused for a collector without it.
[ADR-299](../decisions/299-named-go-endpoint-tls.md).

## Endpoint authorization (ADR-302)

`credential.audiences` names exact workload roots; the public policy digest excludes private
material, and recurring definitions carry only public policy/audiences. The private credential
map is a regional Secret mounted into the connector and loaded at startup; rotation is a Helm
upgrade that restarts the connector. The connector selects the entry after checking the work's
target and audience and sends the bytes only in the work item pushed on the node stream; queues
and stored work stay credential-free. Node TLS verification precedes the Authorization header.
Disabling removes the public configuration and the private entry.
[ADR-302](../decisions/302-named-profile-endpoint-authorization.md).

## Finite policies (ADR-296)

Finite policies reuse C-03 authorization and approval, C-06 planning, C-11 execution and the
node/connector profile transport. The endpoint definition is looked up over the connector
connection; the selected definition and binding enter the accepted policy configuration, and
concrete Pod routing is resolved per child execution and matched to the hash-pinned grant scope
at admission. [ADR-296](../decisions/296-finite-policy-go-profiles.md).

## Metadata, refusals and summaries

- Verified acquisition interval (ADR-297): the manifest's HTTP acquisition interval passes
  through verification and the catalog projection into C-16 metadata, displayed in UTC
  microseconds with unknown cross-source clock uncertainty and process attribution; records
  without it show unknown. [ADR-297](../decisions/297-verified-profile-acquisition-metadata.md).
- Refusals (ADR-298): missing or disabled endpoints report `Failed`/`ProfileUnavailable`;
  application conflicts report `Failed`/`ProfilerBusy`. They create no evidence, replacement
  target or automatic retry, and release the operation's reservations. Only the application
  owner stops its profiler. [ADR-298](../decisions/298-explicit-go-profile-refusals.md).
- Summary refusal (ADR-291): a `get_extract(view=profileSummary)` authorization failure before query
  admission becomes a content-free `NotAvailable`; denied, missing, unsupported and unavailable
  sources share that response and audit outcome. Native Go trace download stays available
  (REQ-PRF-005, SC-PRF-003/005). [ADR-291](../decisions/291-bounded-profile-summary.md).
- Heap summary: C-20 passes the saved acquisition type; heap suggests editable `inuse_space`,
  CPU suggests `cpu`. C-18 verifies the selected sample type and returns unit and duration.

## Repeat and previews (ADR-285)

A history-backed repeat is a stateless preview: it resolves the current target, capability,
eligibility, retention and storage facts and the exact catalog version referenced by the
history entry, checks the catalog source/definition against the original canonical scope and
returns the plan and its digest. The resolved target must be the same pinned Pod. Submission with
the digest and an idempotency key accepts that plan or reports what changed. Builtin profiles
need no catalog read. [ADR-285](../decisions/285-profile-preview-plans.md).
