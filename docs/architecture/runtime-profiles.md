# Bounded Go runtime-profile acquisition

The C-11/C-23 acquisition mechanism serves the existing `profile` action
(REQ-PRF-001/002 and REQ-LIF-001). Installed manual and finite-policy Go CPU
workflows now compose protected planning, independent approval, admission,
publication, inspection and native pprof download. The namespace heap MCP
workflow also passed at `80593f93` in native41818585176: read-only `inuse_space`
summary, authenticated original, exact signed total and a fresh repeat preview.
PR160 merged as `5b765322106c8b76e5c73a87577548856b6d609c` after eligible
`pull_request` CI41821140504 passed; its full tree equals qualified `80593f93`.

Heap React inspection/native download/Repeat passed at c2d4 in native41891716697
attempt2. Native41912395184 passed Go trace capture/publication, authenticated
download/local parsing and history/settings/Repeat at59812214; PR162 merged as
3cc76be0 with the identical complete tree. Accepted-heavy comparisons passed at
c6 with measured worker memory/CPU containment for that one input shape.

These are named Linux/amd64 reference workflows. Named TLS CPU endpoints passed the original-app native/summary/Repeat and
wrong-peer journey at abf25590 (installed41916430295); endpoint authorization,
all-maxima analyzer qualification and broader S-05 remain open. See
[the current evidence](../implementation-progress.md)
for originals and limits. The initial mechanism and staged-test boundaries below
describe which facts each layer supplies; component checks alone establish no
installed authority.

## Lifetime and authority contract

`GoProfileRequest` is an immutable, resolved mechanism input. It contains the
original artifact/attempt binding, exact whole-pod/node/boot identity, named
source and resolved endpoint digest, profile parameters, native byte limit and
original `NotBefore`/`Deadline`. Its producer must derive the deadline from the
earliest accepted capture, action, grant, processing/write and retention cutoff.
The mechanism cannot extend any of those deadlines or create/renew a permit.
`PinnedPod.ControllerUID` keeps the existing immediate-controller meaning; it is
empty for a bare Pod, never fabricated as the Pod UID. Full workload ownership
and credential audience come from the original accepted scope/current resolver.
This is an on-trigger action, including a cumulative or delta profile. A timed
profile is not a recorder and has no pre-trigger history.

Before calling acquisition the execution service must have committed the
original intrusive start, impact/output reservations and conflicting-runtime
slot, and prepared wrap-only encryption keys. This new mechanism input cannot
be used as an existing `ContextStart` or public collection scope. In particular,
the existing local start binding's one-minute ceiling cannot represent a
60-second CPU profile plus setup/shutdown margin. Profile-specific admission
must resolve that contract explicitly before maximum-duration profiles can be
enabled; this component does not silently widen the existing binding.

The separate `GoProfileGuard` reports a current observation of that same admitted
request, including original grants, current permission/deny/recovery state,
exact endpoint source, target incarnation and retained runtime-domain slot.
There is no production guard implementation in this component. Each observation
lasts at most five seconds. A one-second current-state recheck is bounded by the
previous observation's **original** expiry. A blocked, stale, denied or failed
recheck stops the socket; success may replace only observation freshness inside
the unchanged action deadline. It cannot alter the request or replenish spend.
Original caller cancellation remains connected throughout acquisition and
encryption. The observer is joined before returning.

The mechanism requires at least two seconds of explicitly admitted setup/finish
margin, permits at most ten, and does not synthesize defaults. Planning retains
the product's ten-second CPU, five-second trace and five-second snapshot defaults.
Before dialing, the fit check uses the original caller/action context deadline.
After channel resolution it uses the earliest original caller, action and
channel cutoff for both the socket and final pre-HTTP check. A longer admitted
action cannot bypass a shorter caller lifetime. If the remaining effective
interval cannot fit the requested recording plus margin, do not contact the
application. Recording duration, not HTTP/client timeout, sets the
server-side upper request parameter. Cancellation or even complete HTTP EOF
does not independently prove the remote profiler stopped. Unknown starts remain
spent; the mechanism has no retry, stop-profiler request or capacity-refund path.

## Named endpoint and network boundary

The passive endpoint planner below resolves a named route without contacting the
workload. `GoProfileDialer` remains a required trusted capability, not an
implemented node resolver. It resolves only the admitted source/digest, rechecks exact pod/node
identity and credential audience and opens the connection from the target node.
For target-loopback it must enter the exact qualified target network namespace;
ordinary collector loopback is forbidden. Pod IP and declared port are routing
facts, not serving-process attribution. No container permission or public
container selector is introduced. Node-local and network-namespace qualification
remain outstanding.

The dialer returns one already authenticated HTTP/1 connection with its original
channel/credential expiry (no later than the action deadline) and a fixed
administrator-selected Host value and optional bounded Authorization value.
For a credentialed endpoint it must first verify the configured TLS peer and
the credential's workload audience; unauthenticated clear transport cannot carry
that credential. The adapter cannot supply an address override, TLS roots,
credential reference, URL, port or arbitrary request header. Its socket deadline and request context retain the earlier channel expiry;
neither a fresh current observation nor the longer action interval can extend it.
Its HTTP transport
has no environment proxy, DNS path, redirects, persistent connections or retry.
It receives that one connection once. HTTP/2 is not negotiated by this profile.

Paths are fixed Go pprof paths; CPU maps to `/debug/pprof/profile` and runtime
trace to `/debug/pprof/trace`. Only `debug=0`, approved integral `seconds` and
explicit heap-snapshot `gc=1` are generated. Never call index, cmdline, symbol,
sampling controls or an application's stop endpoint. Go handles a `seconds`
request through its delta path before heap GC, so `forceGC` combined with delta
is rejected rather than claiming GC occurred. The standard handler's busy
response is recognized only by its exact bounded signature; arbitrary server
errors do not become `ProfilerBusy`. [Go pprof API](https://pkg.go.dev/net/http/pprof),
[Go HTTP pprof implementation](https://go.dev/src/net/http/pprof/pprof.go).

## Evidence and local tools

Successful response entity bytes flow directly into the prepared
`evidence.StorageEncoder`. HTTP transfer framing is removed, while content
encoding and native gzip bytes are preserved exactly: automatic decompression
is disabled. No native file, plaintext object or whole-profile buffer is created.
Calling acquisition transfers ownership of the single-use prepared sink even
when validation, current authority or endpoint opening fails. Acquisition closes
the sink after joining source/observer work, drops prepared key references and
checks the original cutoffs again; it cannot reuse that attempt. Releasing Go
primitive references is not a promise of physical memory erasure.
The existing versioned framed format retains native length/checksum for later
authenticated byte-exact download. This component returns an encrypted layout
and acquisition facts, not a catalog artifact or readable profile.

Response headers are bounded, non-success bodies are inspected only through a
small fixed classifier and never emitted/logged, and accepted body reads have a
hard native cap with at most one overflow byte. Empty/truncated/over-limit and
partially consumed responses cannot report complete acquisition. Consumer errors
stop the socket, preserve possible-start provenance and do not return a usable
layout. Endpoint Host, authorization and upstream error strings are absent from
returned errors and acquisition provenance.

An HTTP success and an octet-stream content type do not verify profile semantics.
The separate offline C-18 parser must establish sample types/units, duration,
sampling configuration, labels, mappings and format before publication. Unknown
process attribution, disabled block/mutex sampling and remote stop must remain
unknown until qualified. No parser or flamegraph renderer runs in this
network-enabled mechanism process. Native downloads and local pprof/trace tools
remain required; their publication/transfer integration is not supplied here.

All originals are raw evidence that may contain user data. Original acquisition
retention, workload quotas, encrypted custody, audit and independent verification
must cover the output and partial copies. No sample/label redaction is claimed
for the preserved original. Managed deletion cannot erase downloaded copies.

## Initial mechanism qualification boundary

The staged tests exercise synthetic HTTP and the existing framed encoder; test
guards and node connections are explicitly synthetic. Passing them does not
qualify real node routing, runtime-domain mutual exclusion, production authority,
object-store custody/publication, native-download permissions or the UI/MCP flow.
The mechanism files alone enable no public/Helm profile capability. The integration
sequence is accepted endpoint/template resolution and profile-specific admission,
qualified node dialer/current guard, bounded custody/manifest verification, then
the same shared capture/catalog/native-download workflow and isolated analysis.


## Passive named endpoint planning

`planning.ResolveGoProfileEndpoint` composes the existing recipe binding fields
(`name`, `templateRef`, `addressMode`, `portName`), an independently supplied
protected catalog observation and the exact selected whole-pod network facts.
It also supports fully configured administrator profiles with fixed numeric
ports; these do not require the application to declare an otherwise approved
port. The input contract is private. This is not a new public endpoint API or an
implementation of catalog protection, durable acceptance or source supervision.

The complete bounded catalog contains at most 128 template/profile entries;
a recipe has at most 16 bindings. Sources carry cluster, optional namespace UID,
resource UID, entry name and public definition digest. Source namespace identity
is provenance: a definition stored in a protected control namespace can serve an
application namespace. A separate definition scope names that application
namespace UID or permits any authorized namespace in the enrolled cluster. The
resolver validates entry shape separately from applicability. Valid entries for
other namespaces or clusters are ignored before name resolution, including
foreign entries sharing an allowed entry's name. Selecting a foreign entry
returns the same empty result and `ProfileUnavailable` as an absent name.
Duplicate applicable names across catalog kinds or overlapping scopes, duplicate
local bindings and applicable binding/profile collisions remain ambiguous.
There is no namespace shadowing or last-entry-wins behavior. A template is usable only through an explicit binding;
its existence is not an implicit request to contact an endpoint.

Canonical recipe `name`/`templateRef` and profile `source.profileRef` schemas impose
only a 1–63-character string length, not a DNS-label pattern. The internal
mechanism narrows these references to valid UTF-8 with no control characters and
at most 63 bytes, matching the existing `GoProfileRequest.SourceRef` contract.
This is an explicit internal limit, not complete Unicode wire-schema parity;
future public decoding still validates the canonical schemas separately.

Named ports resolve across all regular and init container declarations, including
restartable init sidecars. Multiple matching declarations are ambiguous even
when their numeric port is identical or only one uses TCP. One matching TCP
port must be inside the template's range. The observer retains duplicates for
this decision instead of silently deduplicating. Container names are neither
retained in this routing projection nor exposed as a configuration/permission
choice. Ephemeral-container port declarations are rejected; Kubernetes does not
allow them. [Kubernetes Pod API](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/).

Administrator definitions fix `go-pprof/v1` path policy, permitted address modes,
port range, HTTP Host and, when relevant, an explicit loopback family (`ipv4` or
`ipv6`). `targetLoopback` produces 127.0.0.1 or ::1 **in the pinned target network
namespace**; the plan is not a dialable socket or a namespace handle. `podIP`
uses the observed primary Pod IP and validates any published dual-stack list
against it by parsed address value. Equivalent expanded/uppercase IPv6 spellings
are normalized with `netip` before comparison and digesting. This handles the
legacy Pod IP fields; newer Kubernetes IP fields can require canonical text.
Zones, mapped IPv4-in-IPv6, loopback, link-local, unspecified and multicast Pod
addresses remain excluded. [Kubernetes IP validation](https://github.com/kubernetes/apimachinery/blob/v0.37.0/pkg/util/validation/ip.go).
There is no DNS lookup, secondary-address retry, address-family fallback, replacement Pod or endpoint probe. Missing IP affects pod-IP routing,
not passive loopback planning. Host-network Pods produce an explicit unavailable
reason until a separate mechanism is qualified; neither address mode permits
access to the node's loopback through this slice.

TLS pins a named public trust definition and an exact server name. A credential
policy is also a named public dependency, never a Secret value or secret-payload
hash. Credentials require TLS and a nonempty finite audience of exact
cluster/namespace/workload-kind/workload-UID roots. The selected Pod must belong
to one of those roots through independent target resolution. Port declarations,
labels and service-account names cannot establish a credential audience. Actual
credential retrieval, current policy acceptance, certificate verification and
socket opening remain required in the node dialer; the pure planner performs
none of those effects.

The resolver canonicalizes copies of the selected definition, sorts set-valued
address modes/audiences and computes a definition digest plus endpoint digest.
The endpoint digest includes source identity/public digest, resolved policy and
TLS/credential references, exact target/root/Pod/node/boot, route IP, address
mode, port/binding, profile parameters and native limit. Current resource versions
and observation timestamps do not change immutable scope. This computed digest
binds the actual input values; it does not prove that their claimed public source
digest was independently accepted. The configuration producer must establish
that correspondence before these inputs can be used for execution planning.
`MatchesAcquisition` compares against the existing `GoProfileRequest`; it is not
an authorization decision and cannot renew that request's action lifetime.

`PodTargets.ObserveProfileNetwork` uses the fixed enrolled-cluster API transport
and only GETs. It reads bounded routing facts, invokes the existing exact
namespace/Pod/owner/node resolver, and requires the final Pod resource version
and node to match the original routing response. It returns at most 256 declared
ports and two Pod IPs, without container environment or free-form workload data.
The whole operation retains its original at-most-five-second interval and any
earlier caller deadline. Composition retains the earliest catalog, target and
caller cutoff; later source reads cannot manufacture a fresh interval.

The tests are synthetic TLS API and pure planning regressions, including an
actual adapter-to-planner path. The second component gate passes all 30 selected
parents / 269 named race tests and canonical checks after correcting forbidden
domain imports; the architecture rule is unchanged. This is not a native
node/network or installed feature result. Current qualification is recorded in
[implementation progress](../implementation-progress.md). Remaining integration
is protected catalog definition/acceptance and observation, profile admission
and runtime-domain reservation, current credential policy, qualified node/netns
dialing and guard composition, then the existing encrypted custody/publication
and authenticated native-download workflow. No public capability is enabled.


## Named endpoint TLS preparation

[ADR-299](../decisions/299-named-go-endpoint-tls.md) extends protected regional
endpoint entries with `tls: {serverName, rootsPEM}`. The Kubernetes adapter parses
all certificate blocks without ignored text or headers, canonicalizes the public
bundle and retains its SHA-256 under the existing typed `GoEndpointTLS.Trust`
source. The trust source reuses the protected endpoint identity; its material
digest and exact server name enter both manual and stable recurring definitions.
The target-independent regional query carries those public metadata fields only.

A comparable `GoEndpointPlan.TLSMaterial` sidecar is excluded from canonical JSON
and approval/SQL scope. The selected entry supplies it without another API read;
regional dispatch and node receipt check its digest/name against the admitted
public definition. The node uses `tls.Client` over the existing gadget socket,
explicit roots, HTTP/1.1 and the original operation deadline. TLS does not add a
second dial, DNS, proxy, fallback or new credential channel. Authentication is
separately introduced by ADR-302; ADR-299 alone still refuses it. The 8 KiB per-bundle, 64 KiB aggregate endpoint configuration and
256 KiB/16-item node poll bounds are unchanged or explicitly bounded, rather than
increased to fit the new data.

An optional `profileTLS` flag on the existing Go profile adapter report identifies
TLS wrapper support. Generic `goProfile` availability alone cannot establish it;
passive previews may succeed for an old node but actual TLS start/queue admission
refuses. Upgrade connectors before collectors because the old connector decoder
rejects unknown report fields. Old reports remain HTTP-only. No additional API,
RBAC, watch, Job or persistent record is needed. Focused component validation is
separate from installed TLS qualification, which remains pending.

## Finite policy endpoint scope

[ADR-296](../decisions/296-finite-policy-go-profiles.md) reuses C-03 policy
authority/approval, C-04 compilation, C-06 execution and the existing node/region
profile transport. A target-independent endpoint definition lookup runs over
the existing regional standby query path. Its selected protected definition and
binding enter the accepted policy configuration; concrete Pod routing remains a
separate child observation. Full hash-pinned grant scope is matched to that child
inside atomic admission. No new component, durable table, worker kind, listener,
credential or ongoing observation lease is introduced. Actual implementation and
qualification are tracked in [implementation progress](../implementation-progress.md).


## Verified case acquisition metadata

[ADR-297](../decisions/297-verified-profile-acquisition-metadata.md) passes the
existing authenticated profile manifest interval through verification, immutable
audit and the already joined catalog projection into C16 metadata. The interval
is HTTP acquisition, with UTC microsecond display precision and unknown
cross-source clock uncertainty/process attribution. It adds no object/key reads
or raw authority to case lookup; legacy records remain unknown. Qualification is
tracked in [implementation progress](../implementation-progress.md).

## Explicit refused acquisitions (ADR-298)

The existing diagnostics `ErrProfileUnavailable` and `ErrProfilerBusy` observations
remain distinct through node results, regional terminal completion and SQL/public
progress. Missing or disabled endpoints report `Failed` / `ProfileUnavailable`;
application-owned conflicts report `Failed` / `ProfilerBusy`. These terminal
outcomes create no evidence, replacement target, automatic retry or refund.
Only the application owner may stop its profiler. Bounded collector and installed
manual qualification passed under
[ADR-298](../decisions/298-explicit-go-profile-refusals.md); broader modes remain open.


## Refusing a summary before admission

Under [ADR-291](../decisions/291-bounded-profile-summary.md), only a
`get_profile_summary` authority-resolution failure proven to precede any query
admission carries C-18's private pre-admission refusal marker. C-20 turns it into
a content-free `NotAvailable`; denied, missing, unsupported and unavailable
source/provider cases share that same response and unavailable/none audit
outcome. REQ-PRF-005 and SC-PRF-003/005 therefore preserve native Go trace download
without attempting a pprof worker. This includes provider failure at that exact
pre-admission boundary, rather than misreporting it as an attempted query.

Audit completion, final current identity and original cancellation/deadline still
gate error delivery. Nonclassified and attempted/post-admission errors retain
their existing transport failure and conservative effects. SQL native-source
allowlists, ordinary rights, native parsers, funding and worker limits are
unchanged. Component composition tests use synthetic publication/permission
ports and do not establish installed trace qualification.

## Saved heap summary selection

C-20 passes C-16’s existing saved acquisition type to its source-scoped summary
form. Heap suggests editable `inuse_space`; legacy/CPU retains `cpu`. This adds
no read, preview, authority or parser: C-18 still verifies the exact selected
sample type and returns the authoritative unit/duration. The existing regional
worker and native-download boundaries remain separate. The focused heap
qualification and its current limits are recorded in
[implementation progress](../implementation-progress.md).


A history-backed single-profile repeat allocates eight seconds at entry within
the existing fifteen-second public preview window. Its one readiness hint is
not target or recovery authority. Initial recovery and current review remain
before it. The existing complete recorder resolution runs after readiness and
must return the same pinned target; final capability, eligibility, retention
and storage facts are independently read. One fresh recovery read must match
the initial installation, issuer epoch and full revision. Each final proof
retains its own original interval, and earlier request/history/policy ends and
final checks still apply. This adds three SQL reads/one bounded transaction,
zero Kubernetes reads or new background work. The browser selects the existing
fifteen-second preview bound up front; other capture operations retain ten
seconds. See [ADR-285](../decisions/285-profile-preview-plans.md).

Stored previews omit catalog documents. When creating a new profile review with
selected result access, the capture service reloads the exact referenced catalog
version and verifies its source UID/definition against the original canonical
scope before reconstructing the reviewed endpoint. The read retains the original
request/preview deadlines and post-read cancellation checks. Existing covering
grants return before this reconstruction; builtin profiles need no remote catalog
read. Submission still performs its existing current-catalog and authority checks.


The named installed heap run41818585176 passed on `80593f93` with a snapshot,
16 MiB output cap, five-second endpoint timeout and no forced GC. SQL checked
the installed Pod memory limit of 384 MiB and matching transient reservation,
ten units and one joined three-role key batch before authorized native
preparation. These are configured limits/reservations, not peak RSS. The 531-byte native original
opened with local pprof; its two samples sum to 4,326,741 bytes, exactly matching
the summary with null duration. This is a sampled total, not physical heap/RSS.
The subsequent fresh preview passed without collecting another profile. The
successful logs contain no detailed owner/demand phase markers; exact phase
ordering/count evidence remains source inspection and synthetic tests. No
installed heap browser click or maximum-shape resource claim follows.

### Named endpoint authorization (ADR-302)

Public `credential.audiences` names exact independently resolved workload roots;
its policy source reuses the protected endpoint identity and public definition
digest. Private material is absent from that digest. Recurring definition exchange
carries public policy/audiences only and reconstructs exactly the same manual
approval definition. It never carries header bytes.

The regional installer validates a separate bounded private map against precisely
the configured credentialed names and projects its fixed file from the existing
immutable RegionalEvidence Secret. Existing input UID/resource-version checks
cover it with zero extra API reads or Secret readers; no separate credential cache
or refresh service exists. A reader validates public expected sources and loads the private map once at
startup, then returns selected cloned bytes. It never rereads a replacement
projection: rotation requires the existing guarded reinstall/restart. The held admitted-work owner
checks exact node/work/epoch/original cutoff and workload audience before invoking
the reader, then rechecks after blocking work. Only a receive-only transient poll
envelope carries selected bytes; public collector.Work and pending queues remain
credential-free. Node TLS verification precedes the fixed Authorization header.
The original TLS/acquisition deadline is unchanged. Disabling removes the public
credential configuration and private entry through the existing guarded restart;
no separate rotation lifecycle or fallback is introduced.
