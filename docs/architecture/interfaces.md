# Internal interfaces

[I-14 — Private local key operations](local-key-service.md) defines the optional A-KEY mTLS wrap/unwrap/sign boundary under ADR-065. It is separate from public permission configuration and carries keys/signing inputs, never artifact payloads. Production current-authority/issuer/bootstrap composition remains required.

Public browser/MCP operations and schemas remain in the [interface package](../interfaces/README.md). These internal ports implement those operations. Interface IDs and callers/providers are recorded in the [catalog](catalog.yaml); none is an additional user permission API.

## Common contract rules

Internal control uses versioned strict JSON over authenticated TLS. Authenticate and enforce wire limits before decoding; reject duplicate JSON keys, nonfinite numbers, malformed UTF-8, unknown fields and ambiguous normalization. Accepted work uses the existing canonical scope rules, exact immutable IDs and portable integer limits. Never put an arbitrary callback, object URL, shell command or evidence row in a control envelope. Protected references resolve only inside a configured pool and authorized region; they are not bearer capabilities.

The [internal-work/v1 schema](../../specs/contracts/internal-work.schema.json) defines seven disjoint purposes and their receipts. `workId` identifies stable work; `operationId` identifies the parent operation; action `attemptId`, recording `snapshotId` and analysis `stageGeneration` identify effects independently of delivery. `issuerEpoch` binds recovery/enrollment authority, `deliveryFence` binds the current sender lease, `scopeDigest` binds the exact purpose-specific accepted scope, and `notAfter` caps a new start. `authorityRef`, `budgetRef` and `auditRef` resolve to purpose-specific, current, durable authorization. Their mere presence is not proof of validity. No generic “execute this payload” handler exists.

| Purpose | Payload | Required receiver behavior |
| --- | --- | --- |
| armSource | Source session/epoch, activation and action IDs | Verify ongoing mode, observation approval/resources and target before attaching. Duplicate work cannot create another source. |
| runAction | Capture/action/attempt IDs | Resolve the frozen onTrigger plan and durable start record; no action/argv override in transport. |
| saveRecording | Capture/snapshot/source/epoch, immutable end time, bounded lookback and original policy execution digest | Verify a recording-save scope, source rights and reviewed enablement. Dispatch only SnapshotExecutor. The 1-hour schema cap is a transport ceiling; effective source/policy limits can be shorter. |
| analysisStage | Analysis ID, acquire/analyze/publish stage, generation, exact input ref and output slot | Only the connector schedules the matching reviewed Job template. A claimed stage never proves the previous writer stopped. |
| eraseCopy | Exact copy identity/generation and deletion-work ID | Check current cleanup authority and the copy ledger. Expired acquisition grants must not prevent required deletion. |
| downloadArtifact | Exact download/artifact/digest and transfer generation | Schedule only the bounded download Job; no analysis, acquisition of new evidence or arbitrary destination. |
| projectLive | Watch/source/epoch, approved projection and view revision | Verify a live-purpose permit and independent view budget. Never arm a source or borrow capture authority. |

The schema describes decoded payloads; signed work additionally uses a standard JWS wrapper with a pinned algorithm/key purpose, protected `typ`, `alg`, `kid`, and the exact canonical payload bytes. Select trusted keys only from configured installation/cluster trust; reject `none`, algorithm/key substitution, remote `jku`/`x5u`, embedded untrusted keys and unsupported critical headers. Bind version, issuer epoch, intended cluster/node, purpose and deadline in the signed payload. TLS peer authentication remains mandatory. The selected signing suite and library qualification are recorded in [research](research.md); no hand-written signature framing or cryptographic primitive is permitted. The design fixtures remain unsigned DTOs; the initial [runAction verifier](../research/signed-work-foundation.md) now signs/verifies the runAction fixture with real ephemeral Ed25519 keys and adversarial protocol tests. It does not implement enrollment or dispatch authority.

Scope references can identify protected definitions that outlive a start permit. They must remain valid at resolution; their storage lifetime cannot extend execution or evidence retention. Receipts bind work/operation/cluster/epoch/fence and monotonically increasing sequence. `Completed` means that work stopped; its referenced result distinguishes success, partial, cancelled and failure. A receipt is not proof of artifact commit or copy deletion. Stale receipts can be retained as bounded reconciliation evidence but cannot overwrite a newer accepted state or refund a charge.

## Network and IPC contracts

### I-01 — Hub federation

Connector initiates requests to its configured hub origin. Bootstrap/renewal belongs to C-04 and uses one-use enrollment/current peer identity. After enrollment, separate mTLS connections carry control and transient delivery so traffic cannot monopolize cancellation or heartbeat. Proposed private routes under `/internal/v1/federation/` are `negotiate`, `poll`, `receipts`, `heartbeat` and `resolve-reference`; only peers can reach them. Endpoint literals are internal protocol, not additions to the public OpenAPI.

Negotiation binds peer/build identities, protocol major/minor, supported action/projection schema versions, maximum byte/item limits and issuer/enrollment epoch. Hub and connector support N/N-1 minors of the same major; use the negotiated strict schema, not field stripping of an unsupported accepted plan. Required capabilities fail explicitly. No downgrade may omit an authority/limit check. A protocol-compatible peer still needs qualified mechanisms.

Poll request carries connector epoch and an opaque continuation; response has up to 16 signed items, at most 256 KiB total encoded bytes, and a bounded retry hint. One signed item is at most 128 KiB and its decoded canonical control payload at most 64 KiB. Wait up to 25 seconds; transport timeout does not change operation identity. Receipt/heartbeat requests are at most 64 KiB and 100 receipt entries, whichever limit is reached first. Heartbeat defaults remain 15 seconds / offline after 60 seconds; heartbeat has independent scheduling. Compression is disabled for control in v1. Reference resolution has per-kind byte caps and never returns an unrestricted evidence object.

Delivery is at least once. SQL outbox/audit gate makes work eligible; a poll lease is not a start approval. The connector acknowledges Accepted only after its relevant local durable state exists. Lost acknowledgements cause replay of the same identity. Exponential backoff with jitter respects original deadlines; overload returns bounded retry guidance, not a fresh request. Error vocabulary: UnsupportedVersion/Capability, Denied, Expired, Conflict, StaleEpoch/Fence, CapacityUnavailable, DependencyUnavailable, Indeterminate. HTTP success does not replace checking disposition.

### I-02 — Node control

Collectors initiate mTLS requests to the private connector service with the same bounded work/receipt DTO family. Enrollment derives node UID from the admitted DaemonSet pod bound through current Kubernetes identity and records the node boot ID plus collector generation; request-supplied node names alone are insufficient. Scoped node credentials cannot poll another node's work or resolve another source's protected references. No privileged generic Kubernetes proxy is exposed.

Routes under `/internal/v1/node/` support negotiate/poll/receipts/heartbeat/resolve-reference plus typed `reserve-start`, `lookup-start`, `checkpoint-source` and `reconcile-spend`. The latter are narrow C-07/C-11 ports; they do not accept arbitrary CRD YAML or SQL. Start reservation binds operation/attempt, scope, node boot, prepaid bundle, exact charge and expected local revision. The connector CASes existing local control records and returns a signed bounded ticket or the existing disposition. A lost response is looked up; the node does not assume reservation failed. No new CRD kind or node-held general writer token is needed.

The initial [local start journal](local-start.md) implements the internal single-start `CapacityReservation` profile and non-retrying CAS adapter. These node routes, signed ticket issuance, current-reference resolver and local process exclusion are still pending. An adapter disposition is not a reusable network execution credential.

Sensors/sources may continue within existing leases when disconnected. Ordinary intrusive starts need the durable reservation and remaining permit. Natural-core acceptance is the prepared special path in I-03. Losing the local journal, boot identity or collector epoch makes past unproven starts unavailable/Indeterminate; a new leader cannot authorize replay by advancing only a delivery fence. Multi-node admission is conservative and may produce partial outcomes; it is not an atomic Kubernetes transaction.

### I-03 — Host core handoff

Use an installation-owned Unix-domain stream socket with restricted path ownership/mode, authenticated peer credentials and collector-generation handshake. The helper verifies the expected privileged peer; the collector verifies the permitted helper peer and independently resolves the kernel-provided process identifiers. UID alone cannot prove an executable identity against root; node/root remains trusted. No caller-controlled executable path or argument string becomes authority.

A fixed-version header of at most 4 KiB carries numeric IDs, node boot/process start identity when available and a nonce. The node either refuses promptly or returns a bounded acceptance tied to one preprepared envelope, durable spend allocation and monotonic byte/time limit. Only then consume bytes, with bounded backpressure and a hard close deadline. No remote refill, audit upload, DNS or key call occurs while holding the crashed process. The encrypted spool has its own budget. Exact Linux header/pidfd qualification is a required native-core spike; socket credentials alone do not solve PID reuse.

### I-04 — Gadget observation

The C-23 adapter drives only pinned approved gadget definitions via the selected build's qualified node-local API. Its public port is `Attach(VerifiedSource, Limits) → Session`, bounded event reads, atomic membership-generation replacement and `Stop`. No user gadget registry, script, path or arbitrary BPF program is accepted. It reports attach/restart/map-overflow/filter-update and entry/exit-pairing gaps. Qualification must establish the actual private transport and supported ABI for the pinned build before enabling it; the diagram is not proof that every Gadget version supports this topology.

### I-07 and I-12 — Transient live delivery and owner routing

[Pre-Ready owner enrollment proof](owner-enrollment-proof.md) binds the private CSR request to current online Pod-token/workload observations and accepted configuration. It adds typed C-04 ports, not a public listener or forwarding permission; durable registration and activation remain required.

[Private hub workload protection](owner-workload-protection.md) narrows namespace mutation before owner enrollment. It adds no public or network interface and supplies no forwarding authority. Current admission proof, historical installation integrity, token/CSR proof and certificate activation remain distinct checks.

A-HWORK owns a fenced LiveWatch projection lease; SQL stores only control/charges. Any A-HAPI replica accepts a browser/MCP request, resolves the current owner and forwards a bounded authenticated query over a private same-cluster mTLS service (I-12). The caller cannot supply a worker address. Forwarding binds authenticated viewer/client, watch revision/fence and query identity; the owner repeats current authority checks. No sticky browser session or new public endpoint is required.

The connector opens an outbound bounded exchange to the configured hub origin (`/internal/v1/live/exchange`), whose API ingress routes to the current owner (I-07). The exchange contains exact watch/source/revision bindings and already approved rows with original observation/expiry/coverage metadata. Existing live schema and public batch/output limits apply; no unbounded HTTP stream, websocket, raw payload, durable replay, SQL event row or control-outbox body. Each hop charges transfer/processing, expires rows and preserves loss provenance. A disconnected client cannot back up acquisition; bounded queues drop with a gap or close. Resume is bounded/current-source only. If the hub path violates region policy, reject the view; this design does not silently deploy a regional frontend or relax residency.

## In-process and staged contracts

### I-05 — Evidence commit and copy ledger

C-14 requests a C-15 copy registration with exact store/version generation, class, source times, parent lineage, reserved capacity, read cutoff and delete-by. Register pending copies before writing. A typed bounded writer compresses when appropriate, encrypts with unique material, tracks multipart/partial bytes and reports checksums inside protected manifests. Finalization verifies expected object/manifest state, completes artifact/lineage and converts reservations using the existing commit protocol. C-16 and C-17 consume commit references, never an upload-complete callback as authority. Original and derived copies have one authoritative privacy ledger; deletion and indexes cannot extend their age.

The initial [custody facet](custody-transactions.md) supplies registration, `CheckVerification`, unpublished ciphertext receipts and deletion work. It does not yet satisfy the complete finalization/publication boundary above. Cleanup binds the configured store identity, confirms the writer barrier, verifies all version/multipart inventory and acknowledges only the current SQL deletion fence. A no-op production writer barrier or a caller-supplied `verified: true` is not an implementation of this contract.

The subsequent [context verification facet](manifest-verification.md) adds `ContextExpectation`, `ContextVerifier` and `ContextCustodian`: match a complete authenticated manifest/native pod-status document to independently supplied target, audience, origin, classification and retention facts before storing receipts. There is no production accepted-execution resolver or persisted semantic-verification verdict yet. Both custodians still yield `stored_unpublished`; neither authorizes publication/disclosure. The catalog coordinator must establish current authority, durable audit and the full verification boundary itself.

### I-06 — Analysis handoff

C-18 owns one stage-generation state machine. C-15 registers input/output volumes before use. Acquisition writes exact inputs, exits and is confirmed terminated/unmounted; the analyzer mounts input read-only and output under its bounded policy with no network. After analyzer termination/unmount, a separate publisher walks outputs with confined paths, no-follow/type/size/count rules and trusted manifest fields. The controller fences old Job UID/generation and prevents simultaneous writers, including across a partition. Unknown detach/termination blocks the next stage. No shared emptyDir, executable input script, plaintext fallback PVC or user-supplied Job spec. Cleanup survives parent/controller failure.

### I-08 — Configuration projection

C-01 consumes typed Kubernetes list/watch objects through a read port and records full source identity plus opaque resourceVersion. A relist boundary is required after lost synchronization; freshness and accepted generation differ from authored generation. Deleted/recreated namespaces/resources invalidate old mappings. Permission configuration writes use Kubernetes RBAC/admission; configuration previews cannot become an alternate SQL configuration store. The transport must verify submission identity rather than attribute GitOps work to a privileged reconciler.

The initial [identity/eligibility facet](identity-eligibility.md) defines consumer-owned `TokenVerifier`, `PolicyReader`, `ProjectionReader` and `AudienceReader` ports. Token verification, the protected Kubernetes identity-policy reader and the accepted SQL permission projection now have concrete adapters. The committed-evidence AudienceReader remains pending. Current policy/source deadlines intersect token/group/key deadlines. `Result.ContributingAssignments` explains one caller's eligibility, not an execution permit or the complete audience to persist for a capture. Ordinary scope checks precede artifact lookup; raw/share/audit/effect gates remain separately required.

The subsequent [permission observation boundary](permission-observation.md) adds C-01 `PermissionReader` / `NamespaceReader` facets with a concrete Kubernetes implementation. Their values deliberately do not satisfy the accepted `ProjectionReader` contract. Binding lists are complete and at most five seconds old; automatic allow-source availability is separate. Namespace reads return selected metadata only. Current deny state, including an empty list, has an independent five-second interval in the evaluator. The subsequent SQL acceptance, encrypted authority audit, native admission guard and explicit-binding journal/reconciler now provide that boundary for AccessBindings; inherited-source acceptance remains pending.

The [owner configuration acceptance](owner-configuration.md) follows ADR-078: C-04 observes the protected source into a monotonic SQL head; C-08 writes/verifies encrypted audit and separately acknowledges the exact revision. Current route readers consume the audited projection under original freshness and fleet recovery, never a raw ConfigMap alone. Negative observations and known rollback fence old trust; acknowledgement cannot refresh it. This adds no public configuration API.

### I-09 — Transactional facets

Application services request named transactions such as AdmitCapture, PublishSelection, RegisterCopy or ExpireScope. Each transaction receives typed immutable proofs/expected versions and narrow owner facets. PostgreSQL acquires the existing canonical lock order; CAS/conditional writes enforce counters. It may retry the pure database callback within the existing bounded policy, never process actions or remote I/O. UNKNOWN commit is resolved by operation uniqueness. Kubernetes local spend uses a distinct CAS contract; there is no interchangeable universal repository claiming identical atomicity.

The initial [context admission facet](context-admission.md) now atomically rechecks SQL authority after locks, binds workload storage, reserves all four objects and saves independent manifest expectations. It also has a separately credentialed encrypted-intent publisher with exact durable acknowledgements. Neither acceptance nor intent acknowledgement dispatches or publishes evidence.

### I-10 — Collector adapters

The consumer-owned Go ports below describe responsibilities; exact production types are generated/reviewed in the first slice. Every method receives a framework-constructed verified scope, finite limits and cancellation context, never just a pod name or arbitrary argv. A port is not a Go plugin ABI or a network endpoint.

```go
// Illustrative interfaces: no runtime code or unforgeable-capability claim.
type ActionAdapter interface {
    Describe() MechanismDescriptor
    Acquire(context.Context, VerifiedAction, BoundedEvidenceWriter) (ActionOutcome, error)
}
type RecordingAdapter interface {
    Arm(context.Context, VerifiedSource) (SourceHandle, error)
    Snapshot(context.Context, VerifiedSnapshot, BoundedEvidenceWriter) (Coverage, error)
    Stop(context.Context, VerifiedStop) (StopOutcome, error)
}
type LiveProjectionAdapter interface {
    Read(context.Context, VerifiedLiveRead) (BoundedLiveBatch, error)
}
```

Descriptor fields include immutable mechanism/schema/projection versions, supported action kinds/modes, kernel/runtime/privilege prerequisites, required qualification reference, data classification/impact rule, budget dimensions, readiness and cancellation/loss behavior. Passive Describe cannot attach, sample or inspect user data. The dispatcher constructs typed scopes only after current checks. Adapter code is trusted but isolated and tested; a Go interface alone is not a security sandbox. Block arbitrary outbound URLs, host paths and uncontrolled writer access. Snapshot-only dispatch depends on the snapshot port, not ActionAdapter, so it has no callable dump path. Packet/syscall onTrigger variants still use their explicit zero-history semantics.

### I-11 — Analyzer adapters

`Analyze(context, VerifiedInputs, TypedQuery, BoundedOutputTree) → AnalysisOutcome` runs only in the offline role. Descriptor pins tool/image/runtime pack, input kind/sample units, supported approved/raw queries, required private symbols and output classification. No network fallback, shell interpolation, target code execution or arbitrary debugger commands. Stderr/stdout are bounded and treated as potentially sensitive evidence, not central service logs. Publisher validation is independent of an analyzer's self-reported paths, class or retention. Missing symbols or incompatible profiles produce explicit unavailable/partial results.

### I-13 — Native artifact byte relay

[ADR-206 context projection](context-projection.md) permits reuse of bounded
verification/TLS/framing primitives for an explicitly distinct query operation.
Its approved DTO, query admission, worker/key ledgers and original five-second
request authority must remain separate from native-download sessions and ranges.
No existing download command/profile is implicitly query-capable. This extension
is an implementation contract with native qualification pending.

[ADR-122](../decisions/122-private-native-owner-listener.md) composes an optional
separate native HTTP/2 port on the exact accepted owner Pod/process, with protected
worker API/topology pins and a distinct read/lock SQL credential. Its bounded
listener joins shutdown; credentials and request callbacks retain their original
authority. Connector server identity, installed projection provisioning and public
download mounting remain separate requirements. See the
[listener contract](native-owner-listener.md) for limits and qualification scope.

A download-only acquisition Job opens an authenticated regional connector stream for its exact transfer generation. The connector initiates the bounded outbound relay to the configured hub ingress; the authenticated HTTP reader receives native bytes. Purpose, artifact/version, actor/client, region, range, original deadline and delivery fence are bound and rechecked under [REQ-DLD-003](../../specs/artifact-downloads.md). Separate bounded queues and short authorization leases apply; no arbitrary callback, storage redirect, durable byte queue or SQL/outbox payload. Range bytes are distinct from live projections and control receipts. Resume may reread verified ciphertext only inside a reserved decode/read-work budget; no plaintext disk cache. Hops that violate locality block the transfer.

[ADR-113](../decisions/113-large-native-response-accounting.md) requires a distinct
whole-response lifetime, prepaid accounting windows and current short leases for
large files. Only the original hub reader retains human authentication; no
serialized identity or decoded authority-shaped message can replace independent
peer, stored-operation and current-generation checks. Accounting measures the
final HTTP handoff, not merely a connector's successful send. The existing
credential-operation locators and certificate channels do not become long-lived
native ownership by extending their deadlines. Native protocol composition is
still pending.

The [context publication continuation](context-publication.md) now implements the initial C-14 verification/catalog transaction and a SELECT-only `AudienceReader`. This supersedes the earlier absence of persisted semantic-verification/catalog facets. External result/privacy authority, disclosure audits/native sessions and public composition remain required; generic custody does not confer visibility.

Private acquisition credential bootstrap within I-13 follows [ADR-072](worker-credential-channel.md): pinned server TLS plus current Pod-bound token/CSR, bound to active authenticated control. Its certificate response is separate from native evidence bytes and does not confer download authority.

[ADR-074 request ownership](worker-request-routing.md) adds the bounded process-local owner registry and private response lifetime. Registration checks current human scope and admitted SQL worker identity; original cancellation/deadlines survive response write/flush. Cross-replica and connector/hub owner rendezvous remains required and is not supplied by this local registry.


[ADR-075 shared locators](worker-owner-locator.md) provide the finite request-to-hub-process mapping for I-13 and an exact local owner receiver. The mapping stores no address or credential and grants no authority. Private forwarding must independently authenticate the named process and current connector-origin proof; that transport remains pending.

[ADR-076 owner discovery](hub-owner-discovery.md) adds bounded pinned hub-cluster EndpointSlice/Pod/account/Deployment observations and exact TLS Pod/process identity verification. Both are required before a future forwarder transmits credentials; they do not themselves qualify protected bootstrap, certificate activation, current owner authority or the network path.

[ADR-077 owner configuration](owner-configuration.md) supplies protected public pool/root observations and checks matching current configuration around discovery. The original deadlines survive composition. Durable acceptance/recovery, certificate activation and authenticated forwarding remain separate prerequisites.

The private [owner certificate issuer](owner-issuance.md) consumes an already-spent, original-deadline permit under ADR-079. It returns a verified leaf/chain only; durable activation and actual TLS/current-owner checks remain separate. Server and client signers have distinct fixed provider roles. No public enrollment or forwarding endpoint is introduced by this port.

[ADR-082 owner enrollment](owner-registration.md) adds private typed enrollment-ledger, certificate-activation/registry, current-crypto-verifier and retirement/pruning ports under C-04, with separate C-11 encrypted audit writer/acknowledgement facets. They do not add a public permission or enrollment API. Certificates remain unusable without actual TLS/current trust and exact request/developer authority.

[ADR-083](owner-authentication.md) adds C-04 `OwnerPeerConnection` and `OwnerProtectionReader` private ports. The former is backed by an actual verified TLS snapshot; the latter is bound to the independently pinned native workload. `AuthenticatedOwner` is finite transient identity, not a wire bearer capability or a replacement for current locator/developer authority.

[ADR-084](owner-credentials.md) adds C-04 `OwnerCredentialEnrollment` and `OwnerCredentialClient` in-process ports. The existing audited coordinator supplies enrollment; C-21 owns process keys and TLS callbacks. Paired supervision provides nonblocking identity status only. There is no new enrollment HTTP endpoint, public permission API or evidence grant.

[ADR-085](owner-relay.md) adds C-04 `OwnerServingIdentity`, C-14 `WorkerOwnerEnrollment` and the private C-20 [owner relay request](../../specs/contracts/owner-relay.schema.json). Local serving checks never fabricate remote TLS; wire locators resolve existing live registrations only. Current admission and output checks preserve original operation deadlines. The public worker request/response contract is unchanged; outbound forwarding remains separate.

[ADR-086](owner-forwarding.md) adds C-04 `OwnerClientIdentity` and C-14 read-only `WorkerOwnerLookup`, without changing I-13 wire or the existing live delivery contract. C-21 performs one finite verified transfer; its public certificate result cannot become a remote owner context or evidence capability.

[ADR-087](../decisions/087-live-owner-delivery.md) changes the private owner wire to v2: one bounded length-prefixed response frame followed by an open silent body. C-21 now implements the existing C-14 `WorkerEnrollmentExchange` with a live cancellation context, retained socket and joined monitor. C-20's worker handler closes that delivery after its response flush. No new interface ID, durable entity, user API or evidence authority is added.

[ADR-088](owner-startup.md) adds the private C-04 `OwnerReadinessIdentity` public CSR/certificate snapshot port and finite readiness check. C-21 supplies the process-owned adapter; bootstrap joins current components. No new I-13 wire, durable entity, outward API or evidence permission is introduced. Readiness is a scheduling hint, not an authenticated peer or operation grant.

[Multi-cluster I-13 routing](worker-routing.md) uses installation/root-bound `WorkerEnrollmentBindings` and `WorkerOwnerLookup` reads, with exact current stored profile and control-digest issuer selection. The catalog provides public material only; profile-scoped effects and live delivery limits are unchanged.

[ADR-090 protected deployment](owner-deployment.md) adds private installation DTOs for fixed public provider/pin inputs, separate credentials and an exact worker-control bundle. Bootstrap constructs existing ports; no new public interface, entity or evidence authority is introduced. C-21 mounted-file reads support confined projection rotation; current accepted SQL/native proof remains independently required.

[ADR-091 reconciliation](configuration-reconciliation.md) adds a private installation DTO and reuses current C-04 administration/configuration and C-08 audit ports. The scheduling Lease conveys no I-13 peer, evidence or recovery authority. Original source deadlines and monotonic SQL checks remain required after every blocking operation.
