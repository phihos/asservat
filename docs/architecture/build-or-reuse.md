# What Asservat builds and what it reuses

Planning baseline, 2026-10-09. Read with the [technology decisions](../technology.md), [measured experiments](../../experiments/technology-selection/README.md) and [qualification plan](../research/technology-selection.md). This covers every component in the [architecture catalog](catalog.yaml). Reuse means an integration we must implement and qualify; it does not mean that the component already exists.

Use existing software for protocol mechanics, storage, cryptography, UI primitives and diagnostic engines. Build the product rules that bind these together. No evaluated library provides Asservat's combined workload authority, disclosure approvals, incident budgets, retention, provenance and failure semantics.

## Component ownership and reuse

Size is relative implementation/qualification effort: S = narrow adapter, M = ordinary subsystem, L = several coupled workflows, XL = substantial distributed or kernel-facing subsystem. It is not elapsed time. Shared integrations appear in several rows and must not be counted repeatedly.

| Component | Reuse | Asservat must implement | Size / decisive qualification |
| --- | --- | --- | --- |
| C-01 Configuration | controller-runtime, client-go, controller-gen, Kubernetes structural schema/CEL | Accepted configuration projections; immutable profile publication; exact actor request bridge; conflicts, freshness and Conditions | M; real admission and resourceVersion races |
| C-02 Identity | coreos/go-oidc, x/oauth2, standard TLS/x509, configured IdP | Enrollment, actor/client binding, session/CSRF handling, step-up verification, rotation and disconnect behavior | L; wrong issuer/audience/client, key rotation and stale sessions |
| C-03 Authorization | Kubernetes SubjectAccessReview; CEL for finite configured predicates | Permission inheritance, protected metadata trust, combined capture/result grants, current rights, shared disclosure counters, revocation and owner rules | XL; concurrent spend/revoke and confused-deputy tests. No generic RBAC library replaces these rules |
| C-04 Fleet | Kubernetes informers, TLS and JWS library | Cluster/node identity, epochs, capability versions, enrollment and stale-peer rejection | L; partition and old-process exclusion |
| C-05 Targets | Kubernetes owner references, EndpointSlices, label selector parser, CRI API | Qualified ownership resolution, all-replica monitoring, immutable execution pins, process-reuse checks and coverage gaps | L; rollout, PID reuse, network namespace and NAT ambiguity |
| C-06 Planning | JSON Schema, cel-go, reusable profile data | Composition, finite typed edits, scope digests, impact/privacy assessment, deterministic guidance and preview handles | L; no preview side effects, source expiry, aggregate budgets |
| C-07 Capacity | PostgreSQL transactions, row locks, Kubernetes CAS | Protected allocations, burst pool, fair scheduling, local prepaid slices, conservative uncertain spend, workload-wide storm protection | XL; races, disconnects and noisy-neighbor isolation |
| C-08 Audit | S3 SDK, SHA-256, maintained DSSE implementation for attestations | Content-minimized intent/outcome records, commit gates, immutable links, reconciliation and operator verification | L; audit outage and lost acknowledgements |
| C-09 Capture | SQL queries and durable work rows | Immutable accepted capture, idempotency, action lifecycle fanout, cancellation, output binding and combined-approval children | XL; no duplicate intrusive effects after retries |
| C-10 Monitoring | Go regexp, cel-go, Kubernetes watches, CRI log readers, cgroup/proc parsers | Bounded temporal AST evaluator, Unknown/stale handling, coalescing/cooldowns, detector cursors and correlation | XL; 10,000-match storm, lost events, restart and temporal semantics |
| C-11 Execution | Go context/process/syscall facilities, CRI protocol | Signed purpose checks, current authorization, permit spend/start journal, process selection, cancellation and uncertain outcomes | XL; crash before/after an irreversible start |
| C-12 Recording | Gadget streams, gopacket PCAPNG writer, Tink/zstd | Segmented rings, sequence/time coverage, reservations, source leases, save-now cutoff, independent retention, loss accounting | XL; pressure, overlapping saves and bounded memory/disk |
| C-13 Live observation | React views; existing HTTP/MCP transports | Approved projections, finite viewer lifecycle, bounded replay, owner failover, filter/pause semantics and incident priority | L; slow readers and revocation, no durable live payload |
| C-14 Evidence | AWS S3 SDK, Tink, zstd, SHA-256 | Commit/verification protocol, manifests, acquisition/derivation lineage, partial-file distinction, authenticated native decoding | XL; corrupted/truncated uploads, range integrity and exact local-tool bytes |
| C-15 Privacy | Object/CSI APIs and SQL persistence | Acquisition-based deadlines, copy ledger, early erasure, verified deletion, restore fences and overdue accounting | XL; replicas, backups, unreachable nodes and shortened deadlines |
| C-16 Catalog and history | PostgreSQL indexes, regional Bleve index | Authorized search/counts, case signatures/aliases, selector history, immutable repeat snapshots and independent expiry | L; ACL changes, history loss and cache eviction |
| C-17 Sharing | Identity/group facts and SQL transactions | Multi-owner management, concrete shares, bounded future instructions, draining/revoke and exact output eligibility | L; late outputs, mixed parents and revoked owner authority |
| C-18 Analysis | Pinned GDB/Delve/pprof and qualified runtime packs | Typed operation adapters, exact companions, stage fencing, resource/output limits, redaction/projections and parser isolation | XL; hostile inputs, wrong symbols and untrusted outputs |
| C-19 Delivery | Go HTTP streaming, S3 Range requests, CloudEvents/Standard Webhooks libraries | Current-read checks, transfer reservations, resume limits, native filenames/checksums, live relay and minimized notification outbox | L; mid-transfer revoke/expiry, backpressure and duplicate delivery |
| C-20 User and peer transports | Go net/http, official MCP SDK, React/TypeScript, React Aria, TanStack Query, React Router | Shared service adapters, console workflows, typed error mapping, bounded browser state, human approvals and Kube request bridge | XL; whole user journeys, accessibility, schema parity and no authority in browser code |
| C-21 Persistence adapters | pgx, sqlc, goose, client-go, AWS S3 SDK, OpenBao client, go-oidc, Bleve | Consumer-owned port adapters, explicit credentials, transaction facets, retry classification and qualified backend behavior | L; real PostgreSQL/S3/KMS integration, no alternate authority |
| C-22 Host crash helper | Rust standard library and narrowly reviewed Linux syscall bindings | Bounded local Unix-socket handoff, trusted peer checks, fail-fast limits and exact helper ABI | M implementation / high risk; disposable-VM kernel pipe and shutdown tests |
| C-23 Mechanism adapters | Gadget Go/runtime APIs, OpenTelemetry eBPF profiler for CPU profiles (ADR-201), cilium/ebpf where needed by the qualified integration, libpcap compiler, gopacket, CRI clients, diagnostic tools | Whole-pod mapping, generation-swapped peer maps, bounded HTTP projection, no-read syscall metadata mode, files/commands/profiles/core adapters | XL; largest engine gap. A custom pinned Gadget/BPF extension may be required |
| C-24 Domain types | Standard Go value types; Go 1.27 standard-library RFC 8785 canonicalization at serialization boundaries | Explicit finite unions, invariants, immutable identities, pure transitions and conversions | M; cross-language canonical vectors and layer/import checks |

Library-specific objects stay in adapters. Domain types do not import pgx, Kubernetes, React, MCP or Gadget types. A protocol client is never the owner of access decisions.

## Mechanisms and runtime packs

| User outcome | Reuse / package | Integration still required |
| --- | --- | --- |
| Open packets in Wireshark or another compatible tool | PCAPNG via maintained gopacket; libpcap capture-expression compiler; offline tshark where qualified | Link types, timestamps, original/captured lengths, interfaces, gaps, authenticated native download; projection artifacts must not pretend to be original packets |
| Follow a changing Service/Deployment/StatefulSet | Kubernetes EndpointSlice/workload watch; Gadget/BPF attachment | Authorized membership generations, atomic map replacement, retirement/loss reporting; no documented general Gadget hot-filter RPC is assumed |
| Capture plain HTTP headers | TCP decoding/reassembly building blocks; explicit HTTP/1 parser | Bounded flow state, partial requests, header allowlist/removal, malformed traffic, TLS/HTTP2 capability reporting. A short snaplen is insufficient |
| Record syscalls | Qualified Gadget traceloop/related BPF program | Metadata mode that never reads user memory, process attribution, ABI support, error pairing, quotas and optional separately approved arguments |
| Open a native core locally | Kernel ELF core; live gcore in a pinned acquisition pack; exact available executable/libraries/symbols | PID/start identity, pause/impact reporting, bounded serial multi-process selection, companion fidelity and downloads usable by the developer's compatible debugger |
| Analyze native/Go cores on the server | Pinned GDB and Delve | Typed bounded commands, disabled startup scripts/public symbols/listeners, exact images and separate encrypted analysis stages |
| Capture CPU/heap/runtime profiles | Go pprof endpoints and google/pprof parser/tool | Endpoint permission/caps, native protobuf download, unit/build compatibility and finite comparisons; no profiling backend required |
| JVM/.NET/Python/Node/CUDA diagnostics | async-profiler, jcmd/MAT, dotnet diagnostics, PyStack/py-spy, Node diagnostics, CUDA-GDB as applicable | Separate optional capability/image/license qualification. They are not interchangeable full-core mechanisms and are not all required in the base image |
| Files, `/proc`, commands, pod context | Linux APIs, Kubernetes/CRI clients; pinned allowlisted diagnostic executables | Namespace/path safety, deadlines/output caps, process provenance, unavailable-tool behavior and user-data classification |

Do not reimplement Wireshark, debuggers, runtime profilers, an IdP, object storage or a database. Do not embed Kubeshark's whole product merely to obtain packet parsing: it would bring another authorization/UI/lifecycle model. The existing selected Gadget integration remains the engine boundary.

## What operators supply

For temporary installation SQL passwords, reuse `xdg-go/scram`'s stored-verifier
API and pgx's enforced SCRAM connection authentication. Asservat owns finite
credential state, exact grants/replay, persistence orchestration and retirement;
do not implement password cryptography or let installation roles leak into runtime.
See [ADR-100](../decisions/100-temporary-initial-sql-credentials.md).

The capability contract is PostgreSQL, regional S3-compatible evidence storage, purpose-scoped key services, qualified identity, Kubernetes and—when server-side offline analysis is enabled—qualified encrypted scratch CSI storage. These need not be separately operated services. [ADR-063](../decisions/063-small-deployment-alternatives.md) requires internal users/login, static-key services and Helm-provided PostgreSQL alternatives, with a small evidence-store option. [Research](../research/small-deployments.md) recommends bundled SeaweedFS, single-instance PostgreSQL/pgBackRest and maintained Go identity libraries; all new provider/profile integrations remain unqualified. External reference integrations remain PostgreSQL 18, Ceph RGW, OpenBao and Keycloak. Reuse existing qualified services or explicitly select bundled ones; never install a hidden infrastructure estate. No Redis, Kafka, NATS, Elasticsearch, Temporal, Node server or dedicated profiling service is required.

The local alternative adds real product responsibilities: C-02 owns accounts/authentication lifecycle, C-01 provider/bootstrap configuration, C-14 the unchanged artifact encryption contract and C-21 provider adapters and database/store lifecycle integration. C-03 still owns all evidence authorization. Proposed local key-service scheduling/ports, account entities and exact DTOs must enter the canonical catalog/schema alongside their implementation; they are not implied to exist by this dependency selection. Reuse OAuth, WebAuthn, AEAD, TLS/X.509 and pgBackRest implementations; do not build cryptographic primitives, an OAuth protocol stack, database failover or a new filesystem object store.

Rust, Node/npm, TypeScript, Vite, sqlc, controller-gen, Python validators, Playwright, image builders and supply-chain scanners are build/test tools. Runtime packs are isolated executables/images, not always-on services. The existing HTML/CSS/JS mockup remains a design artifact; production React work starts from its workflows and visual tokens.

## Work planning and unresolved user journeys

The main implementation cost is safe coordination under failure, then kernel mechanisms and complete investigation UX. Existing libraries reduce low-level implementation; they do not justify describing the platform as mostly assembled. Avoid estimating it from 63 screens or the number of generated structs.

Before committing to a delivery date, timebox S-00 into: (1) authenticated artifact/download and storage experiments, (2) packet/syscall/host-crash experiments in disposable VMs, (3) PostgreSQL races/restore and identity integration, and (4) one complete developer workflow with real services. Record actual engineer effort per boundary, then estimate S-01–09 with that evidence and team availability. These can produce independent evidence; none waives dependencies for enabling product features.

The [user-task review](../reviews/user-task-review.md) still has open product decisions: temporary watches, incident time navigation, private companion intake, stable postmortem eligibility, linked investigations, trigger sample/replay, approval routing and batch download (U03–07/U09–11). Reserve explicit design/implementation work for them; React or a queue library does not solve them. No permission expansion or new upload API is silently introduced by this technology selection.
