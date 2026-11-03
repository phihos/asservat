# ADR-286 — Bounded Go analyzers in the regional acquisition worker

Date: 2026-11-03. Status: accepted architecture choice under explicit maintainer
delegation; implementation and qualification pending.
Requirements: REQ-EVD-005/008, REQ-PRF-003/005, REQ-MCP-003/005.
Supersedes ADR-036's universal scratch prerequisite only for the class below;
resolves M1 in the [S-05 plan](../reviews/s05-plan-2026-11-02.md).

## Decision and authority

During continuation of Claude session `06c27237-b261-43c1-9d73-4b617059a89d`,
the maintainer explicitly delegated the M1 architecture choice. The selected
implementation is the existing regional acquisition worker for bounded Go
analyzers. The earlier request for a further maintainer choice is resolved.
This changes the analysis mechanism, not collection/disclosure authority or
first-release feature scope. It enables no runtime capability by itself.

An explicitly qualified analyzer from a maintained Go library may interpret data
and produce a closed projection inside the existing regional worker. It receives
bounded bytes and approved parameters, never an evidence-selected URL, path,
command, plugin or callback carrying credentials. It runs no external process,
script or evidence-supplied code. Symbol lookup over the network is prohibited;
a qualified symbol input must be separately authorized and digest-bound. The
worker keeps only the existing scoped transport and key capabilities. The hub
never receives raw input or unwrap keys. Parser code shares the worker process
and its credentials: this is an accepted residual exposure, not a sandbox claim.

Native-code tools, subprocess analyzers such as GDB/tshark, plugins and any
execution of evidence-supplied content retain ADR-036's separate acquisition,
analysis and publication Jobs with qualified encrypted scratch. No plaintext PVC,
cross-Job emptyDir or network-policy phase switch substitutes for that boundary.
This decision does not require new scratch copies for transient Go projections
and does not authorize storing a derivative without ordinary custody checks.

## Bounds and remaining risk

Each analyzer must declare finite native/compressed input, decompressed input,
parser work/structure, output and elapsed-time bounds. Apply limits before growing
buffers; post-parse checks do not bound allocations the parser already made.
Use worker container CPU and memory limits with room for decoding, object graphs,
crypto, transport and output together. Measure each advertised maximum shape.
An input-size cap alone does not establish an acceptable object-graph expansion.

Go's memory limit is a process-wide soft target; it may be exceeded to avoid GC
thrashing and excludes memory outside the runtime. `GOMEMLIMIT` cannot isolate
queries sharing a process or guarantee an allocation ceiling. [Go GC guide](https://go.dev/doc/gc-guide#Memory_limit).
Kubernetes CPU limits throttle CPU rate; memory enforcement can terminate an
allocating container through OOM and is reactive. Neither proves successful
completion at the configured bound. [Kubernetes resource limits](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits).
A Go cancellation function signals cancellation without waiting for work to stop.
Therefore a context deadline alone cannot terminate a parser that does not check
it. [Go context cancellation](https://pkg.go.dev/context#CancelFunc).

The engineering consequence is a two-part limit: bounded parser inputs and work,
plus the worker process/container boundary for failure containment. Original
operation deadlines fence disclosure immediately; cancellation closes delivery
and requests shutdown. A parser that has not joined keeps its worker charged and
unavailable for reuse until actual completion or independently observed process
termination. Do not release capacity, refill key slots, retry a query or extend
its deadline on OOM, panic, timeout or uncertain cleanup. A container limit is
not described as a hard per-query Go heap or precise CPU-time limit.

Current ordinary/raw rights, original retained audiences, retention, recovery,
prepaid query limits, exact artifact versions, one-use key slots and durable audit
remain mandatory. Parsing success cannot grant access, prove remote cleanup or
classify arbitrary text as an extract. Validate the projection's closed fields,
size and current delivery authority after blocking work. The existing logging,
core/swap and transient plaintext rules still apply.

## Complexity gate

| Question | Cumulative answer |
| --- | --- |
| 1. Observed frequency/harm | Required profile/network queries; no measured parser exploit in this project. Malformed-input and resource-exhaustion cases are qualification inputs, not observed attacks. |
| 2. Accepted risk | Yes: maintainer delegated M1; agent selected shared worker credentials for this bounded class. ADR-036 remains for native tools. |
| 3. Typical deployments | Yes: profile summaries and packet projections are ordinary investigations. |
| 4. Comparable behavior | Existing ADR-244/248/282 publisher/worker parsing is local precedent. Go and Kubernetes document the limit mechanisms below; no external product is claimed to provide an identical security boundary. |
| 5. Added privileges/exposure | Zero new RBAC, credentials or network destinations. More parser code sees the existing worker process; it is not isolated from scoped credentials. |
| 6. Added states | Zero additional persistent lifecycle states; reuse query failure and uncertain retirement. The alternative adds six staging/handoff/cleanup states. |
| 7. Self-tuning configuration | No new user configuration solely for isolation. Per-analyzer limits and worker resource profiles must be qualified. |
| 8. External dependencies | Maintained Go parsers and existing runtime/cgroup enforcement; no new CSI dependency for this class. |
| 9. Aggregate cost | One existing worker per query, zero extra Jobs/PVCs/API watches. At concurrency N, reserve N times the qualified worker profile, including buffers. Alternative: two extra Jobs and two PVCs per query, provisioning and cleanup. No latency or memory percentage is claimed. |
| 10. Disable/rollback | Keep each new analyzer unavailable until qualified; disabling removes new admissions and existing original work remains fenced/charged through retirement. No SQL or persisted layout change in this ADR. Runtime rollback remains to be tested when composed. |
| 11. Smaller fix | Reuse the worker and bounded library; native download remains available for artifacts that cannot be analyzed within the qualified limits. It does not substitute for required first-release query features. |

## Acceptance evidence required

No row below is passed by this documentation change:

- Maximum-shape and hostile compressed inputs: account for native data, expansion,
  parser object graphs, output, crypto and transport together; measure peak process
  memory, CPU use and elapsed time at the chosen worker resources and concurrency.
  Refuse unsupported shapes before publication of a result; never trim raw evidence
  to make an analyzer pass.
- Fuzz parser inputs and independently validate projected outputs. Test wrong
  symbols, incompatible sample units and secret-bearing labels. Only approved
  fields leave the worker; normal logs and errors carry no evidence.
- Cancel during decoding and parsing; exercise OOM/process failure and a parser
  that has not joined. Prove no late result, replacement query, budget refill or
  early capacity release, and observe eventual worker retirement. Test original
  deadline/expiry/revocation checks after blocking reads.
- Verify no child tools, plugins, evidence-selected filesystem paths, symbol/URL
  fetches or evidence-bearing crash/log output. Test egress restrictions on a
  network-policy-enforcing profile, retaining only required worker transports.
- Real SQL/key/worker composition and installed MCP/browser query-to-result tests
  prove exact artifact authority, shared quotas and original cancellation. Record
  source hashes, actual terminal exit and cleanup. Component parsing and small
  fixtures do not qualify maximum-size or full installed operation.

REQ-EVD-005 and SC-EVD-005 own the isolation and failure acceptance; REQ-PRF-003/005
own profile semantics and comparison. EXP-13/14 and the S-05 exits remain open.
