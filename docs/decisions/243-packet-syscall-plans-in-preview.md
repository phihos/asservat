# ADR-243 — Packet and syscall plans in preview (S-04 increment 1)

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-NET-001 (SC-NET-001, new SC-NET-007), REQ-LIF-001/005, REQ-CPR-001/002/004/005
(new SC-CPR-006), REQ-ASM-001–004, REQ-SYS-001/002 (metadata mode only). Plan:
[S-04 plan](../reviews/s04-plan-2026-10-27.md) §4 row 1 with simplifications S2 (hub-side filter
compilation) and S6 (embedded builtin profiles), §4 interim behaviour and §4.1 (no grant for
metadata recordings). No migration: the plan-only preview reuses the ADR-103 passive blueprint
table, whose JSON blueprint gains one optional field.

## Problem

Packet and syscall recordings are the second and third action kinds. Before any node recorder
exists (increments 3–4, 10), users and agents need to see what such a capture would do: which
mode it runs in, what it records before and after a trigger, what its filter compiles to, what it
costs while armed and per incident, and what data it may retain. Without a typed compiler, every
later increment would invent its own plan shape, and the libpcap filter, the plan digest and the
assessment would have no single owner.

## Decision

1. **Selection: one embedded builtin profile.** `preview_capture` gains its third selection form,
   `profile_composition`, with exactly one component referencing `builtin/network-connections/v1`
   (packet `networkHeaders`) or `builtin/syscall-activity/v1` (syscall `metadata`). The
   definitions are embedded in the release binary (S6), are byte-for-byte the definitions of
   `examples/capture-profile-*.yaml` (a test keeps them equal) and are identified by their
   definition digest. Their resolved provenance and `captureProfile` dependency carry no source
   object; `capture-composition.schema.json` and `collection-scope.schema.json` now say so, and the
   composition fixtures were regenerated. The network preset ring is the spec's 16 MiB/30 s ring
   (REQ-NET-003) instead of the fixture's earlier 4 MiB. Organization and namespace catalogs,
   other builtins and composing several profiles are refused with `ProfileUnavailable` or
   `InvalidComposition` and their field path (increment 11).
2. **Typed edits only.** The runtime accepts the exposed `packetFilter`, `packetBefore`,
   `packetAfter`, `packetRing`, `syscallFilter`, `syscallBefore`, `syscallAfter`, `syscallRing`,
   `syscallMaxEvents`, `syscallRate`, `actionTimeout` and `actionExecutionMode` edits (the runtime
   schema lists only these value types). Unexposed, unknown, duplicate or mistyped edits are
   refused with their path. Edits are applied first, then the plan is validated as a whole:
   `executionMode` defaults to the kind's `ongoing`; `onTrigger` requires `before: 0s` and a
   positive `after`; at least one window is positive; `before` ≤ ring age ≤ 1 h; ring 2–64 memory
   segments, segment × count ≤ ring ≤ 256 MiB (the encrypted-disk medium is increment 16);
   syscall `after` ≤ 60 s; frozen bytes ≤ the action output limit; action timeout ≥ `after` + 5 s;
   the summed output and longest timeout fit the authored `maxTotalBytes`/`maxDuration`, which are
   never raised. HTTP headers, raw packets and syscall arguments are refused with
   `ApprovalRequired` (§4.1); the builtin profiles cannot select them.
3. **Hub-side libpcap (S2).** A packet filter is screened, then compiled on the hub: at most
   4,096 bytes of printable ASCII and 256 syntax tokens; every word must be a supported primitive
   or a numeric, IPv4/IPv6, CIDR, MAC or port-range literal, because libpcap resolves host,
   network, Ethernet, protocol and service names (and `gateway`) while compiling, so a name never
   reaches it; escaped names (`\tcp`) are refused for the same reason; any `proto[offset]`
   comparison is `ApprovalRequired`. libpcap 1.11.0 (`pcap_open_dead`, link type `EN10MB`,
   snapshot length 65,535, optimizer on) compiles the whitespace-normalized expression; more than
   256 instructions is refused with a remedy. The program and its digest (SHA-256 over little-endian
   `struct sock_filter` bytes) are part of the plan, so the execution digest binds the program the
   node will run.
4. **libpcap only in the hub build.** `internal/adapters/pcap` (C-23) holds a cgo binding built only
   with `cgo && libpcap` and a stub otherwise; a build without it refuses filter edits with
   `FilterCompilerUnavailable` and still previews unfiltered plans. libpcap is built from the
   signature-verified 1.11.0 release as a static archive with every capture backend that needs
   another library disabled (`make libpcap`); `make pcap-check` runs the real compiler tests and a
   fully static `-tags libpcap,netgo,osusergo` hub build, as a FROM-scratch image needs. CI's `go`
   job runs it (cached archive). All other roles and the default product build stay cgo-free.
5. **The plan: `recorder-preview/v1`.** The canonical document (new
   `specs/contracts/recorder-preview.schema.json`) holds source, executor, target workload and pod,
   the expanded recipe and its `composition-…` reference, the composition provenance (authored
   edits, resolved builtin digest, action map with `a`+24-hex IDs), the `action-lifecycle/v1` plan
   (ongoing: `manualSession`, `acceptedCapturePods`; onTrigger: `requestedBefore: 0s`), the compiled
   filters, the effective retention and the deadline, plus `acceptance: recorderUnavailable`. Its
   SHA-256 is the preview's `execution_digest`. It is deliberately not `collection-scope/v1`: that
   contract needs node identity in its pod binding, which an API-class installation does not
   resolve, and no acceptance exists yet. `examples/resolved-recorder-preview.json` is a
   cross-language fixture: the specification checker recomputes its expansion, provenance,
   lifecycle, recipe and program digests, the Go test compares bytes, and the libpcap-tagged test
   pins the fixture program to libpcap 1.11.0's output.
6. **Assessment `recorder-assessment/v1`.** Per action: impact `unknown` with effects
   (packet: node CPU, collector memory, storage I/O, upload; syscall additionally application CPU),
   conservative exposure (packet: network addresses and personal identifiers retained, user
   content and credentials only transient; syscall metadata: personal identifiers), retention
   anchored at `firstAcquisitionOrEarlierSource`, and configured limits only: output bytes per
   incident pod, the ring per observation pod while armed (per incident pod for onTrigger), frozen
   bytes per incident pod. Combined level `unknown`; alternatives `narrowScope` (no filter / all
   syscalls) and `futureOnly` (ongoing with history). No overhead number is invented; the basis
   names the absent recorder capability by a fixed digest.
7. **Interim refusal.** Every composition preview carries the blocker `RecorderUnavailable`
   (including the onTrigger `before: 0s` variant), `capture_enabled: false` and `data_class:
   extract` (full composition settings are a protected extract). The preview runs the ordinary
   current identity, recovery, target, eligibility and retention reads (not capability, storage or
   processing coverage) and persists the blueprint, so `request_capture` on it returns
   `RecorderUnavailable` right after reading it: before any target, storage, admission or audit
   work, so nothing is reserved or charged. Composition errors are reported only after current
   eligibility on the target. A DebugPolicy with `profileComposition` is refused at compile time
   with its path (`spec.profileComposition.components[i].profileRef` for these builtins).
8. **Contracts.** The `preview_capture` runtime subset adds the composition branch (no sharing,
   one component, the modeled edits), the composition reply (`profile_composition`, no
   `preset_ref`/`pod_selection`) and `extract` for it; the generator drops unused nested `$defs`.
   The descriptor is 31.1 KiB (was 16.8 KiB), inside the 32 KiB hard result limit; its test bound
   is 32 KiB for this tool only. `get_capture_settings` shrank from 49.5 to 35.8 KiB. The browser shares
   `presentation.Call`; an MCP test drives the official SDK client through the composition branch.

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | No installation records packets or syscalls yet (not observed). Network and syscall evidence is the stated use case of S-04; without a shared typed plan each later increment would build its own, and filters could not be checked before a recorder exists. |
| 2 | Risk accepted | Yes: plan §2 (P3, P4, P11, P12) and the 2026-10-26 decision put these features in the first release; S2 and S6 are the plan's simplifications. |
| 3 | Typical deployments | Yes: every network or syscall investigation starts from these two builtins. |
| 4 | Precedent | tcpdump `-d` and Gadget `--pf` compile filters in user space; libpcap is the reference compiler (feasibility lab: Gadget's compiler rejected an IPv6 case libpcap accepts). Helm/Argo-style data templates for profiles. |
| 5 | Privileges added | None. The hub gains a pure user-space compiler (no capture handle, socket or BPF load); no new credential, SQL grant, Kubernetes permission or network access. The libpcap archive is a build-time download, verified by SHA-256 (signature checked when pinned). |
| 6 | Failure/degraded states | 1: `FilterCompilerUnavailable` (a build without libpcap). `RecorderUnavailable` is the interim refusal, removed by increment 4; the other codes are input refusals, not states. |
| 7 | Self-configuration | No: bounds are spec constants; no new setting. |
| 8 | External dependencies | libpcap 1.11.0 (C, statically linked, hub build only, BSD licence). |
| 9 | Cost at scale | Per composition preview: the ordinary identity/recovery/target/eligibility/retention reads, at most one libpcap compilation of ≤4,096 bytes (the 11-expression corpus compiles in under 5 ms in total), one blueprint row (≤128 KiB, same per-principal/root caps as pod-status previews). Nothing per node, workload or cluster; no background work. The static hub binary is 36 KB larger than the cgo-free one (89.71 vs 89.67 MB, unstripped); the preview_capture descriptor grows by 14 KiB. |
| 10 | Upgrade/rollback | Additive: the blueprint field is optional (older binaries never wrote it and would refuse such a row as invalid, failing closed); removing the branch disables it; no migration. |
| 11 | Smaller fix | Documenting the plan without a compiler leaves filters unchecked until increment 4 and lets each later increment define its own plan. Not persisting the preview would make `request_capture` answer "preview expired" instead of the actual reason. Compiling on the node (spec text) would put a compiler on the privileged collector. |

Benefit established, cost small: proceed.

## Remaining limits

- **No recorder:** every packet/syscall plan is blocked. Increment 4 lifts `RecorderUnavailable`
  for manual `networkHeaders` on nodes whose capability probe passes; increment 6 lifts the policy
  refusal; syscall metadata follows in increment 10.
- **Installed hub image:** the native harness's product image (`scripts/test-context-storage.py`)
  now takes its binary from `make hub-binary`, the same static `libpcap,netgo,osusergo` build as
  `make pcap-check`, still `FROM scratch` (2026-10-27; the image build was checked locally, no
  installed run has used it yet). The collector image keeps its own gadget-tagged build. No release
  image recipe exists yet; one must use the same target.
- **Syscall names** are checked for shape only; the ABI table check is increment 10.
- **Peers** (`packetPeers`) and the other registered fields are not accepted by the runtime schema
  (increment 9 for peers).
- **One component** per composition; catalogs, deduplication and conflicts are increment 11.
- **tools/list size:** the MCP-listed descriptors total about 145 KiB with a 20-tool page against a
  64 KiB response ceiling; this predates this change (get_capture_settings alone was 50 KiB) and
  is reduced, not solved, here.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-04-increment-1-packet-and-syscall-plans-in-preview-adr-243-2026-10-27).
