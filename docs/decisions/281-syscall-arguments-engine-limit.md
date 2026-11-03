# ADR-281 — Syscall argument tracing stays disabled with the published traceloop gadget

Date: 2026-11-02. Updated: 2026-11-03. Status: accepted; the maintainer
approved the narrowly scoped engine exception, with native qualification pending. Requirements: REQ-SYS-001, REQ-SYS-002 (arguments
mode), S-04 increment 15. Related: ADR-273, ADR-279, S-04 plan S1.

## Context

`arguments` mode must reserve each admitted entry/exit probe (one event unit,
256 B plus every requested user-memory read) *before* the probe reads user
memory, and stop before extra sensitive reads at exhaustion (REQ-SYS-002,
SC-SYS-002). The pinned published traceloop v0.57.0 program reads argument
strings/buffers (one 128-byte continuation record per defined argument) only
for syscalls present in its definition map, and has no kernel-side counter or
budget before those reads. ADR-273 keeps that map empty and refuses startup
otherwise, so `metadata` mode performs no user-memory reads at acquisition.
(The kernel record still copies the six argument registers and `comm`; the
decoder drops them — kernel memory, not user memory.)

Charging in user space after records arrive cannot bound reads between
exhaustion and stopping the gadget, so it would let a grant be exceeded. The
smallest compliant engine is a patched traceloop with an atomic per-namespace
budget map debited before the reads (about 40 lines of C), which S1 ("published
upstream gadgets pinned by digest; no custom kernel/eBPF program") excludes.

## Decision

1. `arguments` mode stays refused at compile time with its typed reason; the
   capability is reported disabled ("Unsupported node/ABI/mode combinations
   disable that capability", specs/syscalls.md).
2. No user-space approximation of the accounting is added: it would weaken
   observation limits.
3. On 2026-11-03 the maintainer approved: “Allow the narrowly scoped patched
   trace program, with native qualification.” This authorizes an owned,
   digest-pinned traceloop patch with a reproducible build as a narrow S1
   exception for pre-read observation accounting. It does not authorize other
   custom eBPF collectors or enable argument capture before qualification.
   The implementation slices are:
   engine patch and fixed definition table; event accounting rule and
   migration; planning/grant/node reuse of the ADR-279 ad hoc pool; raw native
   type and verifier; native `continuation-manual-arguments` focus.

## Complexity gate

Benefit: a specified but uncommon sensitive opt-in. Cost without the exception:
none (status quo plus this record). With it: an owned kernel program, its
verifier behaviour and build pipeline become Asservat's responsibility.

## Qualification required before enablement

Pin the upstream source, patch, build inputs and resulting engine digest. Native
tests must establish concurrent entry/exit budget exhaustion before user-memory
reads, failed-read charging, no refill on restart, workload isolation, bounded
map/ring behavior, and stop/revocation handling. Preserve metadata mode's empty
definition map and absence of user-memory reads. Test decoded native artifacts,
raw approval and authenticated download through the installed workflow; a verifier
load or unit test alone cannot qualify arguments mode. Run the collector only in
a disposable authorized environment, never on the developer workstation.

## Finite planner continuation

The compiler now has a distinct optional argument-mechanism port. Without the
qualified adapter it returns RecorderUnavailable. Supplied pins, selected names,
read bounds and the canonical accounting rule enter the execution digest and
frozen replay context; authored recipe fields cannot supply trusted pins.
Raw approval and cumulative eligible-probe event limits accompany the existing
byte pool. This does not enable a deployed argument collector.

Incremental complexity: 0 new services, credentials, API reads, watches,
background loops or configuration switches; 1 optional compiler interface and
1 frozen mechanism record per finite action. Unsupported mechanism is the
existing RecorderUnavailable state, not a fallback. Only sensitive opt-in
captures pay the additional bounded compilation/serialization cost. Legacy
packet/metadata scope bytes and assessment hashes retain their old form. The
smaller alternative (using only the recipe or charging delivered events) cannot
bind the reviewed engine or bound pre-read work and does not meet REQ-SYS-002.

## Runtime composition continuation

The manual path composes the distinct argument source resolver and prepaid
permit with the existing regional recorder, node work queue and encrypted
producer. SQL129 admits the exact raw argument type into processing lineage and
the existing collection loop. Independent publication resolves historical source
facts from the original immutable observation row through the existing verifier
credential and checks them during the same authenticated native stream. It adds
one bounded SQL read per argument verification, no additional key unwrap or
object download. Existing context-verifier SELECT permission is sufficient.

Finite argument Stop reuses the existing cancellation request/join columns and
node cancellation queue, with a distinct typed argument Stop and completion
proof. A request acknowledgement cannot prove detachment; the original node
result and regional writer must join. A bounded holder retained before enqueue
preserves uncertain-start state. A restrictive tombstone can fence a delayed
start but cannot establish a joined result. Stored output wins over Stop.

Incremental cost: 0 new services, credentials, privileges, watches, background
loops or configuration; 1 source SELECT per publication and existing bounded
holder/queue capacity per active attempt. Pending, uncertain, cancelled and
stored states reuse the existing lifecycle. Downgrade refuses retained argument
captures; empty-schema rollback restores the prior functions. These changes
address required publication and cancellation of the sensitive opt-in path;
installed qualification remains required before the capability is advertised.

Containerd creates a private cgroup namespace for nonprivileged cgroup-v2
containers even when they use host PID visibility
([containerd v2.1.4](https://github.com/containerd/containerd/blob/v2.1.4/internal/cri/server/container_create.go#L923-L929),
[containerd v2.3.4](https://github.com/containerd/containerd/blob/v2.3.4/internal/cri/server/container_create.go#L821-L827)).
The argument membership scan therefore uses the existing locked-thread pattern
from profile dialing to enter `/proc/1/ns/cgroup`, reads Pod membership against
`/proc/1/root/sys/fs/cgroup`, and restores the original thread namespace before
returning pinned descriptors. Both paths select the node's view, including
[Kind's nested private cgroup namespace](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/cluster/internal/providers/docker/provision.go#L170-L175).
This uses the collector's existing SYS_ADMIN/SYS_PTRACE capabilities: no new
privileges, host mounts, configuration or discovery loop. Each existing initial
or one-second scan adds two namespace switches and one short joined goroutine;
cancellation waits for scan/restoration, and restoration failure closes returned
pins and retires the locked thread. The existing 128-member bound and original
capture deadline remain unchanged. Injected namespace tests do not qualify
native namespace entry; the installed argument workflow must exercise it.

## Finite recurring policy preparation

The same compiled argument mechanism can now be bound into a finite onTrigger
policy. Ongoing argument sources remain unavailable. The protected automation
envelope and accepted authority carry the existing cumulative event ceiling;
absence means zero and preserves legacy source serialization. Independent policy
review is raw even with captureBuffers false. It binds the exact recipe/mechanism,
aggregate byte/event pools, finite session and rate limits. Policy and grant
status report conservative event charges separately from bytes. Replacing a grant
does not reset the accepted policy's spend.

This reuses SQL128's atomic policy/grant accounting. Incremental cost: zero
services, credentials, API calls, watches, background loops or configuration
switches; one optional bounded integer through existing authority/status records
and one mechanism record in the policy scope. No new failure or fallback state.
The benefit is the accepted REQ-SYS-002 automatic-policy requirement; omitting
this field makes the existing event pool unreachable from protected configuration.
Legacy packet/metadata scope bytes remain unchanged when arguments are absent.

Focused compiler, authority, grant-plan, public-contract and console tests are
component evidence only. Installed recurring capture and a separate exact-artifact
human inspection/download approval remain required. A team collection grant never
confers personal disclosure rights. The manual native qualification is tracked
separately in implementation-progress.md.
