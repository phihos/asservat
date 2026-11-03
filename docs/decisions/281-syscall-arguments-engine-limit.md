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
   type and verifier; native `continuation-manual-syscall-args` focus.

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
