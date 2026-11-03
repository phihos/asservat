# Finite argument recording composition

Scope: REQ-SYS-001/002/003, ADR-281. This increment composes the separately
qualified argument object with the existing finite node channel. It does not
enable the public compiler or advertise an argument capability.

## Authority and lifecycle

`PacketCapture.Arguments` carries the distinct immutable argument permit;
`Observation`, cBPF `Program` and its packet `ProgramDigest` stay absent. The
metadata syscall invariant is unchanged. Exact source enqueue checks Pod, node,
boot and collector process under the existing channel mutex. The node regenerates
the fixed definitions and checks engine, definition and accounting pins before
reserving resources. Acceptance is a queue/start receipt, not proof of attachment.
The loader rechecks the original StartBy before and after each blocking attach;
uncertain/failed starts never reset the attempt.

Reuse the existing capture ID replay fence, running-work registry, authenticated
upload and exact-work cancel route. Stop cancels the original engine and waits
for reader/decoder cleanup. Cancellation reports a failed original capture,
retains uncertain observation spend and grants no retry. Output/event exhaustion
stops acquisition and records a partial result; no refill or replacement source.
The ordinary metadata engine and output path remain unchanged.

## Resource and complexity gate

Before acquisition, reserve the finite native output under FrozenBytes and a
working allocation through existing source/ring/count/input-rate quotas. Perf
uses actual possible CPUs × nine OS pages: eight data pages plus the metadata
page. Add 2 MiB + 4,096 bytes per permitted tracked thread for bounded kernel
maps, decoder and pairing state. This is a conservative admission allowance,
not a measured allocator/heap guarantee; the physical collector memory limit
and production-loader native resource qualification remain independent checks.

At 256 CPUs and 4 KiB pages this is 27 MiB for 4,096 threads, 75 MiB for 16,384;
64 KiB pages and 4,096 threads require 162 MiB. Output is separately capped at
8 MiB. Refuse insufficient capacity before attachment. Hold reservations until
acquisition and delivery join. The input reservation is the effective event
rate × maximum probe charge, including its one-second burst.

Observed missing composition: the accepted raw mode previously had no node
producer, typed file or joined Stop. The maintainer requires these outcomes.
Added services, credentials, network endpoints, watches and user configuration:
zero. Reuse the existing source discovery and one-second engine checks. Add one
bounded JSON line decoder and one bounded pairing table per capture, two fixed
native metadata records, and no background work beyond the existing capture
lifetime. A collector image gains the pinned 694,968-byte ELF and build-time
source pins; there is no runtime download or registry fallback.

## Native file and verification

[The native schema](../../specs/contracts/syscall-arguments.schema.json) defines
`asservat-syscall-arguments/v1`: one header, zero or more event lines, one footer.
The header binds Pod, node, boot, collector process, session/fence and immutable
engine/definition/decoder/accounting identities. Events reuse the canonical raw
syscall event shape. Process/thread references include their start times, boot
and source epoch. Pairing requires matching TID, both start identities, syscall
number and entry timestamp and tolerates reversed cross-CPU delivery. Missing
halves remain unfinished/unmatched; lost input flushes pending correlations.

Argument values have closed reversible encodings: `decimal:` for approved scalar
values, `base64:` for exact bounded bytes, and `unavailable:fault` for failed
reads. Empty successful bytes are `base64:`. Signed fd/dirfd and unsigned flags/mode use their qualified 32-bit ABI widths;
count/offset remain 64-bit. Pointers, comm, unused registers and
padding never enter the native event. Faults, possible truncation, malformed
records, output exhaustion and pair gaps remain separate counters. Known perf
loss is a count; overall coverage remains explicitly unknown. Unknown observation
spend is null, not zero. Quiet captures still contain their header and footer.

The ordinary manifest checker validates the embedded schema, ordering, original
Pod/time/mechanism tuple, event/whole-file caps and exactly one footer. The
mechanism checker additionally consumes independent historical
`ArgumentSourceProvenance`, validates exact source identity and original start
window, selected scalar/buffer semantics and reversible encodings. Production
publication must compose both checks on the same verified stream, using the
existing immutable SQL observation session for provenance. Header fields never
supply their own authority. Metadata projection readers reject these raw records.

## Validation boundary

Local tests exercise exact native values, schema/semantic refusals, reverse
ordering/incarnations, bounded duplicate pairing, original permit round trips,
source replacement/replay refusal and Stop retaining resources until joined.
These component checks do not establish installed custody/download/Stop or
production loader resource cost. Full public activation remains dependent on
those composed qualifications and the accepted planner/SQL/publication path.
