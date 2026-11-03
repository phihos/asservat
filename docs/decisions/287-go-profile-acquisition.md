# ADR-287: admitted Go endpoint acquisition

Status: accepted implementation direction; native qualification pending.

## Context

ADR-285 resolves a reviewed endpoint without collecting anything. The accepted
first-release profile requirement also needs real Go CPU/heap acquisition,
managed encrypted storage, independent publication and native download. A
profile must retain its own typed parameters rather than impersonate a packet
recording. The node collector has no artifact key authority.

## Decision

1. Persist the authored composition and exact endpoint observation as a separate
   profile context. Admission recompiles that frozen input, binds raw/profile
   approval and reserves the complete admitted native output and temporary
   multipart obligations. One manual Go endpoint action is executable in this
   increment; policy profiles, eBPF sampling and credentialed endpoints retain
   their later slice boundaries.
2. After the existing committed start, the connector resolves the same endpoint
   from protected configuration and the exact Pod again. Digests, parameters,
   node UID/boot/process and the original committed action deadline must agree.
   The API target remains an API-only whole-Pod pin. Node execution provenance
   is separate and never adds container permissions or public node selection.
3. The authenticated node channel carries dedicated profile work and result
   types. One HTTP GET uses the existing Go profile collector, with fixed path,
   no redirect/retry/DNS fallback and bounded response bytes. The node opens
   the exact Pod's current network namespace, rejects the host namespace, checks
   the Pod cgroup after opening it and returns to its original namespace before
   delivering the connection. Pod-IP routes must be local to that namespace.
   A declaration does not establish serving-process attribution.
4. The node reserves the full admitted response size in the existing aggregate
   frozen budget before acquisition. It holds native bytes only in memory until
   the single authenticated upload joins; the connector encrypts them using its
   existing wrap-only prepared artifact. The node receives no artifact keys.
   The Go HTTP collector's native-stream API does not return a fictitious
   encrypted layout or custody verdict.
5. One conservative slot per Pod excludes overlapping Asservat runtime
   acquisitions. Cancellation closes the HTTP attempt; uncertain started work
   keeps the slot through its original action deadline. Upload and cleanup use
   the existing fixed transport margin, never a new acquisition interval.
   Unknown starts/uploads remain spent and are not retried. Application-owned
   incompatible sessions report busy and are never stopped by Asservat.
6. Profile and recording holders share the existing 64-attempt and 32 MiB
   connector storage budget. A streaming profile reserves that entire working
   budget while storing, independent of its total native length; it uses the
   unchanged 8 MiB frames and multipart writer. The profile writer's private
   one-shot state cannot release durable temporary charges. Process replacement
   cannot reconstruct it. Cleanup still needs writer quiescence and complete
   attempt-prefix inventory before releasing reservations. Generic resumable
   streaming retains its durable journal.
7. Publication verifies the actual native profile independently and derives raw
   result-access children only after verified commit. Native download retains
   the exact format and hashes and integrates the separate bounded multi-frame
   transfer change. A received node body or stored ciphertext is not publication.

## Accepted cancellation lifecycle

The existing revision-bound `cancel_capture` operation accepts a profile attempt
under current ordinary rights. Migration 124 extends the existing cancellation
journal to the distinct profile expectation; it does not create a new public
operation, grant, listener or retry loop. A restrictive typed stop travels over
the existing signed regional control stream, bound to the accepted attempt,
expectation and exact connector process. It carries no recording source or
packet parameters. A bounded holder tombstone prevents a delayed start.

Queue acknowledgement is not completion. The connector waits for the actual
node result and any active storage call to join before recording the typed
cancellation proof. Confirmed storage wins a concurrent Stop. Known cancellation
before endpoint work reports that no application profiling started; if the
endpoint may have started, public progress warns that stopping collection does
not confirm the application stopped profiling. The original node exclusion
interval and all uncertain storage charges remain spent. A process replacement
cannot acknowledge or reconstruct the original attempt.

## Costs and validation

The implementation plan records the cumulative complexity assessment. A capture
adds one bounded endpoint resolution at start, one node work item, one endpoint
GET and one authenticated native upload. It adds no privileges, credentials,
watch, listener or user-facing tuning setting. An explicit Stop adds one durable
intent update, one regional control query, at most one node cancellation work item
and one joined outcome update; it adds no polling loop or automatic retry. Node response memory is reserved
at the admitted 16 MiB default (64 MiB profile/128 MiB trace maxima), under the
existing aggregate budget. Connector buffering is frame bounded. The one-shot
writer avoids up to 38 multipart journal control RPCs at the trace maximum;
failed attempts retain their full temporary charge until normal cleanup.

Local tests exercise exact endpoint/process binding, original start/deadline,
one-use delivery, uncertain HTTP cancellation, immutable multipart claims and
unknown create/part/complete results. Gadget-tag compilation is separate from
native qualification. The installed endpoint, resource cost, approval,
publication, stop and native-download workflow still require the frozen-source
native suites; no component result completes S-05.
