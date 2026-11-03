# Mixed packet/profile upload fairness follow-up

Date: 2026-11-03. Status: proposed implementation/qualification plan, **not
implemented or qualified**. Source audit: `78afa6ec`, including PR-147's bounded
profile wait. Requirements: REQ-CAP-002/003/006, SC-CAP-003, REQ-EVD-001,
REQ-PRF-001; TASK-05 fair transfer scheduling. Related: [capacity](../../specs/capacity.md),
[ADR-248](../decisions/248-manual-packet-capture.md),
[ADR-287](../decisions/287-go-profile-acquisition.md),
[ADR-290](../decisions/290-one-shot-profile-streaming.md).

## Finding and disposition of the suggested priority patch

The [PR-147 review](https://github.com/phihos/asservat/pull/147#discussion_r4451710508)
identifies a plausible starvation schedule. Packet A1 starts storing; profile B
waits for the shared counter to reach zero; A2 starts before A1 releases; further
A packets overlap in the same way. Two 1 MiB packet stores suffice to keep the
counter nonzero without consuming the 32 MiB ceiling. Each release wakes B, but
B cannot reserve its whole working budget before its original deadline. This
is reasoning from the exact branches, not an observed installed workload or a
measurement of its frequency. A saturated network is not required.

The transient-contention fix remains useful: a completed profile now survives
another packet/profile store when capacity becomes available in time. Its local
real-writer regression covers both types. It preserves the original request,
upload and WriteUntil bounds, unread waiting bodies, Stop, one-use delivery and
uncertain charges. It does **not** prove mixed-workload fairness. Expiry under
genuine overload remains legitimate; avoid describing every starvation schedule
as unavoidable overload. REQ-CAP-003's absence of a real-time network guarantee
does not remove its workload allocation/fair scheduling requirement.

Reject the proposed `profileWaiters > 0 => discard packet body` patch:

- `internal/application/delivery/node_packets.go:DeliverPacket` deletes the
  pending work before entering the sink. `internal/transport/node/client.go:UploadCapture`
  sends once; `internal/bootstrap/node_packets.go:runObserved` returns after an
  upload error. Keeping `held.prepared` cannot authorize another delivery.
- That priority would discard a different already-acquired artifact, including
  when ample capacity exists for it. It provides artifact-type preference, not
  workload isolation, and a stream of profiles could reverse the starvation.
- A whole-artifact FIFO would avoid overtaking but still let a 128 MiB profile
  retain the storage turn ahead of another workload. It does not satisfy the
  bounded-byte-quanta requirement either.

Resolve that proposed destructive change with this explanation and keep the
actual requirement open. No completion checkbox or fairness claim follows from
the transient fix or this plan.

## Existing primitives and missing integration

| Existing code | Useful boundary | What it does not establish |
| --- | --- | --- |
| `ConnectorRecordings`, `regional_profiles.go`, `regional_recordings.go` | 64 holders, 32 MiB shared storage counter, exact prepared expectation, cancellation and release notification | No workload queue, deficit accounting or mid-artifact yield |
| `collector.Budget.TakeUpload`; `nodePackets.takeUpload`; `profileUploadReader` | Existing node byte-rate/burst ceiling; profile reads charged in at most 64 KiB chunks | Aggregate node bucket, not per-workload scheduling or cross-node leases; packets currently acquire upload credit for their entire result |
| `PreparedArtifact.Store` in `objectstore/artifact_produce.go` | Single-use writer, original WriteUntil, native checking, four-object completion | One monolithic call; it cannot be called again to resume a quantum |
| `framed.Encoder.Encode` | Independent 8 MiB native frames and per-frame encryption/index entries | Keeps an 8 MiB native buffer and zstd state through the entire call |
| `privacy.StreamingWriter` | Sequential 8 MiB multipart parts, immutable claims/acks, no retry | Retains a part buffer across frames; frame and part boundaries differ |
| `Store.VerifyStreaming` | Exact ciphertext hash from at most 8 MiB range reads | Its current whole-object loop would monopolize a finalization turn |
| Accepted expectation and registration | Cluster/namespace/workload provenance, allocation ID, attempt and process identity | No caller-selectable queue/account/weight; these facts must be traced back to the protected allocation |
| Capacity reconciler's demand round robin | Bounded control-plane refresh work | Unrelated to payload scheduling; do not route uploads through it |

The code search found no reusable upload DRR implementation. DRR itself is not
a novel mechanism: Linux's [DRR qdisc](https://github.com/torvalds/linux/blob/v6.12/net/sched/sch_drr.c)
maintains active classes and byte deficits/quantums. That is algorithm precedent,
not evidence for Asservat's storage, cancellation or memory behavior. The existing
budget schema provides upload rate/burst/request ceilings, not arbitrary weights.
Begin with equal workload weights; do not add a public priority setting merely
to tune the scheduler.

## Smallest credible approach to prototype

Use **one process-local workload scheduler at the existing connector writer**,
with at most the current 64 holders and one shared bounded working arena. All
packet/profile writers sharing this arena must participate. No type may bypass
it, and several captures of one workload must not gain several workload turns.
Derive the queue key from the accepted allocation's cluster, namespace and
workload identity; never accept it from an upload header. Preserve individual
attempt IDs, node processes, writer epochs and original contexts within a queue.

Enqueue one live continuation for an already accepted upload, keeping its body
unread until selected. The existing single-use delivery is claimed once. A
continuation here means internal state of that same invocation, **not** a new
upload, acquisition retry, durable resumability or restart reconstruction.
Stop/deadline removes queued work or cancels the active operation and joins it
before releasing working memory. A wakeup, admission turn or successful part
never renews any deadline or returns grant/custody spend.

Selection uses workload deficits with an initial 8 MiB quantum. Bound a turn
to a frame-sized operation, not to `Store` completion. Account native input,
ciphertext upload and verification reads explicitly; a turn that reads 8 MiB
and writes about 8 MiB costs both. Carry bounded deficit for an operation larger
than one quantum rather than pretending it costs 8 MiB. Small index/manifest/
commit and multipart-control operations also require bounded request service;
they cannot become an unmetered bypass or be held until a full byte quantum.
Avoid idle credit accumulation and round-robin captures within each workload.

Required yielding boundaries are native-frame processing/part upload and
individual verification range reads. Complete/receipt, index, manifest and
commit stages are individually bounded terminal work. A profile with 16 native
frames must allow another eligible workload to advance between frames and
between its verification ranges. A blocked backend operation may retain the
active turn only until its existing context ends and the call actually joins;
the design does not promise instantaneous preemption of an HTTP request.

### Memory is a prerequisite, not a semaphore adjustment

Simply parking today's `Store` goroutines is invalid: 64 retained multipart
buffers alone would consume 512 MiB. A gate around `Read` does not release the
encoder's native/compression/ciphertext buffers. Reducing the semaphore charge
without changing those allocations would misaccount memory.

First prototype a frame-step writer using the **already supported identity
codec**, streaming the existing Tink frame encryption directly into a shared
multipart buffer. This avoids a full compressed buffer and a second full
ciphertext buffer. Preserve the storage format, AAD, hashes, 8 MiB native frames,
8 MiB multipart parts, three prewrapped keys and existing one-shot journal.
Compression policy is a proposal for this prototype, not an accepted runtime
change. Profile input is commonly already gzip; packet/trace data can compress
substantially. Measure the byte/latency cost before selecting it. Worst-case
identity bytes are already reserved; do not silently change output limits.

Identity frames offer a concrete route to bounded parked state: the current
Tink AES256-GCM-HKDF 1 MiB template uses a 40-byte header and 16-byte segment tags.
An 8 MiB identity frame therefore expands by 184 bytes (nine segments), rather
than leaving an arbitrary compressed fragment in the multipart buffer. Prove
this against the pinned implementation with tests; use a conservative 512-byte
per-full-frame bound in the prototype. Across at most 32 full frames, that is
16 KiB of ciphertext tail per writer, or 1 MiB across 64 holders. At a final
short frame, flush/finish that tail within bounded steps; do not park an
unaccounted almost-8-MiB final fragment. A format/key-template change must fail
the bound tests rather than silently enlarge retained state.

Provisional **allocation ceilings**, to verify before runtime composition:

| Working allocation | Maximum |
| --- | ---: |
| One shared native-frame buffer | 8 MiB |
| One shared multipart/small-object ciphertext workspace | 8 MiB + 64 KiB |
| Active Tink segment buffers and crypto scratch | 4 MiB (must measure/check) |
| All compact tails, paused checks/index/hash/queue state | 4 MiB aggregate |
| Active manifest/index/commit and bounded verification workspace not overlapping the frame buffers | 4 MiB |
| Unassigned headroom within the existing ceiling | Just under 4 MiB |

The sum must stay at or below **32 MiB**, including paused state, not merely the
currently selected writer. Do not count the same shared buffer twice or assume
Go immediately returns released memory to the OS. Record peak live owned buffers
and process RSS separately. The existing node frozen-body reservation remains
held until upload joins; this adds no regional raw spool or whole-body copy.

Manual packets (at most one 8 MiB frame) and profile checks have small parked
state. Larger source snapshots can retain a partial PCAPNG block (up to 256 KiB),
and HTTP document validation retains its bounded document. They cannot be waved
through the 4 MiB paused-state allowance. Before admitting their acquisition/save,
derive and reserve their actual continuation-state/service demand; either bring
their checker into the bounded model or keep the relevant fairness claim open.
They must not retain a legacy whole-artifact bypass into the shared arena. Do
not discard already-acquired incompatible results merely to make the model fit.

## Increment order, owners and acceptance evidence

1. **Reproduce and size, no runtime activation.** Extend the existing bootstrap
   real-writer fixture with barriers: A2 is storing before A1 releases; a finite
   succession keeps the counter positive while B's original deadline expires.
   Show that both small A stores fit below the cap. Preserve transient-wait and
   Stop regressions. Prototype frame stepping in `objectstore/framed` and
   `privacy/streaming`, proving identity expansion, compact tails, a partial last
   frame, exact decode/hash parity and the 32 MiB aggregate bound. Record actual
   bytes/RSS/latency against current zstd before choosing the runtime policy.
2. **Local fair service.** Add pure bounded selection logic under the reviewed
   component ownership, compose it in `ConnectorRecordings`, and make
   `PreparedArtifact`/streaming verification cooperatively yield without
   re-entering their one-use methods. Add no S3/control operation solely for a
   scheduling turn and no per-quantum SQL/KMS round trips. Identity encoding can
   increase actual part and verification-range counts up to the existing reserved
   ceilings (17 parts for 128 MiB profiles; 33 for 256 MiB source snapshots), so
   compare those counts with the compressed baseline. Use accepted workload
   identity and existing original contexts. Both packet and profile body readers
   wait rather than discard because another eligible workload has the turn.
3. **Authority and full shared-path composition.** Carry protected upload service
   and continuation-memory demand through admission/start for all affected types,
   including saved snapshots and HTTP projections. The node's aggregate bucket
   remains a ceiling; it is not proof of hierarchical workload limits across
   nodes/connectors. Reuse existing accepted capacity allocations where their
   fields actually cover the demand; audit missing lease fields before selecting
   a minimal schema/control amendment. Do not invent per-process allowances that
   multiply on restart/replica count. Global REQ-CAP-003 remains open until this
   composition and protected context/control service are qualified.
4. **Mixed installed qualification.** With sources frozen, use two accepted
   workloads sharing one connector: sustained small packet uploads from A and a
   16/64/128 MiB bounded profile/trace from B, plus B arriving after A is active.
   Establish progress for both, exact originals/hashes, semantic publication,
   approved native readback, no duplicate S3 part/create/complete or acquisition,
   bounded memory, current node identities, original deadlines and terminal
   cleanup. Use a feasible service/deadline combination; a slow network can still
   fail within the original bounds. No claim follows from a scheduler unit test.

The first implementation PR should stop at a locally proved quantum writer and
scheduler seam if the memory/transport prerequisites are unresolved; it must not
advertise fair production uploads. Production selection is a subsequent reviewed
contract change with the measured codec/throughput tradeoff, not an automatic
consequence of this research plan.

Test obligations include: many captures from A do not multiply its weight;
late B advances before A's large artifact finishes; both make progress under
continued arrivals; at most the declared turn bytes are consumed; successful
release cannot revive an expired waiter; cancellation before selection and
during read/encrypt/part/verify joins; an unknown create/part/complete stays spent;
replacement process cannot resume; invalid native output never publishes; waiting
bodies stay unread. Test all relevant transport limits, including the current
10-second node HTTP read bound, 3 connections per node client and original upload
margin. Do not raise them preemptively or introduce keepalive-based extensions.

## Complexity gate and remaining decisions

1. Harm: already-acquired evidence can miss service; frequency is unmeasured.
   The overlap schedule is concrete code reasoning, not an installed incident.
2. Accepted risk: finite deadlines and failure on genuinely insufficient service
   remain. Workload fairness remains required; profile-type priority is rejected.
3. Benefit: shared multi-workload connectors; no change needed for a lone upload.
4. Precedent: existing spec selects DRR, with the Linux implementation linked
   above. Cooperative encrypted storage is still Asservat-specific qualification.
5. Privileges/credentials/listeners/watches: **zero new** in the proposed local
   slice. No plaintext scratch, provider key delivery or extra network destination.
6. States: waiting/selected/terminal are bounded states of the existing single
   attempt. No replay, replacement, fallback or second upload; scrutinize any
   proposed new resumable state machine beyond the necessary internal cursor.
7. Configuration: no new tuning knob; equal weights initially. Existing protected
   rate/burst limits and original deadlines remain authoritative.
8. Dependencies: existing Tink/S3/HTTP behavior, especially blocked I/O and multipart
   limits. Identity codec cost and transport headroom require measurement.
9. Aggregate local costs: at most 64 continuation records; selection O(64) worst
   case per bounded turn; 32 MiB total working allocation; no new acquisition,
   KMS, create/complete or scheduling-control calls. Identity encoding can increase
   actual data parts, their existing journal transitions and verification ranges
   within the unchanged reserved ceilings. Quantify those calls and network bytes
   against beneficial compression before adoption; do not call them zero cost.
10. Rollback: preserve readable storage layout and original attempt fencing; no
    running writer is migrated, retried or refunded. A process stop keeps unknown
    backend effects charged. Any later lease-schema change needs its own upgrade
    and rollback evidence, not a claim from this local plan.
11. Smaller options: current bounded wait fixes transient contention and stays;
    destructive type priority and whole-artifact FIFO fail the full requirement.
    A short prototype of memory-safe frame yields is the next justified action.

All implementation and mixed installed obligations above are pending. This
document changes no current runtime, public capability, grant or resource limit.
