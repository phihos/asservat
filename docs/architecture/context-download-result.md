# Regional context preparation result

C-14 adds a private `ContextDownloadResultOwner` for one original acquisition
process, admitted worker and download session (REQ-DLD-002–004, S-02). It fixes a
specific paid-work failure: preparation can finish and acknowledge its successful
outcome just before the first response's authority expires. The verified metadata
must remain recoverable without another native read, key unwrap or batch.

This component is not an enabled regional runtime or public download endpoint.
Protected allocation/environment production, actual native-work/transfer
transport, acquisition executable composition, cancellation/audit composition
and bootstrap remain required. Constructor inputs do not establish key possession,
attest a process, dispatch a worker or authorize evidence disclosure.

## One original process and result

Protected composition supplies the accepted `WorkerEnrollment`, its process
public-key digest, an owning process context, the exact context source and the
existing live worker-proof, current human-authority and SQL observation ports.
The constructor pins the complete admitted worker, actor/client, scope/version
and session and snapshots the source's caller-owned slices. Every use checks the
current exact worker/key proof through `WorkerEnrollmentProofReader`; proof
freshness is an original upper bound, never a renewable execution identity.

There is exactly one result, at most one native preparation attempt and at most
two simultaneous calls per owner (one native operation and one overlapping status
request). Protected ingress may narrow that fixed bound further.
There is no map, eviction-driven replacement or queue. Installation limits remain
in the existing original session/allocation and admitted worker machinery; this
object creates neither. The owning acquisition process must instantiate only its
one original owner. Reusing constructor values does not authorize another process
or replace the missing authenticated native-work protocol.

Before first work, the current SQL observation must still show the exact untouched
Preparing session: no prior generation, request or active batch. Concurrent local
calls cannot begin a second read. Denied preflight does not set the local attempt
marker or spend SQL work. Once the native attempt path is entered, the marker remains conservative even if a
subsequent denial means no SQL admission occurred; without an independent absence
proof the owner does not infer that a failed begin was uncommitted. Failure/uncertainty
then stays occupied locally; this implementation does not automatically retry an unknown
begin, native read, finish or outcome acknowledgement. A replacement owner finding
already-spent or Ready SQL state reports missing metadata instead of re-preparing.
Reconciliation of an uncertain audit is deliberately not a new retry service here.

## Retention before first delivery

`ContextDownloadWorker.Prepare` keeps its existing immediate-response contract.
The worker shares its implementation with a typed `PrepareCurrent` path, which
consumes request-owned `CurrentIdentity` directly. It never fabricates a bearer
string. Initial caller/client/claims and original response deadline are pinned;
subsequent current checks may only shorten that interval.

Only after the exact successful native outcome has been durably acknowledged does
the shared worker helper install `PreparedDownload` into its already-owned result
slot. This point precedes the unchanged final current-authority and original
`PermitDownloadMetadata` response checks. The first call may therefore fail while
retaining verified facts. An unacknowledged or uncertain outcome never installs a
readable result. Native payload buffers are still cleared by the worker; neither
payloads nor unwrapped keys are retained in the result. SQL still receives no
native filename, checksum or coverage.

A fresh Read or same-original Prepare replay obtains current request-owned human
rights, exact process/worker proof and the independently checked successful
historical preparation receipt through `ObserveDownload`. It does not call Begin,
S3, native decode or KMS. The result binds the original batch/generation and exact
artifact version. Current read/delete dates replace the old metadata dates on each
response, and its ValidUntil is the earliest original identity/proof/SQL/session
bound. Ready/Streaming/Interrupted may use the result; terminal status is served by
the coordinator's metadata-free path without this owner.

## Lifetime and joined closure

The process/worker's original lifetime, session deadline and managed evidence
access bound limit retention. Later observed shorter access deadlines shorten the
owner monotonically, with a bounded timer; no status call extends it. Process loss,
expiry or Close clears the result and cancels active calls. Close initiates that
restriction immediately, while Wait joins all active calls before a supervisor may
release its process slot. An uncooperative blocked dependency cannot make Wait
claim termination early. The existing detached worker finish path is accounting
only; cancelled work remains charged and cannot publish a late result.

This is memory lifetime control, not a claim that Go erases all historical heap
copies or that SQL expiry proves remote process/socket termination. Losing the
result after process restart remains explicit cache loss. No automatic native
re-preparation, session replacement or capacity refund is introduced.

## Qualification boundary

Focused source tests cover acknowledged work followed by first-response expiry,
new current observations without another read, unknown begin/finish/audit replies,
changed worker/key/version/batch/receipt, identity changes, concurrency, process
closure with joined active work, shortened retention and original freshness after
blocking reads. They use synthetic current human/worker proof and ledger inputs.
The focused `TestContextDownload` race run passed in 1.117s; the complete evidence
package, including unchanged immediate-response worker tests, passed race in
1.151s. A counterfactual that retains the result only after the original final
response gate fails `TestContextDownloadResultSurvivesExpiredFirstReplyWithoutAnotherRead`
with missing verified metadata; the corrected ordering passes. Logs and guarded
source hashes are retained in the staged result-owner handoff.

These component tests do not qualify a native-work protocol, protected acquisition
startup, real worker-key possession, or public downloads. Existing real SQL/S3
coordinator tests are recorded separately in [context download control](context-download-control.md);
they do not claim to run this new owner.
