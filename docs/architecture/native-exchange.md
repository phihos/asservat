# Approved context native exchange

C-14 uses `asservat-context-native/v1` on I-13 for the existing verified pod-status artifact. The acquisition worker opens an outbound HTTP/2, TLS 1.3 conversation to its installation-selected connector. The connector independently resolves the existing SQL45 operation and exact hub Pod/process. It forwards to that process only after current route, certificate and registry checks. An incoming Hello never creates work or chooses a different owner.

The first mechanism handles the existing native context limit of 4096 bytes. SQL42's response/window accounting supports larger artifacts, but this reader and wire composition do not qualify a large artifact decoder or large-file throughput. One native payload per hop is outstanding, with a separately bounded next-phase control input to observe owner closure; the 1 MiB data limit is a ceiling, not a minimum. A five-second current lease bounds each admitted conversation.
[ADR-220](../decisions/220-response-owned-download-permissions.md) lets the actual
context response consume the response coordinator's exact already-checked short
authority and current identity batch through package-private methods. Original
`CheckedAt`/`ValidUntil`, exact scope and caller/session bounds survive; current
attachment/source/SQL/key checks still run. Direct current-reader calls and
independent runtime operations retain their own complete authorization. The
response's separate ordinary-permission cadence neither changes this wire nor
extends an admitted conversation. Actual sink backpressure can exhaust that lease; automatic pipelining and adaptive large-file behavior remain unqualified.

## Command size and memory planning

The command has a separate 640 KiB ceiling; Hello, metadata and acknowledgement frames remain 64 KiB, and native data remains at most 1 MiB. The existing accepted-domain field bounds permit a conservative 574,075-byte escaped command (32 audience assignments, 64 retention rules, four bounded receipts and the closed placement/processing proof). The proof adds at most 2,991 bytes: 2,378 for the placement, 591 for the processing observation and 22 for their JSON member labels. The Go domain-valid extremal regression encodes 570,968 bytes and reproduced rejection by the former 64 KiB ceiling. Its synthetic maximal strings are a bounding superset of stricter accepted provenance schemas, not accepted production facts. Startup control has its own unchanged 64 KiB bound.

At one point three route processes can each hold one command frame, totaling 1.875 MiB across the route. Closed JSON validation adds bounded input, decoder, raw-message and re-encoding documents. A conservative allowance of seven document-length slots is 4.375 MiB per active command decoder; this is arithmetic over logical documents, not an exact Go allocation/RSS bound. Encoder/canonicalization backing capacity, TLS/HTTP2 buffers, SDK pools and GC are additional. The relay no longer retains a redundant command copy, and relay/worker release decoded raw command source after validation. Each receiver can also hold one small next-phase control frame to observe upstream cancellation promptly; there is no additional native-payload queue.

The v2 native worker has a provisional 64 MiB configuration minimum, separate from the v1 credential worker's 16 MiB floor. This leaves planning room for command processing, the existing 1 MiB manifest ciphertext/plaintext and 256 KiB index ciphertext/plaintext bounds, the 8 MiB zstd decoder bound and runtime overhead. Actual deployed RSS/throughput qualification is still required; this floor is not a measured overhead claim. Hub/connector sizing must account for their explicit concurrent-operation caps.

## Authority and identities

The public hub request retains its actual request-owned `CurrentIdentity` and original current-check closure. `NativeAttachment` registers a local factory before publishing its SQL locator. The factory cannot be reconstructed after process loss from SQL or a certificate. `CurrentNativeResponseSource` receives the existing C02 identity batch from `DownloadResponseTransfer`; a serialized delivery lease is insufficient. The remote source rejects the legacy identity-free source methods.

The connector authenticates the actual acquisition TLS leaf against the exact accepted worker profile, then uses the dedicated Pod token for current worker proof. The hub authenticates the actual connector TLS peer, independently matches its reported acquisition leaf to the activated worker certificate, and repeats current Pod/operation checks. This reports the original peer; it does not fabricate a hub-side acquisition TLS handshake. Every frame retains the original proof/operation/lease deadline and rechecks current registry/operation and original caller authority. Known cancellation or shortening closes the live conversation. A stored locator, nonce, operation reference, certificate or route is never a byte or key permit.

The outbound connector uses a separately scoped connector client certificate. Hub-owner enrollment forwarding remains a different protocol and role. Exact owner routing uses the accepted Pod addresses and the deterministic owner server name; it has no developer callback, DNS route selection or public address override. TLS/session/root/key provisioning still requires protected installation producers.

Within one synchronous registration or attachment call, a private one-use value
may carry the immediately preceding full current check through local constructor
validation. It retains the exact gate, caller, operation, certificate, sequence
and original deadline, and checks cancellation, clock and known shortening again
after local locks. It is never retained across I/O or stored on an operation.
Public entry points still perform their own current check; effect and frame
checks are unchanged. A gate snapshot can only restrict this fresh result and
cannot create or renew authority.

## Preparation and native content

Preparation consumes the existing prepaid metadata batch and its three exact artifact-key slots. The separately scoped download acquisition worker can unwrap the selected artifact; collection writers remain wrap-only. The hub and connector cannot unwrap. The worker verifies native bytes, computes immutable native facts and clears the payload. It retains only one provisional metadata result in memory for the same process, artifact version and original preparation batch.

`ContextDownloadWorker` accepts exactly one direct, batch or regional preparation reader. The regional branch sends Commit only after the existing positive outcome and encrypted audit acknowledgement. Unknown SQL/audit acknowledgements cannot make provisional metadata readable. The original final current-authority check still gates the caller's response. No automatic second decrypt follows an uncertain preparation.

Later metadata observation uses a separately bounded operation over the same committed process result. It never reads the payload or unwraps again. Cache loss, a replaced process, different source version or uncommitted result is unavailable. Metadata stays distinct from the short authorization observation that permits one response.

Content uses an exact SQL42 response/window and a separate SQL45 key binding with three irreversible unwrap slots. `NativeKeyAuthority` selects one immutable preparation-batch or response-window key identity; ambiguity, lookup failure and denied/spent authority never fall through to the other purpose. The worker verifies the native artifact for that paid read and sends only the exact requested range. The hub acknowledges only after the final sink's exact full write and flush succeed. That acknowledgement is bound to the original full lease, response, window, generation, offset and byte count. Partial/uncertain writes cannot claim completion. HTTP flush is not proof of persistence in a developer's local filesystem.

The worker retains its pending buffer until delivery acknowledgement or joined cancellation, then clears it. The connector and hub each hold at most one bounded pending chunk. A lost acknowledgement after a successful sink write stays conservatively charged. Source and sink close join blocking I/O before local capacity is released.

## Conversation outcomes and recovery

The actual h2 client uses a non-rewindable live POST body, no retry-enabling headers and no redirects. One original setup bound covers handshake, headers and Hello. It never retries an uncertain POST automatically.

A positive no-command response requires actual verified h2/TLS, the exact Hello nonce and worker identities, and an original current deadline of at most five seconds. Generic HTTP errors, EOF, timeouts and stale/ambiguous rows are not no-command responses. Idle checks use at least one second of backoff, at most 32768 conversations, and the worker's original `RunUntil`; none renews authority, SQL ownership or capacity. On the hub-local worker path the hub parks an idle request, without a handler slot, until this process publishes that worker's own operation or shortly before the idle reply's deadline; a wake-up repeats the complete worker/SQL admission. Workers start at most one idle lookup per second, counting the time a parked reply took, so an operation claimed by a human request no longer has to coincide with the worker's retry schedule inside one five-second request.

A positive final Done marker runs its blocking current-authority check and positively closes its exact original SQL owner before the write. The private completion callback locks and matches the original operation/reference/fence and lease sequence, requires one acknowledged open-to-closed transition, and checks the original deadline after blocking work and commit. Already-closed, missing, replaced, expired and unknown results cannot supply this proof. Ordinary cancellation cleanup remains idempotent and cannot certify success or close another generation. After that restrictive transition, only the hub’s private exact-completion capability can send the same zero-byte final marker using the unextended last complete gate bound; no metadata, data, key or new-work effect uses it. The transport then checks the original deadline and known cancellation around the write/flush, with no new blocking authority work after the marker has already reached the peer. A peer may close normally upon receiving Done. Metadata, data and other control frames retain their post-I/O current checks; the application's final metadata authorization remains separate. A failed or partial final write is unavailable, and successful HTTP flush does not prove downstream persistence or all participants' independent quiescence.

`RunWorkerConversation` returns Joined only after its successful final protocol acknowledgement, local buffer cleanup, receive goroutine and stream close have joined. The stronger final-marker ordering means that its old SQL operation is already unrouteable; it does not prove the hub’s remaining response checks or remote filesystem persistence. The router and handler remain charged until their actual local I/O joins. Concurrent same-worker registration stays denied before SQL claim while that slot is occupied; sequential application return follows its joined Close. The existing one-second worker backoff is scheduling, not a closure proof. Uncertain results stop automatic selection of new work. The returned reference is diagnostic/fencing context, not recovery authority.

The first implementation does **not** support automatic lost-final-acknowledgement metadata reconciliation. Socket close, fencing and expiry cannot prove that all three former participants joined. A new metadata-only operation would require an exact authenticated same-process closure receipt plus independently joined connector/hub cleanup and the original positive SQL outcome. That receipt protocol is not implemented. The available recovery is cancellation of the exact worker, positive existing termination/retirement proof, and an explicit new paid admission/preparation where current limits permit it. Previously uncertain spend remains charged.

## SQL45 control backing and cleanup

`download_native_owner` is one bounded rendezvous row per existing admitted worker, separate from certificate request ownership. It stores only operation/fence, exact source version and owner/process/worker pins, the internal current authority snapshot and original bounded lease. No human credential, object key, native checksum, filename, payload or unwrapped key is persisted.

`download_native_key` is one immutable key binding per paid response window. `download_native_backing` is an independently installed finite capacity covering rows, key records, capped transitions, qualified row/WAL sizes and backup copies. Admission cannot extend this backing or erase its spend. History qualification numbers are protected measured input, never an estimated value generated by the runtime.

A row close fences work; it does not prove remote quiescence or refund anything. Owner/key deletion requires the existing positive worker-retirement proof and the declared backup cooling interval. A residual backing period covers deletion WAL and backup history; late cleanup retains backing and becomes overdue. Reaching a deadline alone does not release uncertain charges. Public runtime enablement also requires a protected producer and supervisor for this finite cleanup contract.

## Qualification boundary

Staged component checks have exercised actual two-hop HTTP/2/mTLS preparation, committed metadata observation and native delivery through the actual HTTPS sink, with explicitly synthetic current authority and source facts. Those tests exposed an unbounded relay frame context, premature client cancellation before the peer consumed the final acknowledgement, an undersized command frame and a missing upstream EOF read while the relay waited for worker metadata. The latter must cancel and join an ongoing regional read, rather than waiting for its authority lease to expire. They do not replace the pending SQL45/S3/key-service fixture or deployed acquisition process qualification.

The external fixture must preserve provenance: real SQL/encrypted S3/audit/key-slot effects and actual h2/TLS are distinct from synthetic protected installation, Pod-proof, issuer and human identity facts. No component constructor enables a public native endpoint or supplies generic raw/share authority. Public prepare/get/cancel wiring, accepted runtime profiles and Secret provisioning, scoped temporary S3 credential expiry, connector credential production, and the complete protected runtime composition remain separately qualified prerequisites.


Final control-marker forwarding retains the original checked gate snapshot.
After the hub has positively acknowledged content delivery, its caller can
retire the SQL operation before the connector forwards the exact final `Done`.
Requiring that already retired operation to remain effect-eligible incorrectly
turns a successful transfer into an uncertain worker conversation. The connector
therefore forwards only the expected zero-byte final marker under the gate's
last successful complete check, with its original deadline and exact operation,
sequence, certificate, nonce and phase. Known cancellation, revocation and
monotonic shortening still stop that forwarding. This is closure information,
not new disclosure or work authority. Hub generation of the marker retains its
blocking current check; data, metadata, commands, commit and delivery
acknowledgements retain their existing full checks. Bounded inbound prefetch can
use the snapshot, but cannot authorize any nonterminal forward. Unknown or
partial final delivery remains uncertain, and the real-service fixture requires
three positively joined worker conversations in addition to exact bytes and
SQL completion.
