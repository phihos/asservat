# ADR-258 — Native response windows under slow delivery

Date: 2026-10-27. Status: implemented candidate; selected qualification passed,
installed aggregate-cost qualification pending.
Requirements: REQ-DLD-002/003/004. Maintainer clarification: AGENTS.md, 2026-10-20.

## Problem and decision

ADR-220 already reconstructs ordinary download entitlement every 30 seconds.
Changing that constant does not remove the transfer limit: ADR-248 opens one
remote conversation for an entire prepaid 8 MiB window but pins that conversation
to its first five-second disclosure observation. The resulting 1.6 MiB/s floor
is arithmetic, not measured throughput. The gate regression reproduced refusal
after twelve simulated seconds before invoking its fresh callback.

Separate finite conversation ownership from each short disclosure observation.
A response operation has one fixed candidate twenty-second ceiling, intersected
with original caller, worker and access deadlines. Each native/delivery lease
still lasts at most five seconds. Inbound waits may use the fixed ceiling;
outbound frames and the final sink require current short authority. Nothing
rolls the original operation forward. Preparation, observation and approved
projection operations retain their existing purpose-specific bounds.

Reuse the existing RenewNativeOwner SQL transition. Between acknowledged chunks,
a fresh independent caller observation may advance the same response/window,
owner, generation, source/version, range, certificate and native operation.
Only a strictly newer delivery sequence renews its native owner. The acknowledged
sequence replaces its process observation cache; subsequent actual downgrade
closes the gate. Independently current observations of the same operation may
have bounded cache lag: composition retains the newer known sequence with the
earlier cutoff. Unknown renewal stops the conversation and retains spend.

The initial processing proof establishes immutable operation identity while
valid at StartedAt. Its dates are never rewritten or treated as fresh later.
SQL claim, observe, renewal and completion independently check current
processing/recovery/parent/worker/certificate facts and the same state identity.
This avoids widening generic catalog or recovery observation contracts.

Regional readers also separate initial opening from cursor ownership. Metadata
reads and the three key unwraps remain under an initial five-second context;
framed reads retain the original response context and use fresh per-piece checks.
Canceling the joined opening context cannot cancel the retained cursor. Pod-status
reads still finish entirely within the short initial context. No key is reopened
between chunks.

## Finite original Pod identity

ADR-068's full initial TokenReview and live namespace/account/Job/Pod proof
remain required. A purpose-specific local attester output also returns the
actual token expiry already read after successful TokenReview. NativeOrigin
retains that reviewed bound privately; neither wire fields nor deserializing an
origin can manufacture it. A missing producer fails closed for responses.
The original proof retains its short dates for key binding, which still requires
fresh proof. Each receiving hop performs its own initial attestation.

Within the fixed response, exact original Pod identity is an admission fact;
current SQL worker/certificate/processing/permission checks continue. Actual
token and certificate expiry, worker/access cutoffs, original deadline and
cancellation still stop disclosure. The exact checked remote chunk carries its
native cutoff through the final HTTP write and ACK, intersected with the human
lease without replacing it. A missing remote cutoff denies delivery. A blocked
or failed write cannot be revived under another lease.

The accepted tradeoff is up to twenty seconds before a Kubernetes-only
Pod/Job/account deletion or spec change is independently re-observed. The next
window performs full fresh attestation. We retain no raw token, refresh timer,
periodic Kubernetes check or replacement identity. Repeating the full attester
inside a window would add at least two TokenReviews plus eight object GETs per
proof refresh, plus profile/source checks; three two-hop refresh cycles would
add at least twelve TokenReviews and forty-eight GETs. That cost has no sufficient
benefit over this bounded admission plus current SQL checks.

[S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)
and [CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html)
check URL expiry when admitting a request and allow an existing transfer to
continue, while a reconnect needs valid authorization. This supports finite
admission as a familiar design analogy; Asservat still enforces actual token
expiry and independent current disclosure checks. Kubernetes documents token
revocation sixty seconds beyond a Pod's deletionTimestamp, rather than universal
instantaneous deletion revocation ([documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)).

## Complexity gate

| Item | Benefit / cost |
|---|---|
| 1 | Whole-window refusal is reproduced; ordinary slow-link demand below the final candidate floor is not yet qualified. |
| 2 | Relaxed bounded rechecks are maintainer-authorized; the former whole-window five-second restriction was an agent choice. |
| 3 | Applies to larger native files on slower links; 4 KiB pod status rarely encounters the limit. |
| 4 | Reuse existing owner renewal and cursor; finite-admission precedents above are analogies, not imported authority semantics. |
| 5 | Zero new roles, credentials, listeners, network paths, token retention or key openings. Initial attestation and its permissions are unchanged. |
| 6 | Zero new durable phases/fallbacks. Missing local expiry/cutoff or unknown renewal uses existing unavailable/stop behavior. |
| 7 | Zero configuration knobs. The candidate finite bound is explicitly measured and limited below. |
| 8 | Existing SQL, TLS, S3, KMS and Kubernetes attesters only; no new provider behavior is assumed. |
| 9 | O(active responses) small identity/cutoff values; zero additional Kubernetes calls within a window. One existing owner update per newer lease; existing one-second SQL observation memo, one cursor/key opening per window, unchanged native buffering. |
| 10 | No schema or wire-field migration. This qualification targets fresh matched installs; mixed old/new peers can refuse the longer command. No installed rolling-upgrade qualification is claimed. Regional/download-worker upgrade support remains the existing ADR-227 backlog. |
| 11 | Changing permission-cache timing alone leaves the defect. Smaller windows multiply audit/key work; whole-file buffering adds memory. Existing renewal is the smaller integrated change. |

## Qualification and limits

Real two-hop mTLS plus production HTTPS sink, synthetic source/SQL/identity:
8,126,572 exact bytes took 6.313 s at 1.228 MiB/s with 750 ms blocking final writes
per chunk, seventy current-check callbacks and two lease renewals. Resume
returned 7,073,675 exact bytes with sixty-two callbacks and two renewals;
stale If-Range returned the full body. Each window opened one cursor.
Paced revocation stopped after 7,340,032 bytes; original-request expiry stopped
after 4,194,304 bytes. A blocked HTTPS write under an earlier native token cutoff
returned zero bytes and performed no successful write. The actual coordinator
also stops a blocked sink at the native cutoff with no ACK or refund.

Attester HTTP/API unit regressions return the exact reviewed token expiry,
including short-token, malformed, revoked and replaced-object cases, while
retaining exactly two initial TokenReviews. Origin tests prove no reattestation,
unchanged short key-binding proof dates, missing-producer refusal, actual expiry,
cancellation and inability to serialize the private admission. These are unit
boundaries, not real Kubernetes TokenReview qualification.

Prior real Kubernetes producer qualification passed with a fixed fixture proof factory:
`TestDownloadWorkerProofWithRealKubernetesTLS`, 6.92 s selected test / 7.988 s Go
package, exit 0. The dedicated-audience bound token's `TokenNotAfter` equals the
actual TokenRequest `status.expirationTimestamp`. One initial proof used two
TokenReviews and eight live-object GETs. After the original five-second proof
expired at wall time, twelve response checks performed twelve explicitly
synthetic SQL observations and zero Kubernetes requests. Missing tokens and
missing purpose-specific expiry producers deny; wrong audience/binding, changed
spec and deleting objects retain their real-API negatives.

A separate trusted-clock check advances the attester to the actual returned
token expiry: wall-time TokenReview still authenticates, then the existing
reviewed-expiry parser refuses after one TokenReview and before any object GET.
This does not claim a wall-clock-expired TokenReview result or wait ten minutes.
Dispatch pins, certificate issuance and operation/SQL authority remain fixture
inputs. All 3,180 source hashes matched and cleanup failures were empty; no owned
Docker or Kind resources remained. Archived report
`~/.cache/asservat-build/codex-bf86-resume/native-response-qualification/native-response-proof-kube-1-environment.json`,
SHA256 `d2e556ea1f39db5aaa98828903c9e7e7f1b1f297eee8b9d4f638da5659d345ea`.
A corrected factory run additionally feeds the actual supplied token through
`NativeOrigins` into the attester; an invalid supplied token is denied by one
real TokenReview before any GET. The positive and repeated-check counts remain
two TokenReviews/eight GETs initially and zero Kubernetes calls for twelve later
checks. The selected test passed in 7.44 s / Go package 8.559 s, exit 0; phase
including compile was approximately 44.0 s. All 3,180 source hashes matched,
cleanup failures were empty and the owned resources were gone. An unrelated
HAPTIC cluster was left untouched. Archived final report
`~/.cache/asservat-build/codex-bf86-resume/native-response-qualification/native-response-proof-kube-2-environment.json`,
SHA256 `b7d5db04b506d0dc5b51a68a38231daa4e8cfabf220339c61ee718a97984ab7b`.
The prior report qualifies its producer source, not this corrected token handoff.

The [remaining installed qualification plan](../research/native-response-qualification.md)
keeps this producer result distinct from a paced installed transfer.

Selected real SQL qualification passed on 2026-10-27:
`TestContextAdmissionWithRealServices/download-worker-native-owner-renewal`:
subtest 10.75 s, top-level 11.23 s, Go exit 0, harness phase including compile
53.264 s. Actual PostgreSQL, S3 encrypted audit and registered certificate retain
one original twenty-second operation past its old five-second SQL observation.
Expired observation refuses; independent fresh authority advances the existing
owner. Wrong caller, worker, processing state, same-sequence replay and closed
owner deny. The report has unchanged before/after hashes and empty cleanup
failures; owned Docker resources were gone. Human/bootstrap/Pod proof is
synthetic; this is not a paced combined SQL/S3/KMS payload measurement.

Archived report:
`~/.cache/asservat-build/codex-bf86-resume/slow-native-qualification/slow-native-owner-renewal-1-environment.json`,
SHA256 `0b8e675ae6c23b111738a3e480e1561520cdd76a5cae70334267e600e717e5c3`.
The pre-cancellation-guard candidate qualification selected both
`download-worker-native-exchange` and `download-worker-native-owner-renewal`:
9.60 s and 10.64 s respectively, top-level 20.63 s, Go exit 0, harness phase
including compile 46.783 s. Source hashes were unchanged and cleanup failures
were empty. The native exchange delivers the exact existing 4 KiB response over
actual TLS with actual PostgreSQL/S3 audit and three one-use key slots. Its
Pod-proof/bootstrap/human inputs remain synthetic; this is neither actual
TokenReview qualification nor a paced composed 8 MiB payload measurement.

Archived prior report:
`~/.cache/asservat-build/codex-bf86-resume/slow-native-qualification/slow-native-exchange-7-environment.json`,
SHA256 `b6124d1124b6e25ece89edbad571f299005c88382b0ebfbdc18a71230028dff8`.

Earlier composed runs exposed two deadline defects rather than qualifying this candidate.
Clamping an already-normalized operation end to a nanosecond context deadline
caused equality failure after SQL normalized its result to microseconds. The
regression now normalizes after every clamp, only shortening the deadline.
After that fix, the regional reader still rejected the longer response context
before reading: its initial five-second key/opening phase and retained cursor
shared one deadline. A failing actual-adapter regression led to the separated
contexts above. Encrypted-object tests prove three key opens once, exact reads
after opening cancellation, and refusal after owner cancellation. That native
run verifies the composed path after both deadline corrections.

Strengthening the cancellation regression then exposed buffered plaintext being
returned after owner cancellation without another cursor read. The corrected
reader refuses already-expired calls, checks explicit caller cancellation and
original owner expiry after blocking reads, and clears buffered plaintext when
closing. A piece observation expiring during an owned frame load does not cancel
the cursor; independently fresh disclosure authority is required before delivery.
An actual blocked-object regression returns the verified frame after its short
piece observation expires, then succeeds on a fresh contiguous read. Explicit
caller or original owner cancellation refuses the next otherwise-valid range and
clears the buffer. The earlier native report is not evidence for that later change.

Final post-guard qualification selected both native cases with all deadline,
reader, cancellation and short-piece-expiry corrections present: native exchange
9.36 s, owner renewal 10.21 s, top-level 19.96 s, Go exit 0, harness phase
including compile 43.429 s. Before/after source hashes were unchanged and cleanup
failures were empty. The actual 4 KiB SQL/S3/TLS/key-slot scope and synthetic
Pod-proof/bootstrap/human boundaries above remain unchanged. The affected
objectstore/evidence/native race suites also passed (5.081 s/4.847 s/98.921 s),
including the blocked-object observation-expiry and explicit-cancellation cases.

Archived final report:
`~/.cache/asservat-build/codex-bf86-resume/slow-native-qualification/slow-native-exchange-8-environment.json`,
SHA256 `e4ff44c6e6945dccd6f970cf06d023e581b7fdd4f1a0ff892eddcf767a553a7a`.

Review regressions subsequently reproduced two implementation gaps in these
contracts: a valid higher-sequence observation with an earlier timestamp could
be accepted without recording its sequence, and a same-instant lease represented
with another time zone or through JSON could trigger renewal or fail ACK. The
gate now retains every accepted higher sequence and conservatively intersects a
lagging same-sequence cutoff. The source renews only on sequence increase and
matches ACK by exact window/sequence plus current expiry. Changed scope, stale
sequence and expired ACK remain denied. Test exchanges use the same window,
sequence and expiry semantics as the production operation. Both regressions
failed before the corrections. The complete affected race packages pass:
evidence 4.883 s, native transport 101.577 s and mTLS 41.284 s. The archived
SQL/S3 and Kubernetes reports above predate these review corrections.

A further review reproduced storing the caller's delivery lease before the
post-body gate confirmed its sequence, and accepting an unconfirmed future
sequence for ACK. Delivery state now advances only after successful matching
gate confirmation. A failed confirmation clears plaintext and cancels the
existing operation without changing its accepted lease or releasing pending
accounting. ACK requires a live operation/caller and the exact accepted sequence
before consuming pending bytes. RED/GREEN tests cover each mutation boundary and
successful advancement. Full affected races pass: native 98.944 s, evidence
4.854 s and mTLS 34.752 s. Earlier external qualifications retain their original
source scope; they do not qualify this later correction.

The candidate twenty-second ceiling still implies about 0.4 MiB/s for a full
8 MiB window before control overhead. Aggregate installed SQL/S3/KMS/API cost
and practical slower-link qualification remain pending. No arbitrary slow-client
support or full installed download completion is claimed.
