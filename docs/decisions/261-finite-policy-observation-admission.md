# ADR-261: Finite policy observation admission

Status: accepted engineering design (2026-10-28); implementation and native qualification pending.

This revises the agent-authored short-lease choice in ADR-259 under the
maintainer's complexity/proportionality instructions. Twenty seconds is an
engineering bound, not a maintainer-selected interval and not an application of
the download timing clarification. It does not enable a recorder.

## Decision and exact scope

First compose one explicit finite `onTrigger`, before-zero, single packet action
under a real accepted policy, its original independently approved grant and real
capture/Pod. The initial increment supports a recording duration up to 15 seconds
only when its reviewed session and other original bounds leave sufficient start
slack. Manual raw observation and default ongoing policy arming remain separate
unfinished requirements. Their existing unavailable gates remain closed.

New admission, permit issuance and any future renewal require current identity,
complete-deny, source, delegation, recovery, target and original-grant checks under
their existing at-most-five-second preflight bounds, after blocking locks and
before dispatch. Each source keeps its own original observation interval; this
does not turn the policy source's 30-second observation into a new timestamp or
extend a five-second deny/recovery fact.

A committed, independently prepaid finite admission creates a distinct active
execution lease of at most 20 seconds. It may outlive transient check intervals;
those intervals are not described as still fresh. Original review, action,
session, grant, capture, retention and local hard expiries always win. A reviewed
15-second session does not gain a 20-second session. If the full recording cannot
fit, decline rather than silently extend or restart it.

Keep latest start separate from recording duration:

`startBy = min(existing original start bound, leaseUntil - requiredDuration)`

The existing node start allowance is at most ten seconds; this rule only shortens
it. Already-issued work may start within that original short latest-start bound
without issuing a fresh permit. Once started, the node owns the action through
its process lifetime, fixed admitted lease and recording-duration timer, not the
completed request's context. Expiry, changed incarnation or closed meter cannot
be rearmed by replay, reconnect, an attachment change or another request key.

## Revocation and residual

Once authoritative grant, deny, policy-source or recovery changes are visible to
the issuer, new admission/issuance/renewal refuses. Already-issued work may still
start within its original latest-start bound and continue only to its fixed
active lease, no more than 20 seconds after issuance. In particular, an issued
lease can outlast a subsequent revocation by its remaining lease lifetime.
External configuration changes additionally retain their existing qualified
observation/propagation delay; the active-lease bound is not an instant-change
visibility guarantee.
For a source whose qualified visibility lag is five seconds, the composed
external-change residual can therefore be that lag plus a twenty-second leaf,
not universally twenty seconds. Other sources keep their own qualified lag.
An authoritative SQL grant revocation or recovery fence blocks later issuance
under the existing locks once committed; an already-issued leaf is not extended.

No connected packet stop operation is implemented today. `WorkStopSource` being
an enum value is not cancellation support. Do not claim immediate interruption
or add a watch/outbox/service to imply it. A later qualified stop may shorten this
residual but cannot extend it. Finalization/upload uses separate existing bounds
and cannot acquire more input after the lease ends.

## Credit and actual binding

Reserve once, before dispatch, from both original remaining observation pools:

`C = min(reviewed ceiling, R * (ceil(D_seconds) + 1), policy remaining, grant remaining)`

`D` is the actual finite recording duration that fits the original hard bounds;
`R` is the reviewed/compiled rate. The extra second is the existing token bucket's
one-second initial burst. This formula depends on the actual rate/whole-frame
boundary being enforced. At 16 MiB/s for 15 seconds it reserves at most 256 MiB,
not an automatic 1 GiB. Smaller remaining pools can stop processing earlier at
exhaustion; a maximum rate is not a promise of observed traffic or completion.
Credit and unused/uncertain tails remain conservative spend, never measured user
data or a refundable balance. No credit stream, top-up quantum or timer refill.

Reuse the single existing SQL session per real capture and the immutable original
occurrence→capture→grant tuple. Bind actual Pod/node/boot/collector Pod/process
incarnation, action/program/expectation and accounting-rule digests. Source and
node observations grant no authority. Compare the same actual tuple under the
node-channel enqueue mutex, then debit whole original wire lengths before the
predicate. Missing length, stale binding, loss, exhausted credit/rate or expiry
must not continue sensitive processing. Join engine teardown before releasing
local resources. Gadget's bounded prefix copy is not a before-kernel-copy gate;
actual published prefix/loss behavior still requires qualification.

## Transport and ownership

Reuse the authenticated same-work start exchange tied to its existing signed
capture/expectation. Avoid an independent initial JWS/provider operation. The
current first work signature precedes later SQL preparation; do not claim that
an eventual SQL permit was already present in those signature bytes. The typed
permit must travel on that authenticated operation and match its exact accepted
work, SQL session and resolved node. No remote DTO selects a policy/grant budget.

The shared value owner is C-24 `domain/collector`: byte-compatible local binding
and permit, with the accounting rule represented by its fixed canonical digest
(test-verified against the documented version string). Do not broaden the pure
domain crypto allowlist solely for this move.

Use one primitive C-24 `targets.PacketSourceObservation` containing PodUID, NodeUID,
BootID, CollectorPodUID, CollectorEpoch, ObservedAt and FreshUntil, optionally in
RecorderAnswer.Source. C-19 EnqueuePacketExpected consumes that same value directly
and checks cancellation and its original interval/tuple under the existing
injected clock and enqueue mutex. The catalog already permits C-19 → C-24,
including targets; delivery → targets has no Go import cycle. No duplicate
collector source type, bootstrap field mapping, catalog expansion, extra deadline
timer, freshness interval or configuration is needed. Source facts remain
separate from the committed grant/session permit. C-09 consumes the observation;
C-11 consumes the committed permit; C-21 implements the existing SQL facet.

## Cost and alternatives

The first finite action needs no authority renewal if it fits the lease. Retain
one guarded initial SQL transaction, actual node binding, both counter updates,
one session and bounded terminal retirement. A provisional seven observation SQL
statements is a source estimate, not a measured query/latency result. Count actual
statements, round trips, initial signing/provider operations and WAL during
qualification. No new table, listener, credential, watch, worker or machinery-only
configuration is intended.

| Incremental renewal cost | One finite action fitting its original lease | Rejected provisional three-second renewal |
| --- | ---: | ---: |
| One 15-second action | 0 transactions/signatures/RPC pairs | about 4 transactions, 4 signatures, 12 RPC pairs |
| 64 simultaneous 15-second actions | 0 renewal operations | about 256 transactions, 256 signatures, 768 RPC pairs |
| 64 continuously active long sources | not implemented by this increment | about 21.3 transactions/signatures and 64 RPC pairs per second |

These are arithmetic comparisons, not production measurements. The initial
transaction/provider/dispatch latency and maximum concurrent native costs remain
unmeasured. Existing local meter and compilation microbenchmarks do not establish
end-to-end CPU, throughput, revocation or prefix bounds. The measured current SQL
setup aggregate includes other work and is not attributed to a packet session.

Kubernetes separates request authorization from an exec stream's lifetime:
its [authorization filter](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go)
calls the authorizer before the handler, while the [exec handler](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/kubelet/pkg/cri/streaming/remotecommand/exec.go)
passes the request context to the executor. Go's [HTTP profile handler](https://github.com/golang/go/blob/go1.26.0/src/net/http/pprof/pprof.go)
starts profiling, waits for a finite interval/cancellation, then stops. These are
execution-lifecycle precedents only; neither supplies Asservat's grant/quota
semantics or proves that twenty seconds is the right privacy tradeoff.

## Qualification and remaining work

Under existing REQ-PER-006, REQ-AUT-004/006 and their scenario IDs, prove issuance
after locks with original fresh facts; exact-node CAS; latest-start/duration/hard
expiry; no rearm/refill after unknown/replay/epoch replacement; both pools charged
once; zero retained output still consumes observed input; cancellation/join and
bounded session retirement. Prove manual raw remains unavailable and ordinary
headers retain their current behavior. Keep raw refusal until SQL, authenticated
node binding/transport, actual prefix/input-loss, cleanup/backing and native
qualification pass. SQL output reservations alone are not packet acquisition.

Longer finite actions may later renew only when due, with original rate/session/
credit identity and current checks, using measured loop latency/fairness bounds.
The existing collection loop is not implicitly an authority renewal. Do not add
the held three-second machinery now. Default ongoing arming, manual raw authority
and full installed S-04 workflows remain required and unfinished.
