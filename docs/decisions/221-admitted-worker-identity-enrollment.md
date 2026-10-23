# ADR-221 — Enroll the identity of an admitted worker independently

Date: 2026-10-23. Status: accepted design; implementation and qualification pending.
Related: [ADR-071](071-download-worker-enrollment.md),
[ADR-072](072-worker-credential-channel.md),
[ADR-219](219-shared-approved-acquisition.md).
Supersedes only the certificate-specific human-owner dependency in ADR-072,
[ADR-074](074-worker-request-routing.md),
[ADR-075](075-worker-owner-locator.md) and
[ADR-087](087-live-owner-delivery.md); their native operation ownership and
original delivery/cancellation bounds remain.

## Problem and provenance

Native acquisition and approved inspection are maintainer requirements. Requiring
an already admitted worker to finish certificate enrollment while its human
preparation request remains connected is an engineering choice. It couples
asynchronous Pod startup and certificate renewal to a short public request and
adds certificate-specific registration, polling, owner lookup and forwarding.
The existing public workflow can report Pending without removing the admitted
worker; retaining this socket dependency does not follow from that contract.

The maintainer authorized implementing the specification while simplifying
mechanisms whose cost is not justified. This refinement separates process identity
from evidence authorization. It is not a claim about a particular installed
failure's cause or a measured improvement in startup latency.

## Decision and scope

The existing private worker endpoint serves enrollment locally. It resolves the
exact stored acquisition parent and admitted worker, selects the installed
profile and existing proof reader/coordinator, and completes identity enrollment
under the worker's own HTTP request. The closed parent is either a native-download
session or an approved pod-status query; neither locator authorizes disclosure.
No human credential, active preparation socket or fabricated current authority
is supplied to this enrollment path. Never restamp or replay the stored
`Intent.Authority` as current permission.

Before each enrollment effect, an identity-only SQL transaction locks current
installation recovery first, then the exact parent, accepted worker configuration
and worker state, preserving the existing lock direction. Configuration is checked
inside that same transaction; it must not acquire a second pool connection. It verifies
original root/installation/profile/parent/worker identity, acknowledged immutable
worker intent, claimed and bound Job/Pod, nonterminal unexpired parent, original
`RunUntil`, current unsuspended configuration and current normal recovery with
the original admitted issuer epoch. Recovery uses `fleet_current_trust`, including
the database-incarnation fence; historical enabled flags cannot substitute for
current trust. Read database time after blocking locks and
again before commit. A stopped/expired parent, recovery fence, suspended or
replaced configuration, terminated/retired/replaced worker, or mismatching
identity refuses claim, signing preparation and activation. It cannot create,
adopt, replace, renew or refund the worker or parent.

The existing TokenReview and exact live namespace, service account, Job and Pod
checks still bind the presented Pod token and identity-free CSR to that worker.
The first accepted public key is immutable. Keep encrypted create-only enrollment
and certificate audit, separate audit acknowledgement and activation, one winning
signing claim, at most two spent signing attempts per original certificate period,
strict returned-chain verification and conservative unknown outcomes. Historical
audit acknowledgement remains distinct from current activation authority.

The worker HTTP operation remains bounded by its original caller and at most
30 seconds. Every token/Pod proof and signing permit retains its original
at-most-five-second interval; a new independent proof is a new observation, not
a renewal of an old permit. Worker `CreatedAt`/`RunUntil`, parent deadline and
certificate periods remain unchanged. Existing finite worker startup attempts
and renewal scheduling suffice: no queue, watch, daemon, retry budget or tuning
option is added. Cancellation of the worker HTTP request still cancels and joins
its work and bounds certificate delivery.

Remove only the human-request registration, enrollment polling and owner
locator/forwarding dependency used to deliver certificates. Native operation
ownership and routing, delivery/batch leases, current permission/retention/recovery/
processing checks, prepaid key bindings and exact activated-peer checks remain.
The same certificate permits no evidence read, approved result, unwrap or spend
by itself. A fresh public request must still obtain its purpose-specific current
authority; approved inspection cannot impersonate a native-download session.

## Accepted tradeoff

An eligible admitted Pod token can claim or renew its identity after the human
preparation socket closes, within the unchanged worker/parent lifetime. This
widens the time in which a stolen eligible token could race to claim the first
CSR key. Exact live workload/configuration proof, one immutable key and finite
signing attempts remain, but the design does not claim to eliminate that race.
This is an accepted engineering tradeoff: the certificate alone cannot bypass
current evidence/key authority, and keeping a human socket open is disproportionate
as a condition for independently admitted process identity.

## Complexity assessment

1. **Frequency/harm:** the dependency exists on every cold worker start and
   renewal. Installed preparation failures are recorded, but attribution and
   occurrence rates for this dependency are not established.
2. **Accepted risk:** yes; the wider eligible-token CSR window is explicit above.
3. **Typical use:** yes; both native downloads and approved inspection use it.
4. **Precedent:** reuse the repository's admitted identity reader and enrollment
   state machine. No external project or prevalence claim is made.
5. **Exposure:** zero new services, listeners, credentials or evidence privileges.
   Existing worker endpoint accepts enrollment without the human socket; exact
   SQL-role/grant coverage must be checked during implementation.
6. **States:** zero new lifecycle or fallback states; remove the certificate-only
   active-human-owner rendezvous condition, retaining uncertainty and retirement.
7. **Configuration:** zero new knobs.
8. **Dependencies:** existing Kubernetes, PostgreSQL, audit store and issuer only.
9. **Cost:** removes the certificate-specific human authority reconstruction and
   registration/lookup/forwarding path. Live worker proof and bounded transaction
   reads remain; final call counts and installed latency are not yet measured.
10. **Change/disable:** retain original persisted worker, parent, key and attempt
    identities. Stop/suspension still blocks activation; no development-layout
    adoption, reset or compatibility framework is introduced.
11. **Smaller alternative:** extending the human request or adding polling/owner
    lifetime machinery keeps the unnecessary coupling. Reuse the existing worker
    endpoint and admitted state instead.

## Implementation boundary and qualification

C-14 owns identity-only enrollment coordination; C-20's SQL adapters enforce the
exact admitted-parent transaction. The existing Kubernetes attester, issuer and
private worker transport remain. The ADR-219 closed parent DTO is shared; its
purpose-specific admission, evidence authorization and audit identities stay
distinct. Keep native-download historical JSON and original audit identity intact.

Required regressions cover enrollment after the human request has ended; worker
request cancellation; exact parent/profile/root/Pod/key mismatch; Stop, expiry,
configuration suspension and recovery changes during a blocking SQL lock;
immutable-key and two-attempt races; audit/activation failure and replay without
renewal; and both parent types. A certificate obtained independently must still
fail native/key/approved disclosure without fresh exact purpose authority.
Actual installed qualification must cover cold startup, Pending continuation,
certificate delivery and authorized acquisition under existing production limits.
Tests, build, code generation and external fixtures are unrun for this decision.
