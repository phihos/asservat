# ADR-260: API target observations after completed authenticated queries

Status: accepted implementation decision; installed qualification pending.
Requirements: REQ-EXE-001/002, S-01/S-02. Revises the API target-result lifetime
choice in [ADR-179](179-outbound-only-first-installed-profile.md).

## Observed problem and existing coupling

Installed runs 40557482326 and 40563988015 refused an approved packet request
before admission at `request/facts/current/target`. The latter ran unchanged
e6a2fbfb, with clean cleanup and all 3,193 source hashes independently matched.
Its 129.68-second approved subtest includes the deliberate 120-second preview
wait; it is not the duration of `Request`. The log identifies an invalid target
at consumption but does not measure which constituent target cutoff expired.

The first correction removed duplicate work: two regional queries became one;
a Deployment's exact target/availability GETs fell from ten to eight. The next
installed run still refused. Source inspection identified an independent
lifetime coupling: the API resolver shortens its first-read-plus-five-second
observation to its I/O context deadline, already bounded by the regional owner
proof. The hub then shortens the result again to the query's checked receiver
and frame cutoffs. A newly completed object read can consequently have almost
no remaining usable observation interval.

A composed regression reproduces that coupling through C09 preview/request,
the ordinary C03 eligibility evaluator, Router/Standby, both context-start frame
streams and the real regional API resolver against an owned TLS fake API. A
250ms transport proof completes the query; a subsequent 400ms storage read is
cancelled by the inherited target cutoff. Admission remains zero. Identity and
permission projections, recovery, grant, recorder availability and admission authority in this test are
explicitly synthetic. This proves the protocol/coordinator boundary, not a real
Kubernetes installation or the exact timing of the failed native run.

## Decision

API-class `PodResolution` is exact object-identity/version metadata, not a
permission, recovery proof or execution permit. Apply one freshness rule to
workload selection, exact Pod resolution and combined packet resolution:

- Preserve `ObservedAt` from the earliest constituent target read and a result
  lifetime of at most that original start plus five seconds. Nested exact
  resolution cannot restart an earlier selection interval. An earlier producer
  result cutoff is never raised at the hub.
- Keep the original resolver/query contexts, source pull, owner/receiver checks,
  frame deadlines, cancellation and matched completion checks during I/O.
  Expiry or cancellation before successful completion still discards the result.
- After successful authenticated completion, do not inherit that exchange's
  authentication/transport cutoff into the metadata's subsequent freshness.
  Retain its own original observation interval, never a new interval at receipt.
- Keep C09's original five-second `Request` context, earlier parent deadline,
  current identity, deny/eligibility, grant, recovery, capability, retention,
  storage, processing and admission checks. Retain exact approved namespace,
  Pod and owner comparison and the independent queue-time Pod/node/collector
  checks. A snapshot alone never authorizes an effect.
- Leave NodeExecution target behavior, node/boot identity and authority-bearing
  source/access/restart answers unchanged. No transport-wide deadline is removed.

This changes an explicit agent-authored guarantee in ADR-179 and the execution
contract. It is not a newly asserted maintainer requirement. The maintainer's
standing proportionality and continuation instructions authorize reconsidering
that design choice while preserving current authority and original operation
deadlines.

## Accepted risk and precedent

A target observation acquired and completed under valid source/peer
authentication may remain usable until five seconds after its earliest target
read, even if that particular transport authentication proof expires afterward.
The existing freshness model already permits object changes inside that finite
interval; UID/version observations do not promise that the object stays unchanged.
The consumer's independent current authorization and execution checks remain
decisive. Known peer invalidity or expiry continues to refuse I/O under the
existing source/peer checks; completed metadata does not renew those proofs or
rewrite its observation time. This adds no immediate-revocation guarantee.

[Go contexts](https://pkg.go.dev/context#Context) bound work and cancellation.
Kubernetes separately defines [UIDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids)
as object-incarnation identities and [resource versions](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions)
as observed versions. This supports separating request lifetime from returned
metadata; it does not supply Asservat's authorization policy. Existing
`HubOperations.ResolvePod` also returns the regional target observation while
its work exchange and execution checks retain separate bounds.

## Complexity and compatibility

1. Two installed attempts with precise target-refusal labels failed an ordinary
   supported workflow; this is not a hypothetical production incident count.
2. No maintainer requested transport-proof lifetime inheritance for target data.
   The bounded post-query use above is an explicit design revision.
3. Uniform API metadata semantics help ordinary preview/request paths and avoid
   a packet-only timing mode for the same value type.
4. Context/UID/version separation has the limited precedent stated above; no
   claim is made that another project's security model qualifies Asservat.
5. Zero added permissions, credentials, endpoints or retained payload fields.
6. Zero new durable, degraded or fallback states; existing refusals remain.
7. Zero configuration switches or caches.
8. Zero new components or external dependencies.
9. Zero additional API/SQL calls, watches, timers, goroutines, storage or network
   exchanges. The earlier eight-GET/one-query optimization remains in place.
10. No migration or wire-field addition. An older producer's shorter cutoff is
    retained; an older consumer can still apply its stricter cap. Rollback
    restores refusals, not authority. Mixed-version installed behavior remains
    unqualified; no release is authorized.
11. Re-resolution adds another eight target GETs plus authentication/query work
    per attempt and can expire again. Refreshing proofs adds work without
    changing the object observation. A longer TTL/request deadline increases
    another budget rather than fixing the coupling. Doing nothing leaves the
    observed workflow unusable.

## Verification boundary

The composed matrix passes locally in 7.387s: hub-only, regional-only and both
250ms completed proof cutoffs allow the later 400ms storage read and reach the
synthetic admission boundary. I/O expiry/cancellation, current deny and expired
human/recovery/grant inputs still refuse. An eight-second parent does not extend
C09's original five-second request cutoff. Adapter tests separately retain the
earliest selection/read's original five seconds, including a nested read that
would still be fresh on its own; shorter producer cutoffs remain unchanged.
NodeExecution and unsupported-peer cases remain covered. These protocol/adapter
tests do not establish installed collection. Full pre-push, affected races,
selected Kubernetes adapter races and the static libpcap command build also
pass. A fresh guarded installed approved-recording run, current CI and review
remain required.
