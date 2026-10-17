# ADR-148 — One public projection enforcement interval

Status: accepted; component Go/race/vet checks pass; native qualification pending.

The public role projection repeatedly traversed the same native proof through
nested current/read/update calls. With the unchanged 20 QPS/Burst 20 clients,
a controlled TLS component case made 86 API requests with 46.003 ms transport
I/O, exhausted the original 3,551 ms remaining SQL-verified interval, and returned
a changed-source error after the claim and Secret existed but before the receipt.
The original interval and API rate limits remain mandatory.

Within one serialized PublishPublicRuntimeProjection, obtain the first real
independently denied enforcement proof and retain its original observation and
expiry. Intersect the caller, SQL-verification and five-second deadlines before
any reads; later source/root bounds can only shorten that interval. Reuse only
that denial while checking complete current policy/binding pins and versions,
namespace, real administrator identity, accepted SQL configuration and original
worker journal/Deployment/account/Lease at each of five explicit boundaries:
before root read; after root read before claim; after acknowledged claim before
CREATE; after exact Secret/root readback before receipt; after receipt before
returning success. Independent source reads continue to bracket each traversal.

A changed or unavailable observation permanently fails the call. Never renew,
reacquire or share its proof across calls. Current pins include full compiled
policy/binding validation, not only names or status. This gives bounded
freshness within the original interval, not instantaneous enforcement revocation
between API requests. Generic role creation/completion and configuration-role
proof behavior are unchanged.

Only an acknowledged first claim permits the sole CREATE. An unknown claim
permits no CREATE, an unknown CREATE permits exact lookup only, and a later
invocation cannot recreate a missing Secret. Receipt CAS remains once-set; a
failed post-write check may leave an original receipt but cannot report success.
Keep unavailable/cancelled reads distinct from positively observed identity
changes. Preserve root cancellation and joined closure of all in-flight work.

No new wire, SQL migration, credential, cache, runtime enablement or user action
is introduced. Component tests must retain the actual default limiter, current
revocation/changed-pin checks, blocking-read expiry/cancellation, unknown writes
and per-call proof acquisition. Actual protected native projection composition
remains separately required; a loopback enforcement fixture is not that proof.

The unchanged default-limiter regression passes after the correction, completing
in 3,006 milliseconds of its original 3,550-millisecond interval. Nine top-level
tests/27 PASS entries and vet pass. The reproduced failure, successful component
checks and two static mirror packaging failures are retained in the
[integration record](../../test/results/public-projection-enforcement-integration.json).

## Fresh worker runtime operation

The fresh provider-installed worker applies this same-operation enforcement
interval to its fixed runtime purposes. One real independent denied proof for
each required guard precedes effects. The final native phase rereads complete
policy/binding, namespace, source, original journal, workload, account, process
and material facts, retaining the first proof's original cutoff. It does not
repeat that proof or obtain a new interval. This is bounded enforcement freshness,
not instantaneous revocation between reads. Any changed/unavailable fact closes
the operation; after blocking I/O every original bound is checked again.

The operation binds the bearer bytes actually sent by the existing observer and
probe transports. Each later request must use the same original client and exact
bytes, and final mounted-token reads must match both. Token rotation cancels
this finite operation; a shared client pointer alone cannot adopt replacement
credentials. No token is logged or persisted. Separate independent source
observations retain their own actual denials and original dates; no native proof
or successful source value is cached across operations.

This is a staged runtime refinement. The original failed sustained worker
component remains recorded, and command selection remains a separate candidate
until the complete generated-Pod/native-provider/SQL transition is qualified.

The historical public-projection adapter and its 20-QPS component evidence remain
unchanged. ADR-149 records a separate, explicit fresh-worker observer capacity
candidate. That resource change does not alter this enforcement interval,
selected proof age, SQL checks, token binding or genuine final mutable reads.
