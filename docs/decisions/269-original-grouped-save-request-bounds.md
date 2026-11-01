# Original grouped Save request bounds

Status: implementation and local validation in progress. Sixteen-source native
workflow qualification remains pending. Existing qualified two-source results
retain their original source and dates.

[REQ-SAV-002](../../specs/recording-saves.md) accepts one Save with up to sixteen
sources. Two real sixteen-source workflow attempts admitted the whole group
but queued only one child. In the second attempt admission took 3,513 ms;
2,970 ms elapsed after the SQL acceptance time inside that transaction. Only
2,029 ms of the five-second snapshot dispatch interval remained on return.
The first actual runner start took 469 ms. The child intent's original audit
creation deadline closed 1.486 seconds before snapshot StartBy because it also
inherited the earlier admission observation deadline. These are component
measurements with synthetic process/source/local-start facts, not installed
latency percentiles or sixteen-source native qualification.

The five-second whole-phase overlap was an engineering choice. Keep original
five-second admission observations and all current authorization checks. Carry
one server-owned original request interval through the phases instead of using
an observation's freshness as a committed audit bookkeeping deadline.

Capture the original authenticated requester, request start and hard end before
shortening an observation context. GroupRequestBounds is transient internal
composition, never browser/MCP or preview input. The hard end is at most fifteen
seconds from the original request start and retains the original caller context,
identity/token/session expiry and every known shortening. A later Continue or
replay cannot change the first accepted values.

For newly admitted manual groups only, select each child StartBy once as the
earlier of acceptance plus fifteen seconds, that original request end and the
existing source and processing limits. Ordinary, automatic and singleton
builders retain five seconds. The generic snapshot value accepts a structural
maximum of fifteen seconds; authority to select it comes from the existing
protected group membership, canonical selection and exact expectation. No new
wire marker supplies authority. The node continues to check the typed work,
exact source binding/process, original work deadline, current source lifetime
and bounded ring copy. The regional holder binds the exact accepted expectation
and request before queueing.

A committed group's audit RequestUntil is fixed at first admission within that
same original request interval and existing source/custody/processing bounds.
Original admission facts must still be current at admission effects. Completing
encrypted audit of this immutable accepted intent confers no acquisition
permission. Each child still needs its own acknowledged intent, current policy,
initiator, grant, recovery and retention checks before its bounded start. Joined
audit workers and serial starts remain as selected in ADR-268. Failed callers
clip work; failed children cannot renew a source or suppress valid siblings.

Keep old accepted five-second dates and encoded facts unchanged, including
passive replay and uncertain-commit recovery. New bounds are selected only for
first admission with the original request provenance. Downgrade refuses retained
records with longer group dates that previous code cannot consume; empty
restoration must preserve the latest reason and audit guard contracts.

Processing is still the authored reviewed action/composition limit, independently
bounded by retention and authority. The failed ten-second profile was authored
by the fixture. The builtin network profile defaults to fifteen-second action
and twenty-second composition limits. A future thirty-second fixture profile
must be selected before policy acceptance, grants, sources and previews; it is
not an extension of the failed ten-second records or a qualification of defaults.

The next real workflow qualification must use actual ContextSubmission.Request
with one request owner across real SQL admission, audit and start. Direct SQL
admission followed by a newly created Continue owner does not establish that
composition. Native qualification requires every exact selected child and
terminal artifact/source/cleanup verification.

## Complexity assessment

1. Two real supported sixteen-source requests queued one of sixteen children;
   this is an observed failure, not a hypothetical risk.
2. The maintainer accepted bounded grouped Save and current authorization;
   literal five-second phase overlap was not a maintainer requirement.
3. This enables the supported maximum fanout; previous two-source evidence stays
   distinct and unchanged.
4. Reuse the existing request owner, SQL transaction, audit journal and serial
   dispatcher. No new scheduling mechanism is introduced.
5. Add zero privileges, credentials, endpoints, keys or services.
6. Add no external lifecycle states, fallback or retry protocol.
7. Add no operator configuration.
8. Keep existing PostgreSQL/object-store/key-service dependencies; finite bounds
   do not promise availability under arbitrary delays.
9. Add no client SQL roundtrips, RPCs, watches, background tasks, pools or
   concurrent start slots. Existing SQL calls add one indexed parent lookup and
   one capture-row read per child: at most 32 server-side reads for sixteen
   children. The private admission-lock JSON adds one HardUntil field; public
   and collector wire fields are unchanged. Transient request bounds occupy
   fewer than 128 bytes; existing protected timestamps retain selected dates.
10. Preserve old bytes and dates; test original-caller shortening, current
    denials, old replay and populated downgrade refusal.
11. Removing fixture-only repeated work did not fix the observed composition.
    Transaction-local reuse may reduce repeated checks, but cannot establish
    that sixteen serial starts fit five seconds. SQL batching or parallel starts
    would add locking/error/concurrency costs and are not needed for this change.

## Transaction-local facts reuse

Maximum-fanout runs also exposed repeated metadata reads inside admission. One
group now retains its exact permission-stream/transaction identity, at most
sixteen full-target raw permission projections, and one shared accepted-policy
and delegation fact set. The existing root lock blocks supported policy,
delegation, permission and audit mutations; conflicting review locks also wait.
Budget counters, grant decisions, source snapshots, storage, retention and
recovery effects keep their existing checks and locks.

This retains facts, not eligibility decisions. Every existing boundary still
evaluates the domain policy and initiator rules against current database time,
original source/delegation deadlines and the original verified identities.
Changed scope, transaction, trust or stream identity refuses reuse. A backwards
clock cannot make a reused observation predate its initial read. Ordinary and
replay paths remain uncached; the bundle is discarded when the transaction ends.

Controlled SQL-reader tests perform 64 full eligibility evaluations with one
read of each shared source, acceptance, delegation and delegation-audit family.
That is a query-count result, not measured workflow latency. The additional
shared structs measure 1,296 bytes on the test architecture, plus bounded owner,
action and string references; this is not an RSS ceiling. No schema, query
family, privilege, credential, endpoint, watch, worker, timer or configuration
option is added. Actual workflow results and remaining qualification limits
are recorded in [implementation progress](../implementation-progress.md).
