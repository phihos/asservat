# ADR-206 — Bounded approved pod-status projection reads

Date: 2026-10-18. Status: accepted implementation decision; component foundations
implemented, production composition and native qualification pending.
Requirements: REQ-MCP-002/004, REQ-AUT-002/005, REQ-EVD-005/008,
REQ-PRV-003/004; S-02; TASK-03/07/08.

## Context

S-02 requires inspecting captured approved content through browser and MCP.
Case descriptors and authenticated native downloads are separate capabilities.
The canonical `get_file_excerpt` and `get_query_result` operations already define
ordinary approved reads, pending handles and bounded results. SC-AUT-005 requires
a new server audit request ID per invocation and no extra caller-managed
idempotency key for ordinary reads.

The existing pod-status collector emits the fourteen required properties in
`pod-status.schema.json`: `format` and thirteen status/provenance fields. Its
4096-byte native ceiling and independently verified publication permit a narrow
fixed projection. They do not confer read authority or qualify a new delivery
path. Existing acquisition, native relay and key ledgers are purpose-bound to
downloads; their authority cannot be relabeled as a query.

This decision implements the already accepted investigation requirement under
the resumed one-shot implementation goal. It is not a new user-selected product
feature or permission to advertise an unqualified capability.

## Decision

1. **One fixed approved projection.** Support only a committed, independently
   verified `asservat-pod-status/v1` artifact through `get_file_excerpt`. Return
   `data_class=metadata` and the synthetic logical document `pod-status.txt`.
   [The architecture contract](../architecture/context-projection.md#exact-result)
   fixes field order, scalar formatting and line selection. No arbitrary path,
   live workload read, raw query, general parser, share fallback or new capture
   is part of this profile. Native bytes and storage format remain unchanged.
2. **Independent ordinary-read authority.** C-03 evaluates `ReadApproved` with
   `evidence:read`, current identity/client, complete denies, exact case/artifact,
   original retained audience, all retained policy origins, processing, recovery
   and a currently accepted query delivery path. C-18 owns the query. C-14 owns
   scoped acquisition and delivery; only the isolated acquisition/key roles can
   decrypt. A download permit cannot authorize a query, and a query permit cannot
   authorize a native download. No additional consent or raw grant is introduced.
3. **Original total and request deadlines.** The query fixes a ten-second total
   lifetime by default; a protected administrator profile may select a lifetime
   no greater than sixty seconds. Effective artifact access can only shorten it.
   Initial token/session expiry is not a separate total-query cutoff: each
   fresh read needs current authority for the same original principal/client.
   Each invocation and each
   acquisition/key/output operation also obeys its original at-most-five-second
   current-request interval, that request's session/credential bounds and every
   earlier dependency deadline. A pending
   response, new poll, authority observation or batch never extends the query.
4. **A result backed by the immutable source.** The result reference binds the
   original committed ciphertext version, native projection digest, display
   version and line selection. SQL retains minimized query/control/accounting
   state, never native fields, output lines, native checksums or credentials.
   No retained plaintext result cache or new stored derivative is introduced.
   Bounded worker/hub response buffers remain accounted managed copies with
   explicit ownership and joined cleanup; no plaintext PVC or disk fallback.
   General offline analysis still requires ADR-036's separate isolated phases
   and qualified encrypted scratch.
5. **Creation and passive retrieval are separate.** An initial `get_file_excerpt`
   may admit one query and its exact acquisition worker under that live request.
   If not ready, it returns the existing pending handle. `get_query_result`
   observes that existing query and, when its exact admitted worker is usable,
   reads its bound result. It has no worker-create, replacement, capture,
   analyzer-start or repair port. Neither handler requires a user idempotency
   key or a new continuation flag. Repeating an initial read may admit another
   separately charged query within aggregate limits; unknown earlier work stays
   charged. Audit receipt recovery never redispatches application work.
6. **Purpose-specific finite batches.** Every result delivery prepays its own
   query batch, increasing generation, read/output work, audit and three one-use
   data/index/manifest unwrap slots under the same original query. The initial
   profile allows at most two delivery batches and one admitted worker, with at
   most one in-flight batch. Each batch reserves 4 MiB of read work, matching the
   existing conservative small-context allocation, not measured source size or
   overhead. Result and wire caps remain 24 KiB and 64 KiB respectively, including
   the result-poll wrapper. Worker, buffers, control, signing, SQL history and
   cleanup need their own finite protected backing before enablement. No
   download-session, owner-window or key-slot quota is borrowed or reset.
   Accepted query backing separately covers worker/credential/provider effect
   horizons and later cleanup/history, not just the result lifetime. Passing a
   funding date is no proof of retirement and cannot erase uncertain charges.
7. **Accounted repeat delivery, conservative uncertainty.** A lost outward reply
   after a positively joined private read can be delivered again by a fresh
   charged batch under the same query. Repeated batch IDs cannot reexecute or
   refill keys. Uncertain private closure keeps the worker/work charged and
   blocks reuse; local EOF, SQL fencing or expiry alone is not positive remote
   completion. The first implementation fails closed rather than replacing that
   worker. Exhaustion or expiry does not silently create a successor query.
   Initial insert and one-use read-start acknowledgement are distinct; a
   repeatable current fence cannot authorize another start. The active batch
   remains held through outcome audit, outward write and joined cleanup. Only
   a C-14 process-owned closure guard permits SQL's restrictive completion.
8. **Audit and final disclosure checks.** Durable intent precedes sensitive work.
   A bounded result is validated against the original canonical tool schema and
   its outcome is durably acknowledged before disclosure. Recheck current
   identity, ordinary rights/denies, audience, retention, processing, recovery,
   query generation and original deadlines after audit and at the final bounded
   transport write. The outcome records prepared bytes and possible unknown
   delivery, never client receipt. Pending admission/read effects must not be
   labeled effect-free merely because the operation name starts with `get_`.
9. **One browser/MCP implementation.** Both transports use the same C-18 service,
   canonical inputs, result validation and current-identity contract. A query
   handle binds the originating principal/client and original tool. Browser
   views clear managed results on their original cutoff, scope loss and closure;
   they do not automatically start another query after a terminal outcome.
   Full native download remains independently available under its own contract.

## Consequences and qualification

The fixed projection needs no general offline analyzer or retained result cache.
A repeat delivery costs another complete bounded source read and fresh key slots.
This is deliberately limited to the existing approved pod-status format; it does
not relax isolation for ELF, packet, log, memory or other untrusted parsers.

New query-specific SQL facets, key consumption, worker/protocol purpose, audit
normalization, installer projections and current path acceptance are required.
Sharing lower-level verification, TLS or framing code does not establish those
authorities. The regional local read/verification component deliberately cannot
implement the remote closure capability: local proof checks and known execution
handles must join, but only independently authenticated remote completion can
release the active SQL batch. An uncertain opening still closes any known local
handle under its original cleanup horizon without claiming remote completion.
Installed proof/read/audit latency must fit the unchanged five-second
request intervals and original query lifetime at production resource limits.

The [architecture acceptance cases](../architecture/context-projection.md#acceptance)
must pass before runtime composition advertises either tool. This ADR and its
offline documentation gates are not evidence of implemented reads, qualified
native transport, a completed S-02 or existing-install upgrade compatibility.

## Owned HTTP framing after successful payload flush

A local actual TLS/HTTP2 counterexample showed that a complete JSON payload can
arrive before its original disclosure deadline, with Write/Flush succeeding,
while deferred synchronous owner cleanup holds the handler past that deadline.
Go emits END_STREAM after handler return; the retained stream write timer can
reset the stream before that empty completion. This is a reproduced owned-query
lifecycle defect, not an attribution of an installed history/settings failure:
`get_capture_settings` and history metadata replies have no such private owner.

The engineering correction keeps original payload checks, deadlines and joined
cleanup. Only a successfully flushed acknowledged owned reply can move the
framing deadline to the earlier ORIGINAL owner/request and cleanup cutoff while
both the original write context and byte deadline remain live. There is no
now-plus-grace, timer clearing, asynchronous cleanup or extra application body.
Exact Content-Length and no declared trailers apply to these owned responses;
the actual browser/MCP success paths write no later headers or trailers. Failed
and partial writes never receive this handoff. When both original cutoffs coincide,
a successful writer remains successful
without a handoff: immediate joined cleanup can finish normally, while cleanup
crossing the unchanged deadline can still fail naturally. Unowned metadata stays
on the existing writer path.

Per owned response this adds one stream-deadline control call, one owner mutex
acquisition and a bounded Content-Length header value; it adds zero backend/API/
SQL operations, credentials, watches, services, application timers or goroutines.
The existing HTTP transport may reset its own stream timer. Aggregate work scales
with already admitted query responses and preserves their concurrency/output
ceilings. No new configuration, fallback or upgrade protocol is needed; response
JSON and public authority intervals are unchanged. Resetting a deadline to zero,
moving cleanup into a goroutine, or closing/wiping before payload delivery were
rejected as broader or unsafe alternatives. Doing nothing preserves a concrete
loss of successful owned responses. This is an agent engineering comparison,
not a new maintainer requirement or installed-query qualification.

The typed C20/C18/audit fixture exercises real TLS/H2 with synthetic underlying
authority/reader/ledger ports: full payload arrives before its original cutoff,
cleanup remains held through that cutoff, and EOF plus actual completion follow
only after release. Browser serialization and an MCP-shaped wrapper use the
same typed writer. This does not prove the full production MCP SDK/query route,
SQL/provider custody or installed public query execution. HTTP/1/H2 controls
cover exact-length overshoot rejection, valid unsent problem output, original
parent/cleanup caps, lock-delayed expired/canceled handoff, failed/partial writes,
trailer refusal and unchanged unowned metadata. Go Flush may complete through
connection buffering; the contract describes application writes, not peer ACK.
