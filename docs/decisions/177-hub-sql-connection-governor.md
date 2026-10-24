# ADR-177 — Per-purpose logins under a process-wide SQL connection governor

Date: 2026-10-14. Status: accepted; governor and the 22 hub extension roles implemented, roles verified on real PostgreSQL; hub-api public composition and the browser duty move pending.
Requirements: REQ-DB-004 (specs/persistence.md connection budget), S-02; TASK-03 / TASK-11.

The one-login-per-purpose choice is partially superseded by
[ADR-215](215-hub-metadata-reader-role.md): seven hub metadata readers share one
login and pool, and [ADR-217](217-api-execution-role.md): API execution read,
preparation and record share one login and pool, under the unchanged process
governor. The account below records
the original layout and its qualification, not the current credential count.

## Context

Each hub duty has its own NOINHERIT login with one `MaxConns=1` pool. The
hub replica is at exactly 32 purposes: 28 public and 4 owner-identity.
specs/persistence.md allows at most 32 pooled connections per hub replica.

The full S-02 hub-api needs about 55 purposes. Besides those 32 it needs:

- the owner `routing` and `native-read` pools, which hub-api already opens
  but which are neither budgeted nor provisioned;
- API execution prepare, record and read;
- publication verify, verification audit, publish and gate;
- downloads, download audit, download workers, worker enrollment (three),
  worker owners, native owners, key binding, native key authority and three
  stop duties.

These must run in the hub-api process. The worker-enrollment router, owner
claims, the native runtime and context start all bind to the actual serving
process (ADR-074/075/139/171).

A shared login that switches with `SET LOCAL ROLE` was rejected. The schema
authorizes by the login itself:

- `capture_audit_role_ok` and the SQL54 capacity checks pin
  `session_user` OIDs.
- They require NOINHERIT and the absence of any role membership.
- The lifecycle views filter `current_user = session_user`.
- The Go credential verifier enforces the same rules.

A shared login would also hand one credential every purpose, which
`RESET ROLE` after any query bug could use. Adding process compartments alone
cannot fit the budget, because the request-path duties must stay in-process.

## Decision

1. **Keep one login per purpose.** Every purpose keeps its own NOINHERIT
   login, exact connection limit, provenance and `MaxConns=1` pool. No SQL
   function, pin, view or verifier changes.
2. **Cap physical connections per process.** One `SQLConnectionGovernor` per
   process limits how many pools may hold a physical connection at once. For
   hub-api the limit is at most 32. specs/persistence.md limits pooled
   connections, not logins.
   - **Hot purposes** keep one persistent connection, permanently counted:
     identity, browser session and refresh, the audit journal and
     acknowledgement lanes, capture admission/journal/acknowledgement,
     downloads and native owners.
   - **Cold purposes** take a governor token before acquiring. They close
     their connection after its transaction is released and return the token
     when the connection closes.
   - **Reserved tokens** keep audit acknowledgement and stop/deny paths from
     being starved by reads.
   - Each new connection re-runs the existing
     `current_user = session_user AND oid = receipt` check.
3. **Budget the cap, not the purposes.** A compartment's budget is its
   governor capacity (`MaxOpen`). The installation-wide allocation is
   `processes × MaxOpen` plus verifiers and the maintenance reserve. The
   per-purpose role connection limit stays at retained processes plus one
   verifier, because a process holds at most one connection per purpose.
4. **Small compartment moves.** Browser settings observation and browser
   cleanup move to the hub-worker. Configuration, history and stop-lifecycle
   cleanup duties stay outside hub-api. Publication moved to its own
   asynchronous publisher process under
   [ADR-181](181-asynchronous-publication-verifier.md).
5. **New purposes get permanent ordinals** in the existing public runtime
   layout, from free slots (7–9, 21–29, 35–39, 57–69). Their exact grant plans
   live in `public_runtime_role_plan.go`. The owner `routing` and
   `native-read` pools join a provisioned layout.

## Consequences

Authorization facts are unchanged. A process compromise still yields every
purpose credential of that process, as it does today. Each cold transaction
pays a TLS 1.3/SCRAM handshake, so hot-path selection is load-tested.

A backend that is still closing can briefly count against a role's connection
limit (SQLSTATE 53300). Acquisition retries that within the request's
original deadline, never beyond it.

The governor must never be acquired while the caller already holds another
purpose's transaction, or it could deadlock. Callers must avoid that nesting;
the current socket governor does not detect acquisition call chains.

`MaxConns=1` still serializes each purpose per process. Hot-path concurrency
is a separate, measured follow-up.

## Implementation

1. **Contracts:** `SQLConnectionCompartment.MaxOpen`; `Validate` checks
   `MaxOpen` against the per-replica rule. The installed plan includes the
   owner `routing` and `native-read` pools.
2. **Governor:** `postgres.SQLConnectionGovernor`, with governed pool
   construction (`MaxConns=1`, `MinConns=0`, close-after-release for cold
   purposes, token release after the physical socket closes) and the post-connect identity
   check.
3. **Roles:** ordinals and grant plans for the new purposes; the role matrix
   on real PostgreSQL.
4. **Native qualification:** the native journey runs without its fixture
   pool-retirement workaround, asserting through `pg_stat_activity` that the
   hub stays at or below its cap.

Tests:

- The governor never exceeds its cap, releases a token only after the physical
  socket closes, and honors reserved tokens. Nested-acquisition detection is
  not implemented or qualified.
- The budget plan keeps the hub at or below 32.

## Progress

- **Governor.** `postgres.SQLConnectionGovernor` takes a slot when a socket is
  dialed and returns it when the socket closes, so a failed handshake cannot
  leak one. Hot pools reserve `MaxConns` dedicated slots; cold pools share the
  rest and close after release. hub-api's owner pools are governed at 32. The
  budget plan counts the governor cap and includes the owner `routing` and
  `native-read` pools.
- **Failed pooled connection cleanup.** pgx cancellation cleanup opens a
  second socket before closing the failed connection. With one dedicated slot,
  that can wait on the slot held by the same connection while the pool waits
  for cleanup. The governor chains the pool's existing `BeforeClose` hook and
  closes the underlying governed socket only when pgx already marks the
  connection closed. This happens before the pool joins cleanup and returns
  the slot only after the actual close. The default cancellation watcher,
  typed errors, healthy reuse, graceful shutdown and connection limits remain
  unchanged. Installed factories perform credential verification after pool
  construction; arbitrary custom post-authentication constructor callbacks
  outside pooled ownership are not qualified by this fix. A slow cancellation
  endpoint or shared-slot contention can still consume the existing cleanup
  bound. Pool acquisition retains its caller deadline; pgx may finish a
  connection constructor after that acquisition is cancelled, within the
  configured connection timeout.
- **Hub extension purposes.** There are 22, at ordinals 21–29, 35–39 and
  57–64:
  - API execution read, prepare and record;
  - the publication gate, context verify, verification audit and publish;
  - download session and audit;
  - the download worker, worker audit and worker identity;
  - worker enrollment, enrollment audit and enrollment activate;
  - the worker owner and native owner;
  - download and native key bind;
  - download stop, stop writer and stop acknowledgement.

  Their grant table (`public_runtime_hub_extension_grants.go`) is generated
  from the qualified fixture roles' GRANT statements. Some journal tables keep
  their whole-table INSERT; triggers guard them.
- **Real PostgreSQL.** The initial-installation suite provisioned all 64
  roles through the product role producer with exact ACL verification
  ([result](../../test/results/adr177-roles-1/result.json): exit 0, 87 tests).
  An earlier run failed because the exact table inventory did not yet list
  migration 62's `context_key_wrap`; first activation correctly rejected the
  unknown relation.
