# SQL43 browser refresh owner handoff

The 25-path payload is frozen under `changes/`; `manifest.json` binds each current
live base and proposed payload SHA-256. No live file or external fixture was
changed/run by this agent. No public runtime route is enabled.

## Scope

- C02 explicit exact-origin/CSRF POST admission; bounded local joined ownership;
  one current protected policy read per second can shorten the originally
  verified credential schedule without per-chunk/provider/token work.
- Concrete SQL43 owner/consumer admission with current C14 permissions, retained
  audience, retention, recovery and actual OwnerAuthenticator serving-process
  checks; separate admission/maintenance/read roles. Existing globally capped
  browser-session capacity includes retained owners across logout; each consumer
  remains backed by its admitted download allocation.
- Original 30-second grace and all original session/download/access ends;
  exact current SQL42 response lease thereafter. Sixteen **active bindings** per
  owner; detached consumer history remains charged and dates cannot reset.
- One-use owned refresh claims, ordinary POST typed Busy/wakeup, exact no-output
  Pending/Settled pause lookup; no byte leases or cached group authority.
- Positive joined closure; uncertain admissions are abandoned only after the
  synchronous SQL call joins and the same browser-root lock resolves any delayed
  INSERT/COMMIT. Unknown cleanup keeps its exact bounded local placeholder.
- Two isolated native hooks: actual provider rotation without tab polling and
  actual SQL/S3/native-metadata/response-backed durable ownership. The former
  uses synthetic demand/process backing; the latter synthetic accepted process
  observations. Those boundaries are explicit in tests and documentation.

## Integrating

Migration43 precedes already integrated44. The payload preserves44 fields/roles.
Schema head stays44; exact pristine inventory becomes70 (two new tables). Parent
should regenerate sqlc against its combined source rather than overwrite later
agent-generated model additions. The three generated paths are included only as
reviewable consistent stage outputs. The runtime roles change is an appended
SQL43 block, not a privilege relaxation for existing roles.

`browser_session.go` is based on the integrated CSRF race fix (base SHA301f66...).
No handler, React, browser OpenAPI or generated TypeScript file is in this payload;
parent's subsequent logout fixes are preserved. `browser_sessions_test.go` adds
one subtest beside the current logout flow; its base includes parent's actual
held-CSRF-decrypt/provider regression. `context_publication_test.go` adds only a
release-separated helper invocation beside the SQL42 response qualification.

The C14 transfer pause consumer is owned by console_delivery. Its existing
`RefreshPause`/reader dependency shape is unchanged. `RefreshOwnerJournal` adds
historical `AbandonBrowserRefreshAdmission` only for the local POST owner; no
public or worker protocol gains that operation.

## Verification

Actual staged commands/results:

- Failing-before `TestRefreshOwnerCurrentPolicyShortensScheduleWithoutAnotherPOST`
  exited1 after1.503s: old persisted schedule waited for another POST instead of
  honoring the new current group deadline. Preserved `owner-policy-before.log`.
- `sqlc generate -f owner-stage/sqlc.yaml` exited0. This checks generation, not
  actual PL/pgSQL trigger execution.
- `GOMAXPROCS=2 TMPDIR=/home/phil/.cache/asservat-build go test -p2 -race
  -overlay=owner-full-go-overlay.json ./internal/domain/identity
  ./internal/application/identity ./internal/adapters/postgres` exited0:
  1.006s /1.065s /1.191s. These are the actual final production/domain sources.
- Final integration compilation exited0 in0.011s. The exact top-level
  `TestContextAdmissionWithRealServices` and `TestKeycloakProvider` cases were
  explicitly skipped because their owned external fixtures were absent. This is
  compile evidence only; `owner-final-integration-compile.log` preserves it.
- Narrow `go vet -p2` for domain/identity, application/identity and postgres
  exited0 (`owner-final-vet.log`).


Parent-owned native runs should select:

- `TestContextAdmissionWithRealServices/.../browser-refresh-owner-durable-consent-and-joined-capacity`
  (follow the existing context-publication subtest nesting; ordinary custody
  default TestContextAdmission selection includes this helper).
- `TestKeycloakProvider/product-browser-sessions/explicit-post-owned-provider-refresh-without-tab-polling`.

Every new fixture pool is explicitly closed when its helper exits. No database
connection limits or original authority deadlines were increased. The actual
context preparation still charges its existing4MiB read work; the fixture backs
preparation plus one response window within8MiB/session and16MiB/allocation.

## Remaining composition

Public POST attachment/C14 pause integration, actual provider/SQL43 qualification,
operating-envelope sizing and a native browser transfer with its initiating tab
closed remain required. Initial30s grace is an implementation timeout, not a
measured startup guarantee. Process-loss reconciliation and privacy retirement
of orphan/consumer metadata also remain required. Normal joined cleanup cannot
substitute an exact independently established termination witness; 404, expiry,
retired enrollment and forced Pod deletion alone do not prove provider work
stopped. `PROCESS-TERMINATION.md` in the parent staging directory gives the narrow
witness/finalizer design; it is not an implemented recovery mechanism.
