# ADR136 / SQL53 — first approved-context native content

Staged only. Parent owns integration, repository gates and every external fixture.
No public listener/collection enablement, deployed identity claim, large-file native
qualification or completed backend/window lifecycle claim is included.

## Scope and contracts

This package connects actual current C03/SQL authority, the existing dispatcher and
request-owned enrollment, the original paid regional preparation/result, native h2
exchange and HTTP sink. The first-context preparation and Observe/response adapters
are purpose-specific, paired by the concrete bootstrap constructor. Generic paid
re-preparation/native response behavior remains unchanged.

The only new outward behavior is the implementation of the existing authenticated
native content GET and its fixed OAuth metadata URL. GET cannot dispatch, prepare
metadata or refresh credentials; actual regional content read/unwrap remains the
worker's existing authorized operation. A short HTTP-only normal audit preflight
finishes before conditional metadata or response admission. Response/window pairs
continue to own byte outcomes. Stop restricts SQL first, cancels the same runtime's
local exact-session/principal transfers, and joins within the original Stop bound.

The allocation reader uses the unique existing exact-target allocation (LIMIT 2
before backing checks), not another configuration framework. Immutable constructor
limits and the earliest absolute accepted backing end cap the original session.
Sixteen immutable metadata entries prevent routine status polls from spending native
credits; every hit still checks current authority/SQL. Unknown owners remain
unavailable, not actionable Ready. First-context eight-transition backing supports
prepare2 + Observe2 + content2 + retirement1; no refill or expiry-based closure.

## Integration instructions — shared files are explicit

1. Verify each existing base hash before applying `files/`; new paths must be absent.
   Shared implementation deltas are operation.go, connector_operation.go,
   operation_mac.go, download.go, download_response.go, native_exchange.go,
   context_download_control.go, download_response_transfer.go, download_stop.go,
   download_dispatch.go and download_jobs.go. Preserve all SQL50 processing,
   SQL51 retirement, SQL52 capture and ADR134/135 branches.
2. Add migration `00053_native_content_audit.sql`. It replaces only the two closed
   SQL classifiers to add `download_artifact_content` / `native-content-input/v1`.
   There are **no new permanent tables**: pristine inventory remains **91**.
   Parent updates `internal/adapters/postgres/custody.go` currentSchemaVersion to53.
   The existing embedded migration glob must include53; run both actual schema
   bundle/expectation tests after that update. Do not leave binary52 with SQL53.
3. Regenerate with pinned sqlc v1.31.1 using the combined tree. The only new generated
   file is `internal/adapters/postgres/custodydb/context_download_attachment.sql.go`.
   It is supplied under `generated/` for comparison, not blind replacement of shared
   output. Every other generated file currently equals live, including ADR135's
   `context_start_owners.sql.go`; preserve that new query and binding.
4. No shared runtime-roles.sql payload is supplied. The owned native helper creates
   its explicit synthetic role/grant additions: worker role SELECT on native
   backing/owner/response/key-binding/enrollment/certificate; download runtime SELECT
   on native backing/owner/worker; purpose-fixed `native_plan_runtime` reads goose,
   current trust and allocation/control/native/Stop backing, with only
   UPDATE(installation_id) on fleet_current_trust for its existing share-lock idiom.
   The actual fixture checks mutation denial. Installed least-privilege provisioning
   is still required; these synthetic grants are not its producer.
5. Review/manual-merge the three shared canonical/spec files:
   `docs/interfaces/browser-openapi.yaml`, `specs/artifact-downloads.md`, `specs/mcp.md`.
   Parent adds ADR136/architecture indexes/catalog/flow references and current progress
   evidence. No public MCP tool or response schema was added. New docs describe the
   unique accepted-allocation reader; the superseded config-source proposal is gone.
6. Parent ADR138 public endpoint factory/routes compile against immutable
   dependency-http-v1. This final package retains its public handler signature and
   constants. The current concrete bootstrap constructor additionally requires the
   Stop coordinator and wires its Active hook to the returned runtime. No mux or
   public bootstrap file is owned by this package.

## Verification and limits

- Absolute plan deadline regression failed before with a two-second delayed lookup;
  fixed selection passed. Logs: plan-deadline-before.log / plan-deadline-after.log.
- Final isolated SQL regeneration exit0; only the new query binding differs from live.
- Six complete affected package race suites exit0: evidence1.663s, appaudit1.136s,
  domainaudit1.010s, browser4.813s, presentation8.648s, postgres1.282s.
- Nine affected package overlay vet exit0. Integration/bootstrap compile exit0;
  external tests were intentionally not executed by that compile selection.
- One initial Kubernetes regex matched no test. That is preserved and is **not**
  qualification. Exact TestWorkerStartupWaitExcludesKnownExecutionAndTermination and all15
  subcases subsequently passed under race (1.042s), pending-exact-final.log.
- `check-final.sh` contains the exact isolated commands. Sources were stable through
  handle8517; the final stage does not copy dependencies/caches or change live files.
- Integrated make go-check/go-architecture-check/sql-check/spec-check/architecture-check
  and actual SQL53/HTTPS qualification remain parent-owned and pending.

## Native selectors and provenance

Use `TestContextAdmissionWithRealServices`, not TestCustodyWithRealServices:

- `download-worker-native-preparation-race`: two concurrent first admissions, one
  winner; discard its response then retry and verify one batch, one charge, zero
  key effects from admission alone.
- `download-worker-native-control-races`: real distinct SQL replicas, both Observe/
  response orderings, no loser charge, expired unjoined owner remains exclusive,
  held native row crossing its original deadline, cold cache during content,
  simultaneous admission and positive exact no-I/O owner closure.
- `download-worker-native-content`: real SQL/S3/A-KEY, regional result, two h2 hops,
  actual runtime, browser live reader and authenticated HTTPS GET. Requires forty
  warm polls without transitions, conditional304 with no response/key reservation,
  exact native bytes/hash and SQL Completed, exactly three distinct Joined worker
  conversations, preparation3 + content3 used key slots, six transitions within
  the original per-worker eight. The read-only plan role denies writes, and an
  additional exact-target unbacked allocation must cause ambiguity denial.
- Preserve and rerun existing `download-worker-native-exchange` strict baseline.

Job/Pod/issuer/browser session/serving admission and protected installation/backing
qualification inputs remain explicitly synthetic in this fixture. This is actual
SQL/S3/key/h2/HTTPS composition, not deployed Pod/SSO/provider acceptance or the whole
installed journey. Preparation currently invokes the real runtime continuation
method directly; it does not pretend to qualify the public prepare POST/ADR138 mux.
The three new selectors have compiled but have not run externally.

## Next work and open boundaries

Integrate and run the bounded native cases before the installed endpoint journey.
The native operation/response/window identity, regional key slots, cancellation and
joined acknowledgements must remain exact. No live secret, caller token or raw key
is placed in SQL/audit/cache. Immutable cache contents are not fresh worker-aliveness
proof; hub/regional process loss can leave explicit unavailable/unknown recovery.

Protected provisioning of transfer/control/native/Stop and normal operation audit
backing, measured backend/window cleanup/history coverage, v2 credentials and
connector/hub native identities/listeners, download bearer resource/issuer policy,
public HTTPS/session configuration and the installed journey remain release gates.
The <=4096-byte context conversation is not qualified 1TiB transport, slow-reader
throughput, adaptive chunking or deployed RSS evidence. The generic ledger's full
size/accounting contract is preserved.
