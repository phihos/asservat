# Installed PostgreSQL connection allowance

## Failure evidence

Installed journey runs 37 and 38 both tested
`179c376f752285a035de1ac8e4d939beb32cb6bc`, failed before the regional workload
reached `ready_at`, and ended with unchanged sources and no cleanup failures.
Their PostgreSQL logs each contain three SQLSTATE 53300 errors: ordinary
connections were refused because the remaining slots were reserved for
superusers. The fixture still selected `max_connections=48`, with 45 ordinary
slots. Run 38 refused worker-configuration audit at 10:46:14 UTC, and the
owner's resolution audit acknowledgement/journal at 10:48:54 and 10:49:12 UTC.
Run 37 refused the same worker-configuration purpose and two refresh purposes.

This is evidence of capacity exhaustion, not evidence of a pool leak. The
retained logs did not enable disconnection events and cannot reconstruct a
simultaneous role inventory. A logged authenticated/authorized connection may
still be followed by the capacity refusal. Lifetime connection counts are not
concurrent counts. The hub governor deliberately closes cold-purpose sockets
after release; repeated logins alone do not establish a leak.

The worker's last exit 137 is not an OOM diagnosis. This fixture deliberately
stops that container through the owned node's `crictl stop` to verify retained
reconciliation after restart. The retained kubelet tail covers cleanup, not the
earlier termination. It supplies no evidence for raising a memory limit.

The precise cause of the regional workload timeout remains unresolved. The
worker logged three successful guarded candidate reads followed by the same
deduplicated `compose/permission-scope (not-allocated)` outcome. That outcome
does not name the candidate: it may describe earlier infrastructure workloads.
At failure the regional Allow had a live assignment, matching stream sequence
and acknowledged audit. Regional discovery shares a serial round-robin loop
with local reads taking about 4.4 seconds, while regional reads take about 2.2
seconds with a two-second pace. No evidence identifies the requested workload
as the refused candidate. No wait, selector, permission or freshness bound is
changed on that inference.

## Source inventory and correction

Every non-hub purpose owns one `MaxConns=1` pool. The hub's identity and public
purposes share its existing 32-connection governor, with 18 dedicated hot slots
and cold connections closed after release.

| Process | One process, ADR-204 | One process, ADR-205 | Retained processes in the selected plan |
| --- | ---: | ---: | ---: |
| Hub | 32 | 32 | 1 |
| Hub worker | 16 | 19 | 2 |
| Federation | 6 | 6 | 2 |
| Publisher | 6 | 6 | 2 |
| Key service | 4 | 4 | 2 |

The worker's original 16 purposes are three configuration, two capacity, two
permission, four retention, two worker-configuration and three capture-cleanup
purposes. ADR-205 adds three context-deletion purposes. Even one process of each
kind allows 64/67 physical connections before verifier and maintenance headroom,
above the fixture's 45 ordinary slots. These are source-derived upper bounds,
not observed concurrent usage.

The runtime-only inventory plus one verifier and four ordinary maintenance
slots was 101 under ADR-204 and 107 under ADR-205. Review found that this omitted
the installer pools retained while the runtime starts. Those connections cannot
be charged to PostgreSQL's superuser reserve: its admission threshold uses the
number of free connections, so an administrator connected first can prevent a
later ordinary login. See the [PostgreSQL 18 connection settings](https://www.postgresql.org/docs/18/runtime-config-connection.html).

The one admitted continuation has this additional inventory. Every listed pool
has `MaxConns=1`; limits on runtime pools and the hub governor are unchanged.

| Pool | Construction and lifetime | Simultaneous allowance |
| --- | --- | ---: |
| Administrator runtime bridge | `OpenInstallerContinuation` opens `NewInitialRuntimeBridgeSQL`; `InstallerContinuation.Close` joins closure | 1 |
| Administrator public role producer | `PublicRoles` opens `NewPublicRuntimeSQLRoles`; retained until continuation closure | 1 |
| Administrator owner role producer | `Owner` opens `NewOwnerIdentityOperationSQL`, wrapping one `NewOwnerIdentitySQLRoles` pool; closes when `Owner` returns | 1 |
| Administrator acceptance reader | `DownloadAccepted` and `RetentionBaseline` each open a one-connection pool and close before returning; these calls are serial inside `Owner` | 1 |
| Ordinary accepted owner source | `acceptedOwnerSource` opens the scoped configuration-source pool; `Owner` closes it only after its remaining steps return | 1 |

The construction and close points are in
[`installer_continue.go`](../../internal/bootstrap/installer_continue.go) and
[`installer_downloads.go`](../../internal/bootstrap/installer_downloads.go).
The bridge and role-producer constructors fix their one-connection limits in
[`initial_runtime_bridge.go`](../../internal/adapters/postgres/initial_runtime_bridge.go),
[`public_runtime_roles.go`](../../internal/adapters/postgres/public_runtime_roles.go),
[`owner_identity_roles.go`](../../internal/adapters/postgres/owner_identity_roles.go)
and [`configuration_runtime_roles.go`](../../internal/adapters/postgres/configuration_runtime_roles.go).
`WorkerLaunch` closes its configuration-role producer before `Owner` starts,
so that pool does not add to the five-pool peak. The role producers' temporary
`pgx.ConnectConfig` login checks close before each returns and remain covered
by the separate serialized verifier slot. They do not replace the accepted
owner-source allowance, which overlaps them.

The passive history reader previously inherited up to four configured
connections and remained open until continuation closure despite having no
further use. `initialBootstrapHistoryBounded` now limits this continuation's
reader to one; `observeInstallerActivation` closes it after the sole activation
observation, including failures, before the administrator bridge opens. Its
opening phase uses the same one-slot allowance as the later serialized login
checks. Other bootstrap history readers retain their selected limits. No
history or administrator observation substitutes for current bridge authority.

The selected full plan is therefore 102 retained runtime connections, five
installer connections, one verifier and four maintenance slots: **112 ordinary
slots**, or 115 total with three superuser slots and no other reserved slots.
Maintenance still means one DDL, two backup/restore and one operator/monitoring
connection. This is a conservative configured maximum for the selected graph,
not an observed simultaneous count or permission for concurrent continuations.

The promoted continuation checks that plan against actual PostgreSQL settings
under its verified activation/incarnation bridge before runtime provisioning.
Both superuser and other reserved slots are excluded. Insufficient capacity
reports fixed counts and an operator remedy; the product changes no server
setting, SQL role or runtime pool/governor limit.

Only the installed continuation fixture obtains its server allowance from a
Go helper using that same plan. It adds its independent one-connection test
observer to ordinary capacity, then three superuser slots: **116 total**. This
remains sufficient regardless of whether the observer connected before the
runtime. The fixture's short retention reader runs only after the continuation
Pod has finished and reuses the now-free verifier allowance. Other bootstrap
modes keep their original observer pool behavior because some deliberately
hold a lock while reading through another connection. Ordinary component
fixtures remain at 48 server slots. The report records the complete compiled
plan and selected settings; installed PostgreSQL logs include disconnects
without statements or parameters.

The capacity worker also emits cursor position and step/candidate counts at
most once per thirty seconds, using fixed locality labels and kind ordinals.
No workload names, UIDs, credentials or evidence are included. This will
distinguish unfinished traversal from later enrollment failures without
changing the discovery work itself.

## Verification boundary

Local focused race tests cover actual-setting arithmetic, reserved and declared
allocation refusal, cancellation after the settings read, sanitized operator
messages, existing bridge checks and the connection governor. The capacity
package race tests pass. The Python fixture regression failed on the old
profile interface and passes with explicit installed sizing; unchanged component
selection is asserted. Regressions for the installer allowance and fixture arithmetic fail against the
earlier 107/110 plan. The activation-reader regression covers closure before
runtime work on accepted, refused and failed observations. Native qualification
of the corrected 112-slot product plan and 116-slot fixture remains required;
a run using the earlier 110-slot profile cannot qualify this source change.
