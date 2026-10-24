# ADR-217 — One SQL login for API execution facets

Date: 2026-10-23. Status: selected under the maintainer's instruction to implement
the specification and simplify when sensible; implementation in progress,
qualification pending.
Requirements: REQ-DB-003/004, SC-DB-003/004, TASK-03/11, S-02.

## Decision

Replace the same hub process's `api-execution-read`, `api-execution-prepare` and
`api-execution-record` credentials with one `api-execution` login and one cold
pool. Keep `APIExecutionReader`, `APIExecutionPreparer`, `APIExecutionRecorder`
and the stored-completion port; compose them with one `APIContextExecutions`
instance. Their SQL methods, current permission/retention/recovery/storage
checks, original deadlines, one-use preparation and immutable replay are unchanged.

The grant plan is the exact union of the three previous plans: 46 entries,
comprising one schema USAGE, 20 SELECT entries over 18 relations (including
three existing column-only SELECTs on `fleet_trust`), 10 INSERT entries and
15 column UPDATE entries. The writes remain limited to execution/preparation,
writer-completion records and the existing lock columns. No capture admission,
audit acknowledgement, evidence-copy mutation, publication, key unwrap,
deletion, schema creation, role membership or administrative privilege is added.
No `SET ROLE` or SQL schema migration is introduced.

Use new permanent ordinal 94; ordinals 21–23 are retired and never reused.
The three credentials, claim/receipt sequences, projection files and pool
objects become one. Total public-runtime credentials fall from 81 to 79;
hub public entries fall from 46 to 44, or from 52 to 50 including the unchanged
six owner credentials. The new pool uses `MinConns=0`, `MaxConns=3`, preserving
the former group's aggregate concurrency. Each retained hub process still has
the same global 32-connection governor. The installation role limit is 13:
four retained hub processes times three, plus one serialized installer verifier.

The pool no longer serializes each facet independently: up to three reads,
preparations or records can use the group's three slots. Existing SQL locks,
unique rows and exact replay checks remain responsible for concurrent effects.
The adapter's helpers use their transaction's query handle; protected topology
observation occurs before pool/transaction acquisition. No selected facet calls
another selected pool while holding its connection.

Capture audit, connector and capacity role-identity pins remain separate.
Publisher, key service, acquisition and deletion duties keep their process and
credential boundaries. Download-plan and worker-configuration pools remain
separate because the former can call the latter while holding a transaction.

## Risk and development compatibility

A query-injection or miscomposition flaw in one execution facet could now use
the other two facets' privileges. A full hub-process compromise already exposes
all three original credentials. This explicit tradeoff removes duplicated
provisioning and pool lifecycles without changing a user-facing capability or
weakening current SQL effect checks. No reduction in runtime handshakes, latency,
CPU or memory is claimed without measurement.

Use one fresh-install development layout, following ADR-215. The existing exact
layout digest rejects retained earlier state before effects, with the existing
unsupported-development-layout diagnostic. Do not adopt, rewrite, remove or
silently migrate that state. Recreating a disposable installation is explicit;
a supported release-upgrade contract remains future qualification. No permanent
old/new layout framework is added. Historical test reports retain their old counts.

## Complexity assessment

| Question | Answer |
| --- | --- |
| 1. Frequency and harm | Every installed hub provisions and loads three same-process credential lifecycles; failure incidence and aggregate latency are not measured. |
| 2. Accepted risk | The maintainer authorized sensible implementation simplification; this credential split is an engineering mechanism, not an independent user capability. |
| 3. Typical use | All installed API-context capture starts use these facets. |
| 4. Comparable projects | Not investigated for this bounded grouping; no external precedent claim is made. |
| 5. Exposure | Exact existing union; one compromised facet gains its sibling privileges, while process-level authority is unchanged. No new network or provider access. |
| 6. New states | Zero new durable, degraded or fallback states; two credential/pool lifecycles removed. |
| 7. Tuning | Zero new settings. Fixed pool maximum three, process maximum 32. |
| 8. Dependencies | Existing PostgreSQL/pgx/governor only; no new service. |
| 9. Aggregate cost | Two fewer passwords, claims, receipts, projection files and pools per installation/hub composition; no added API/watch loop. Runtime savings unmeasured. |
| 10. Upgrade/rollback | Earlier development layout is refused without mutation; no supported retained-layout migration is claimed. Fresh installation and supported-layout replay require qualification. |
| 11. Smaller alternative | Keeping three credentials preserves narrower injection scope but retains all duplicated lifecycle work; typed ports alone preserve code-level separation with one login. |

## Qualification

First record a genuine failing contract test for the new inventory and exact
historical grant union. Verify removed purposes cannot be provisioned and
unrelated compartments/ordinals remain unchanged. Run the real SQL adapter's
existing preparation, expiry, revocation-after-lock, immutable result and
publication cases using the compiled shared credential and one governed pool.
Require denial of excluded mutations, three held connections, bounded/cancelled
fourth acquisition, release/reacquisition and joined cleanup. The concurrent
preparation race must still return exactly one fresh preparation.

Fresh role provisioning, immutable manifest/projection replay and installed
capture/publication on the final candidate remain required integration evidence.
Presence of tests or passing component tests does not qualify the installed
journey. Actual commands, exits and remaining gaps belong in the result archive
and implementation progress. This ADR partially supersedes ADR-177's one-login-
per-purpose rule only for these execution facets.
