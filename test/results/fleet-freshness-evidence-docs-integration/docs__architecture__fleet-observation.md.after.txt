# Protected fleet trust observation

C-04/C-21 implements current configuration observation under REQ-FED-001 and preserves the independent RecoveryBlocked requirement in REQ-DB-005. `TrustObserver` reads the pinned protected fleet settings and sends a finite projection to SQL. It cannot authorize restoration or rotate the issuer epoch.

An absent SQL root is inserted with database-default suspension and recovery blocking. The observer role cannot insert or update either an unblocked recovery state or a replacement epoch. Successful observation preserves the original at-most-five-second source freshness; database latency cannot stamp an expired source fresh. Source UID and issuer epoch must match; revision generation may advance but cannot regress or change digest at the same generation. Initial insertion, reads, row locks and updates all retain expiry checks.

Read/validation failure fences older observations by setting suspension. The failure carries the original read-start time so a delayed failure cannot overwrite a successful observation started later. The SQL fence advances the observation timestamp and expires it immediately, so an older success cannot reopen authority after that fence. Database unavailability leaves the previous finite expiry in force. Current source observation alone never clears recovery, even after process restart or a missing SQL row. A separate qualified recovery protocol still has to reconcile revocation/deletion checkpoints and uncertain spend before activation.

`test/results/fleet-observation-integration-check.log` records a real PostgreSQL run with exit 0. Tests cover absent-root and restart blocking, exact deadlines, monotonic revisions, stale success/failure races, expiry behind a row lock and actual SQL role denial of recovery clearing, epoch replacement or enrollment activation. The fleet environment report records unchanged tested sources and complete cleanup. Tests deliberately use a separate synthetic administrator when modeling an already recovered root; this is not an implemented recovery producer.

The original observer added no migration version. [ADR-096](../decisions/096-database-incarnation-fence.md) now adds migration 00031's effective-trust view: all authority readers and row locks check the separately accepted PostgreSQL process/database identity. Observer writes remain on the stored projection and cannot change activation. An old enabled flag, followed by a fresh source observation, cannot activate an unaccepted database incarnation. Independent initial/restore activation remains required.

[ADR-091](configuration-reconciliation.md) supplies protected fleet reading and scheduled hub-worker composition; ADR-094/095 qualify its native Pod and ordinary deletion. Installer provisioning and independent recovery promotion remain pending.

Fleet observation and failure timestamps are normalized to PostgreSQL microseconds. An equal stored observation time cannot extend the deadline, advance revision or undo suspension; a replay after an equal-time fence must remain unavailable.

[ADR-155](../decisions/155-unchanged-fleet-persistence-contention.md) defines one narrow persistence-failure distinction. An actual aborted LockFleetTrust55P03 on an independently observed unchanged positive source may retain the previous row without adding suspension only after exact before/after row, database-incarnation and database-time checks. The error stays unavailable, scheduling notices are invalidated, and the previous original expiry never moves. This is a classification of failed persistence, not a current-source proof or success. Source failures, changes, suspension/recovery, expiry and uncertain outcomes retain fencing. [Component checks](../../test/results/fleet-persistence-contention-package/component-1/result.json) pass 119 top-level / 605 named race cases, and [focused native qualification](../../test/results/fleet-persistence-contention-package/native-1/result.json) passes all ten actual SQL cases with unchanged sources and complete cleanup. The earlier diagnostic and full-bootstrap failure remain preserved; broad fleet regression and the original installed owner transition are still pending. [Integration metadata](../../test/results/fleet-persistence-contention-integration.json) binds the source and evidence packages.

## Version-bound positive observations

[ADR-161](../decisions/161-fleet-observation-separation.md) supersedes the original
single-row persistence described above. Migration 00059 retains semantic authority
in `fleet_trust` and stores positive freshness in `fleet_observation`. All existing
consumers still use the nine-column `fleet_current_trust` view and its authority
locks. An explicitly materialized observation query prevents those outer locks
from blocking unchanged positive renewal; restrictive changes still serialize
against retained effects.

`ReadAdministrationBasis` precedes protected source reading in the original
five-second budget. Positive persistence binds its original installation, semantic
version and database incarnation. Every source/issuer/recovery/suspension change,
and every accepted repeated fence, advances the version. Missing or mismatched
positive records expose blocked authority and finite expired dates. The observer
cannot seed an activated record, repair a missing one or approve recovery.

Only qualified first activation seeds the positive row, within its existing
pristine inventory/audit transaction. Completed retries never refresh it. Migration
rejects surviving legacy writer/hook grants and unsafe defaults; existing roots
are fenced without observation backfill. An upgrade/recovery coordinator must
supply separately qualified activation before service resumes.

An unchanged observer holds base SHARE and updates only the positive row. Fixed
table locks precede row locks so initial activation cannot deadlock through the
opposite order. ADR-155's narrow exception now comes only from the producer's exact
authority-row lock abort, followed by rollback and independent original
row/version/incarnation checks. No successful notice is emitted. A failed valid
source's ordering includes its own original native start; newer semantic roots
and newer observations remain protected against delayed failure fencing.

The [actual SQL59 qualification](../../test/results/fleet-freshness-native-1/result.json)
passes all 31 named cases, including scoped producer/activation roles, concurrent
renewal and restrictive locks, original basis/deadline behavior and migration ACL
closure. The [second component gate](../../test/results/fleet-freshness-component-2/result.json)
passes 265 top-level race tests and SQL/schema/canonical checks; three old fixture
basis omissions from the preserved first failure are corrected. Compilation and
full vet also pass. Synthetic protected source facts remain explicit.

The [second full initial-installation run](../../test/results/fleet-freshness-initial-installation-2/result.json)
passes all 87 named cases after correcting two pre-SQL59 fixture expectations;
the original failed run is retained. The
[full fleet run](../../test/results/fleet-freshness-fleet-1/result.json) also passes
all 176 named tests. The
[database recovery run](../../test/results/fleet-freshness-database-recovery-1/result.json)
passes all three actual initial/restarted/restored phases with verified incarnation
changes and complete source/archive/cleanup evidence. Installed owner run 11 still fails its
final native projection check. The split does not establish complete startup,
public investigation or installation-wide connection admission. Remaining results
and the separate aggregate SQL budget gap belong in the
[progress record](../implementation-progress.md); public/Helm runtime stays disabled.
