# First-installation activation

[ADR-098](../decisions/098-first-installation-activation.md) connects the
[one-use witness](installation-witness.md) to first activation of the
[database incarnation fence](../decisions/096-database-incarnation-fence.md).
It cannot restore an existing installation or recover SQL loss.

## Ports, state and roles

C-04 exposes `InitialInstallationPreparation`, `InitialInstallationActivation`
and the private `InitialInstaller` coordinator. C-08 exposes
`InitialInstallationWriter` and `InitialInstallationAcknowledgements`. C-21's
`postgres.InitialInstallations` supplies separately credentialed SQL facets;
`objectstore.InitialInstallationObjects` supplies encrypted write/read verification.
The minimized audit domain record contains the witness scope and immutable claim.

Migration 00032's `fleet_initial_activation` permits exactly one row. Its bounded
record is immutable to all runtime roles. Preparation can insert the attempt and
a blocked root; audit can acknowledge only the exact record; activation can write
only completion and the private fleet activation/observation fields. None owns
tables or has DDL, superuser, operational-row deletion or reset privileges.
Preparation's row-lock privilege is limited to the constrained singleton column.
SQL inventory/locks use the exact reviewed current permanent-table inventory in
`internal/adapters/postgres/initial_installation_tables.go`; each schema change
must update and qualify that inventory. No history is ignored because it is
expired, revoked, deleted or hidden by row security.

The temporary preparation/activation credentials also need SELECT and MAINTAIN
on the application tables to exclude concurrent writes during eligibility checks.
They must be isolated in protected installation and retired afterwards. The
separate audit role does not hold these maintenance or activation privileges.
Ordinary observers still cannot write activation fields.

Before this first activation, runtime configuration acceptance must not populate
operational tables. The supported installer must order those reconcilers after
activation. An optional matching blocked fleet observation is the sole exception.
Local-key installations also need a protected pre-activation audit capability;
using the ordinary recovery-dependent key configuration guard would create a
bootstrap cycle. The current native qualification uses dedicated OpenBao audit
credentials; it does not resolve that local-key installer composition.

## Runtime sequence

1. Read independently pinned protected witness and fleet administration. Reject
   suspension, unknown identity and stale observations.
2. Lock the exact table inventory under READ COMMITTED. Check the current schema,
   primary/database incarnation and eligible state. Persist or recover the same
   five-minute attempt; an already-consumed witness never creates a missing row.
3. Consume the exact native witness once. An uncertain write remains spent and
   is resolved only by exact independent readback.
4. Store an encrypted immutable attempt audit at its fixed installation/claim key.
   Read it back and verify purpose, plaintext record and ciphertext integrity;
   acknowledge the receipt with the audit credential. No SQL lock spans provider
   I/O. This record does not assert that activation completed.
5. Reread witness/source and preserve the original claim, source revision and
   installation plan. Repeat the table/eligible-state and database checks under
   locks, rechecking all original deadlines after waiting.
6. Atomically bind the initial fleet root to that database incarnation, enable it
   and record completion. A completed-attempt retry checks current effective trust
   and changes nothing. Later recovery blocks and suspensions remain intact.

Source changes, identity replacement, receipt mismatch, provider failures,
post-preparation operational state and missing or altered schema deny activation.
An expired consumed attempt requires recovery; changing endpoints or retrying
with a fresh UUID cannot grant another first installation. Native claim lifetime,
SQL lock waits and a thirty-second coordinator operation remain separately bounded.

## Qualification and next composition

`make initial-installation-integration` creates its own fresh PostgreSQL/S3/OpenBao
fixtures. It must not share a populated fixture with unrelated tests. Its
Kubernetes witness/source inputs are explicitly synthetic; the witness's actual
native admission/CAS tests remain separate evidence. TLS bridges protect the
adapter-facing connection but do not qualify a production backend TLS topology.
Provider and SQL tests do not prove protected installation, historical recovery
or a runnable Helm deployment. Exact test results are in
[implementation progress](../implementation-progress.md).

The targeted native run uses `ASSERVAT_INITIAL_INSTALLATION_NATIVE=1` with
`scripts/test-context-storage.py --run '^Test(InitialInstallationWithRealServices|InstallationWitnessWithRealKubernetes)$'`.
It additionally composes the actual protected witness and fleet source with
SQL/S3/OpenBao and verifies missing-source-protection refusal. Its API tokens,
plan and role provisioning remain test-owned, without a deployed installer Pod.

Next supply installation-owned plan/key/store/role provisioning and protected
installer execution, then qualify restart and restore using retained independent
checkpoints and old-primary fencing.
