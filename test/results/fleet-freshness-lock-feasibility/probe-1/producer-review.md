# Producer and transition review (not implemented)

This note accompanies the view-lock probe. It reserves no schema/ADR number and
does not turn a successful lock probe into migration or startup qualification.
The actual current view has **nine** columns. The earlier proposal's ten-column
description was incorrect.

## Complete present writer inventory

Production source searches found these base-table producers, apart from generated
copies of the same queries and explicit fixture/admin writes:

| Producer | Present effect | Required separation |
| --- | --- | --- |
| SQL06 schema / SQL31 migration | blocked defaults; SQL31 forces stored suspension/recovery | new fields/table remain blocked; no positive backfill |
| `InsertBlockedFleetTrust` / `InitialInstallations.PrepareInitialInstallation` | creates blocked root with original source dates; conflict is no-op | retain blocked creation and original pristine/claim checks; creation alone never seeds usable authority |
| `FleetObservation.ObserveAdministration` / `ObserveFleetAdministration` | updates generation/digest, effective suspension and dates under view UPDATE | unchanged renewal takes base SHARE then observation UPDATE; semantic change takes base UPDATE then observation UPDATE |
| `FleetObservation.FenceAdministration` / `FenceFleetObservation` | sets suspension if failed original start is not older than accepted start | base UPDATE then observation UPDATE; compare newest accepted start plus transition watermark; repeated qualifying fence is an event even if already suspended |
| `InitialInstallations.ActivateInitialInstallation` | original pristine/witness/audit-qualified base activation plus activation-record update | retain exclusive initial table locks; explicit base transition and separately explicit original observation seed in that same transaction; replay remains read-only |

There is no implemented general restart/restore unfencer or issuer/source-root
replacement writer in the searched production code. Do not add one implicitly.
Future qualified recovery must obey the same base-first lock order and invalidate
the old observation. Initial activation still requires the independent claim and
audit; ordinary source freshness cannot approve it. The initial schema inventory,
pristine check and exact per-role grants must include the new table deliberately.
Tests that currently seed base dates need explicit synthetic observation seeding;
a migration trigger must not silently make those fixtures pass.

## Minimal state and enforcement candidate

Retain one base authority row and one observation row per installation. The
observation row carries the complete source/issuer/incarnation binding, semantic
version, original start and original deadline. Retain it when fenced: an invalid
binding still carries a monotonic accepted-observation watermark. Deleting it
would lose ordering information; an unexplained missing row for an activated
installation must fail closed, not restart ordering from zero. Base legacy dates
may remain for compatibility/pristine checks but never supply positive view dates.

Use a database-managed `semantic_version` and `semantic_changed_at` on the base.
The field-change set is issuer epoch, source UID/generation/digest, stored
suspension/recovery and both activation-incarnation fields. Installation ID is
immutable. Increment on every such change **and every accepted explicit fence**.
A trigger based only on DISTINCT semantic values misses repeated fences and is
insufficient. An unchanged observation must not touch either private field.

A concrete enforcement shape to review after feasibility is:

- Fixed SECURITY DEFINER producer functions owned by the migration owner, with
  qualified object names, fixed `pg_catalog,pg_temp` search path and no PUBLIC
  EXECUTE. Runtime writers get only exact EXECUTE plus existing lock/read grants;
  revoke old direct source/date UPDATE and INSERT rights. No new daemon or role
  hierarchy is necessary solely for these functions.
- A base BEFORE trigger initializes version/transition for blocked insertion,
  derives an increment for actual semantic change, rejects arbitrary private
  field writes, and accepts only a single-step explicit fence increment from the
  trusted function context. It never writes/renews the observation row. Runtime
  UPDATE(installation_id) used for locking cannot alter that immutable key.
- The source function has fixed unchanged and transition branches, not a caller
  `skip-current` / `allow-old-start` flag. Classify, take the appropriate base
  lock, then lock the observation; reclassify after waits and reject a raced branch
  if it would require upgrading base SHARE while holding observation UPDATE.
  No hidden new independent observation or irreversible-effect retry is added.
- Preserve overflow failure. Transition time must not move backward; the exact
  representation/clock rule still needs review alongside existing normalized UTC
  starts. A conservative strictly increasing microsecond floor is possible, but
  wall-clock ordering is not a substitute for an independently retained semantic
  version if the required clock model cannot establish observation ordering.

The trigger is defense against an omitted transition, not an observation producer.
The fixed functions are the only runtime route to the observation table. A
generic activation-field trigger that seeds positive dates is expressly excluded.
Database superuser administration remains outside runtime credential authority,
as with the existing schema; this is not a claim to fence a hostile DB owner.

## Two distinct monotonic checks

For an unchanged renewal, validate the original independent Administration at
actual DB time after **both** base and observation locks. Require exact current
source/issuer and activated process/database, unchanged stored semantic version,
original caller cutoff, and original source deadline. The source start cannot
precede the last semantic transition, even if the observer just read its new
version after waiting. Retain the existing accepted-start ordering and
equal-start/no-extension rule independently. A later observation does not grant
permission to widen an already captured consumer deadline.

A source-changing/resuming invocation legitimately starts before **its own**
transition. It must satisfy the *previous* transition floor and accepted watermark
under base UPDATE, then atomically write the new semantic tuple and its exact
original interval. The new trigger timestamp is not a reason to reject that same
explicitly authorized seed. Conversely, this exception must never apply to a
subsequent call using only the new version; otherwise a delayed pre-fence observer
can reopen a row. A qualifying fence always advances the floor, including when
suspension was already true. An older failed observation cannot fence a newer
accepted start; an unknown observation COMMIT is not acknowledged success.

Initial activation is a separate fixed path, already authorized by its independent
claim/witness/audit and current input checks. Its original Administration can
precede the blocked-root insertion/activation transition. Permit that seed only
inside the existing first-activation transaction; do not extend the ordinary
source function's exception or let activation replay refresh it. The base update,
observation seed and original `fleet_initial_activation.activated_at` transition
commit together or remain unknown together. Existing lost-COMMIT replay only
checks current state and cannot clear a later fence.

Precise open point before implementation: source `ObservedAt` comes from the
application while `semantic_changed_at` comes from the database. Existing code
already compares independent original starts with DB time, but a new version read
only after native work cannot itself prove that work began after the transition.
Review the existing clock assumptions explicitly; if insufficient, retain the
base semantic version *before* starting that independent native observation and
require it unchanged at admission. That changes producer ports/scheduling, not
consumer proof deadlines. Do not quietly treat a new post-wait version as proof
of when the native read began.

## Lock and deadline consequences

Unchanged positive renewal needs base SHARE, so it can coexist with effect SHARE.
It still waits behind semantic UPDATE, including queued restrictive writers. The
candidate CTE avoids implicitly locking observation rows from consumer view SHARE;
ordinary joins do not. FOR UPDATE consumers continue to exclude an observer's
base SHARE even if the CTE itself stays unlocked. The probe records this distinction.

Changing any semantic authority, activation or failure fence still waits for joined
effect holders. Base comes before observation, activation/owner heads and existing
purpose locks. Do not acquire observation and then request an exclusive base lock.
Existing role/advisory/spent-attempt rules, statement/lock timeouts and independent
native reads remain required. The first captured view row may become old during
an operation; preserve that row's original deadline and all final checks. Renewal
only helps a later operation select a later independently accepted interval.

Passing this probe cannot establish that original owner startup now fits. The
existing parent82/max87 S-request graph and initially aged owner/provider interval
still need actual unchanged-limits native qualification. No sleep, refill, new
limiter, raised QPS, reselected attempt or enlarged operation deadline is proposed.
