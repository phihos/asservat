# SQL52 storage row-lock correction

Three frozen paths against current integrated52 plus the already applied chronology fix. Manifest SHA256:8f1456cef612e4889e21fc84b1d3225884a30dd517737a3b4623de6498fd2d52. Base and payload hashes are in manifest.json; changes.patch is additive.

Measured before state: parent capture52-native-after-time terminal1,1333 unchanged source hashes, cleanup[]. PostgreSQL log reports permission denied on context_storage_binding at ShareContextStorage SELECT ... FOR SHARE. The new admission role had SELECT but omitted the column UPDATE privilege already present for legacy capture_runtime/context_control_config_runtime. That is the measured Changed failure; no timestamp or policy change is needed.

Change: add only UPDATE(source_uid), matching those existing lock grants. No table-wide UPDATE, allocation/revision/digest/freshness write, INSERT or DELETE grant. The source_uid column itself is not described as trigger-immutable; this is the existing narrow lock-permission profile, not a claim that PostgreSQL has a dedicated lock privilege.

Production error correction: pgx.ErrNoRows at the exact storage binding read remains ErrChanged. Other driver/cancellation errors flow to existing captureError and become Unavailable, rather than claiming the user's reviewed inputs changed. No retry, identity or deadline behavior changes.

Three new actual-SQL cases: exact FOR SHARE succeeds with only the column grant and seven disallowed mutations return42501; fixture-admin temporarily revokes only the column grant and SELECT-only admission must return Unavailable/zero charges; actual missing unadmitted binding still returns Changed/zero charges. Restoration of the original role grant is deferred and checked. No synthetic query failure replaces the actual database privilege boundary.

Checks actually run: initial grant-only integration compile73365 terminal0; final two-package adapter/integration compile35321 terminal0 (no tests selected), logs retained. No native run independently performed; parent must run existing ^TestContextAdmissionWithRealServices$/^capture-intent-private-pair$ selector. New cases introduce no intentional waits. Prior frozen52 package remains unchanged; parent original failing logs remain authoritative before evidence.
