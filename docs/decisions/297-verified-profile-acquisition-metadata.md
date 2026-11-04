# ADR-297: verified profile acquisition metadata in cases

Status: implemented; local/service qualification passed, installed qualification pending.

## Context

REQ-PRF-003/004 require truthful acquisition facts and case time correlation.
Current profile manifests already contain collector-observed start/completion,
but verification discards these facts and C16 exposes no acquisition window.
Reading raw manifests whenever a case opens would add regional read authority,
key operations and storage requests to an ordinary metadata view. SQL dispatch,
queue and storage-completion timestamps are not acquisition times; workload
pprof timestamps are not an independently trusted substitute.

## Decision

1. Return `artifact.ContextVerificationResult` with `NativeBytes` and an optional
   `Acquisition *artifact.AcquisitionWindow` from the existing verification port.
   Populate the window only for currently supported Go profiles, after complete
   frame/native/hash authentication, semantic checks and final deadline checks.
   Use the existing manifest start/completion already in hand. Return no timing
   on failure and perform no additional reads. Other evidence kinds retain their
   current result semantics.
2. The window describes HTTP acquisition: immediately before the endpoint GET
   through complete response-body consumption, before upload. It does not define
   a precise sample interval or the history covered by cumulative counters.
   Normalize this display metadata once to UTC microseconds before audit/storage,
   matching PostgreSQL precision. Keep sealed manifests/native bytes unchanged;
   retained display times may lose less than one microsecond of precision.
3. Add paired nullable acquisition timestamps to the existing verification row
   under migration134 and its existing encrypted immutable verification audit.
   Both are absent or both valid and ordered. New profile verifications persist
   their authenticated window; old records remain unknown on replay, without
   backfill, rewriting immutable receipts or re-auditing an old verdict. Retain
   current scope/copies/authority, retention/recovery and post-lock checks.
   New non-null timing must match the verified result on insertion/replay;
   historical null records retain their legacy unknown state. The existing trusted
   SQL recorder enforces new-profile timing; the publisher tolerates a returned
   historical null rather than adding a replay-provenance flag solely for display
   metadata. Progress/history
   audit reconstruction and compiled column grants must consume the same record.
4. Propagate the verified window and already accepted profile parameters through
   the existing joined catalog read and authorized C16 case projection. Add an
   optional closed `profile_acquisition` artifact value with requested type/mode,
   requested duration, forced GC, onTrigger lifecycle, paired nullable start/end,
   unknown clock uncertainty and unknown serving-process attribution. Unknown
   legacy timing stays null, never epoch zero or a substituted SQL/pprof time.
5. Render a collection timing table from that typed artifact metadata, including
   unknown legacy rows. Preserve the existing generic timeline contract; it
   requires a known timestamp and cannot faithfully represent an unknown window.
   Explain on-trigger collection and absence of pre-trigger recording. Do not
   claim a measured incident offset: the preparation anchor is not an original
   incident timestamp, and cross-source clock offset is unknown. Requested
   duration is a request, not observed sample duration. Do not infer a serving
   process or restart from Pod UID; only different Pod identity is known when
   the independently visible targets differ. Full process-instance correlation
   remains a separate required capability.

This adds display metadata, not collection/disclosure authority or a timing-based
permit. No raw read, new public operation, key resolver, worker or background
process is introduced. Profile grants and native downloads retain their current
contracts.

## Complexity and cost

1. Missing case timing is an observed required-workflow gap; current case timelines
   are empty and discard already verified facts.
2. The maintainer accepted profile provenance/correlation; no risk is reopened.
3. The change helps ordinary profile investigation and legacy unknown reporting.
4. Reuse the established verified NativeBytes/catalog pattern; a second raw reader
   has no demonstrated benefit for these two existing facts.
5. New privileges/credentials/listeners/watches:0; extend only existing verifier
   INSERT column access. Hub obtains no unwrap authority.
6. New runtime/fallback states:0; optional legacy metadata remains unknown.
7. New tuning configuration:0.
8. External dependencies: unchanged PostgreSQL and existing artifact verification.
9. Additional API/S3/KMS calls:0 per artifact/case. Two timestamp columns add16
   payload bytes per timed SQL row plus existing nullable/row overhead; audit JSON
   grows by a bounded timestamp pair. Validate existing backing envelopes rather
   than adding a new budget. Current case bounds remain unchanged.
10. Upgrade preserves old rows; rollback refuses retained non-null timing before
    restoring the previous verification guard. Disabling collection is unchanged.
11. Merely displaying queue/pprof timestamps would misstate the required facts;
    persisting the existing verified pair avoids per-case rereads and authority.

## Validation

Exercise complete-authentication success/failure, UTC microsecond normalization,
immutable audit/replay and legacy byte compatibility, compiled SQL roles,
upgrade/rollback refusal, already joined catalog/permission/retention reads,
closed browser/MCP parity and actual case UI decoding. Verify unknown/reversed/
partial windows, cumulative-history wording and process-attribution limits.
Use frozen-source real SQL/S3 and repository gates before fresh installed case
verification. No result, complete correlation, S-05 or full-spec exit is claimed.

Local qualification: integrated race/pre-push checks and built-console checks
passed. Three separate real SQL/S3 fixtures verify new timing, immutable/legacy
replay, catalog/progress/history-facts parity and migration134 round-trip/refusal.
Fresh Kubernetes/SQL/S3/OpenBao empty-schema installation and original product-Pod
activation also passed. Source hashes, actual exits and cleanup are recorded in
`test/results/profile-timing-services/`, `test/results/profile-timing-schema/`
and `test/results/profile-timing-local/`. The history fixture does not publish
history parameters; no complete history-list or installed-profile claim follows.
