# ADR-297: verified profile acquisition metadata in cases

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Status: implemented and merged; bounded installed CPU case timing qualified.

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

Focused races/fault tests verify complete authentication, semantic close, final
cancellation, UTC-microsecond normalization, immutable/legacy audit bytes,
cloning, closed browser/MCP parity and no additional verifier reads. Real SQL/S3
checks cover new/legacy metadata, catalog/progress/history-facts parity, role
columns and134→133→134/retained rollback refusal. The history fixture does not
publish history parameters or qualify history-list visibility. Fresh empty-schema
installation and original compiled activation Pod also pass. Reports are retained
under `test/results/profile-timing-local/`, `test/results/profile-timing-services/`
and `test/results/profile-timing-schema/`.

Final installed CPU10 policy workflow native41779461029 passed at c78b44b2
(Go539.234s), including exact ordinary-case/SQL timing, native download, all4,097
independently matched committed source hashes, unchanged source and clean
terminal cleanup. The921-byte original reopened locally with pprof. Reports are
in `test/results/profile-timing-native-41779461029/`. Fonts-loaded375px/320px
before/after comparison checks and the full browser gate pass after reusing the
existing table wrapping style; native41777263417 predates that UI fix.

The later owner socket-shutdown unit assertion fix changes no product build
input. Its explicit4,096-identical/one-test-file comparison retains the final
native evidence without rewriting the original4,097-matching source inventory.
Exact candidate08e6a2a3 CI41782145212 passed; PR156 merged normally to
59e5f14f79fd83da3400133d3520a396eb694689 with identical full tree read-back.

This qualifies bounded CPU HTTP acquisition metadata, not measured source-clock
offset, precise sample history or serving-process identity. Other/longer native
modes, broader correlation, S-05 and full-spec exits remain open.
