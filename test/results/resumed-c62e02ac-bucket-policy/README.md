# Installed deletion policy read-back correction

Native49 failed at the strict original bucket-policy check before any deletion
fault was written. Its archived provider response represents the single
`DenyEvidenceWrite.Action` as the scalar `"s3:PutObject"`; the fixture builder
emitted a singleton array. The other seven-statement policy fields matched.

The focused regression embeds that exact synthetic provider response. Before
the correction, its full-policy comparison fails (exit 1, 0.015 seconds), while
the scalar/array strictness and existing fault-scope/unknown-restoration controls
pass. The correction emits the provider's scalar only for that fixed action.
Generic policy equality, fault construction and restoration remain unchanged.

The shared installed/small-provider qualifier now performs one exact bounded
GET after its existing PUT, under the original context and without a retry.
All existing cleaner permission positives and negatives remain required.

Focused race checks pass (exit 0, 1.068 seconds). One complete in-process
integration-package race run passes (exit 0, 6.262 seconds), including the
concurrent candidate's frozen authorized case-link correction. External fixture
variables were absent; these commands do not qualify live S3 or installed
lifecycle behavior. Parent will run the exact owned S3 selection separately.

Each phase has its exact command, raw output, observed exit and before/after
hashes for all 2,582 Go/module sources. Each comparison is unchanged. Source
snapshots use `.txt`; `source.patch` and `result.json` identify the final candidate.
No fixture credential, authorization, deadline or retry limit changed.

Independent read-only review found no blockers. It confirmed the snapshot matches
native49, the exact other policy fields and fault arm/restore remain unchanged,
and the new GET retains the original context and both callers' single-attempt
client configuration. Live provider and installed lifecycle qualification remain
pending; no extra tests or external operations were performed by the reviewer.
