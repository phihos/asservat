# native61 (merged proof reuse + download diagnostics) — failed at approved-only denial

Capture preview/request/resolution, regional collection, verification and
publication passed. Hub self-proof calls fell sharply versus native60 (provider
22 vs 1,840; credentials 48 vs 1,326; context-start 180 vs 1,929).
The test's deliberate approved-inspection-only `prepare_artifact_download`
received HTTP 503 instead of a denial envelope: the presentation layer returned
`identity.ErrDenied` for a missing `evidence:download` scope. Fixed to return the
ordinary audited denial reply; regression
`TestDownloadWithoutDownloadScopeIsAnAuditedDenialReply`.
