# Finite logs: first real-service failure

The scalar logs lifecycle on signed `4d5d450f` fails at capture admission,
before query admission. The actual Go test exits1 in6.730s; the harness exits1,
provider log collection exits0, sourceUnchangedDuringTest is true and cleanup
failures are empty. All4,299 reported inputs independently match signed Git.

The legacy record-only fixture cannot fund the64MiB logs final-plus-temporary
obligation. Separate focused regressions identify missing large-log writer
binding and a two-query installed-helper count mismatch; their local originals
are preserved in the companion local archive. This failed campaign establishes
neither a successful logs lifecycle nor the later streaming correction.

Original reports are deterministic gzip files with exact compressed/original
byte counts and SHA256 in archive-manifest.json. The SQL/S3/OpenBao providers
are real; bootstrap/current authority, source bytes, worker/process/issuer and
transport joins remain synthetic where declared by the fixture.
