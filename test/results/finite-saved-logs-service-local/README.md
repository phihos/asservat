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

The corrected scalar run on signed `8aaa4162` advances through admission,
start, actual process-bound multipart writing and encrypted publication, then
fails C-03 read-only authority. Go exits1 in7.904s, harness1, provider0,
sourceUnchangedDuringTest=true and cleanup[]. All4,300 inputs independently
match Git. The concrete PostgreSQL42703 refers to nonexistent `l.version` on
the routing-only context_case_locator. Current reader/group/key-helper SQL must
join the acknowledged context_verification.copies_digest instead. These results
do not establish a successful query or later correction.
