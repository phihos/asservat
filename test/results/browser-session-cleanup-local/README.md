# Browser-session cleanup local evidence

Actual compiled-role/SQL evidence; no installed worker or identity-provider cleanup qualification.

On signed `f8c4a86a85eaf8cd0b543f3edff3cde788b00680`, the owned runner selects
`^TestBrowserSessionCleanupWithRealServices$` and passes with harness/Go exit 0
(Go 4.698 s, 2 selected RUN/PASS). All 4,303 input hashes match that exact Git source
and unchanged current bytes; cleanup failures are empty and no owned containers
remain. The first pass removes exactly 256 rows per table (768 total) in19.902282ms,
then the next pass removes the remainder. This timing uses small synthetic
opaque credential records, not maximum-size credentials or a sustained ceiling.

The test uses the actual compiled browser-settings role and production SQL
adapter. It checks stale/suspended settings, expired/retired-epoch state,
abandoned versus active refresh claims, unchanged live credentials/root and
unexpired 25-hour logout receipts, another root's state, an old bound cleaner's
refusal, actual credential/provider-identity ACL denials, outage-safe logout,
and caller cancellation while the root is locked. It does not execute the
installed worker scheduler or decrypt real provider credentials. Root/source
administration and credential contents are synthetic. Existing authentication,
refresh and provider qualification remain separate evidence.

Two failed campaigns remain failures: `52a154b0` exits 1/3.571 s during fixture
UUID/text setup before cleanup; `34987c3b` exits 1/3.647 s after the existing
uncached candidate subquery deletes299 sessions instead of at most 256. Both
preserve4,303 exact source hashes, unchanged inputs and complete cleanup.
The latter is a real existing SQL bound bug. An isolated pinned-PostgreSQL probe
reproduces LIMIT/LockRows 304 rescans and304→5 sessions; materialized candidates
execute that selection once and leave48 (exactly 256 deletions). Isolated probe
timing 47.640/14.918 ms is separate from the final role fixture's 19.902282 ms.
Probe command streams, SQL inputs and cleanup records are retained.

Commands run in this isolated worktree, using TMPDIR/GOTMPDIR at
`/home/phil/.cache/asservat-build/tmp` and GOFLAGS=`-buildvcs=false -p=2`:

- `/home/phil/.cache/asservat-build/spec-venv/bin/python scripts/test-custody.py --fleet --run '^TestBrowserSessionCleanupWithRealServices$' --result-name browser-session-cleanup-f8c4a86a`
- Full affected races: `go test -race ./internal/bootstrap ./internal/adapters/postgres ./internal/application/identity -count=1` passes115.541/6.368/1.058s before the later SQL-query correction. Unchanged runtime/identity sources retain that scope; it is not relabeled as one final-source full run.
- After the query correction, full PostgreSQL races pass 6.383 s and SQL generation matches all 68 files. Targeted vet, formatting, SQL/spec/architecture/design checks pass as separately recorded.

The existing worker/pool gains no service, role, connection, watch, API request
or configuration. Housekeeping uses its existing loop, one startup pass then
eligibility each 60 s, with a 1 s operation deadline plus existing rollback join.
Physical deletion can lag during backlog/outage/worker downtime; row deletion
does not erase backups or WAL. No hard cleanup SLA or installed claim follows.

Every manifest entry records original and compressed hashes/sizes. Gzip uses
mtime 0 and an empty embedded filename; every payload was decompressed and
compared byte-for-byte. No binary or native evidence payload is archived.
