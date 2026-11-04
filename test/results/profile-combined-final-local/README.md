# Shared final profile candidate: local checks

`make pre-push profile-preflight spec-check architecture-check design-check`
completed with exit0 at4bc2982f, using TMPDIR/GOTMPDIR in
/home/phil/.cache/asservat-build/tmp, GOFLAGS=-buildvcs=false -p=2 and the existing
spec-venv/bin plus cache/bin PATH. It passed441 console tests,5.749s affected
fixture races and specification/architecture/design checks. This source combines
the timing fix and the seven prepared trace/heap commits; unchanged product and
Go-package evidence remains attributable to this source.

The later two-file test-only heap-driver correction f1d182e8 (integrated b6c17323)
checks rendered rows, bytes and unknown duration immediately after summary success,
before a separate native download can validly outlast that view. Missing rows at
close require the actual expired UI state; exact query/native counts stay fixed.
Its real built React/GoTLS synthetic regression fails before the correction
(exit1/12.039s) and passes both heap cases plus comparison (exit0/24.071s) afterward.
The fixture gives the summary3s from actual result handling and delays native
transfer4s. This changes no product lifetime or authorization. File hashes match
the integrated source. Exact commands, known setup failures and source stages
are retained in the handoff. Native qualification and final CI remain separate.

All original payloads use deterministic gzip and byte-exact readback. No SQL,
Kubernetes-installed, all-maxima or complete S-05 claim follows from these checks.

Final review strengthened the driver by requiring cleared rows and the exact expired
status whenever the original returned expiry has elapsed, even if a stale table
is still visible. The final focused built React/GoTLS check passed24.037s (exit0);
the source-file SHA and exact command are in the manifest. Independent final
readback found no blockers. Go architecture/specification/architecture/design
gates also exited0. These small final changes add no product behavior or query.
