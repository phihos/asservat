# ADR-288 — Native profile downloads across bounded response windows

Date: 2026-11-03. Status: implementation in progress; installed qualification pending.
Requirements: REQ-DLD-001–004, REQ-PRF-001–003.

## Observed problem

The installed download path caps every artifact at one 8 MiB storage frame.
The accepted pprof and Go trace types declare 64 MiB and 128 MiB maxima, and the
builtin CPU profile defaults to 16 MiB. A regression rejects metadata at 8 MiB
plus one byte; a separate regression rejects two independently acknowledged
64 MiB windows. Raising a single size constant cannot satisfy the contract.

## Implementation

Keep the encrypted storage frame at 8 MiB and native delivery chunk at 1 MiB.
Use the existing 64 MiB accounting windows, original authority, prepaid key
bindings and audit protocol. Profiles retain their registered native maxima;
recorder acquisition and its current download ceiling stay separately bounded.
Each remote conversation serves one window. Its finite per-direction frame cap
is 128, covering 64 data chunks plus fixed protocol frames, without increasing
any frame payload or permitting arbitrary RPCs.

Charge at most nine storage frames and two index pages (including fixed cipher
overheads) for a profile window, covering an unaligned requested range. This is
a conservative reservation, not measured overhead. Each window opens its own
exact keys once. The hub transfer's incremental native hash spans the complete
whole-file response; the last chunk cannot succeed with a mismatched checksum.
The regional reader still authenticates every storage frame before delivery.

Retry eligibility checks every acknowledged window in order, exact owner and
generation, unique window identity, contiguous offsets, emitted lengths and
successful outcomes. Only the last window reports the response's final check.
The largest enabled profile requires two windows; SQL reads a third sentinel
row to detect excess history. A closed owner alone never certifies completion.
Unknown outcomes, cancellation and unjoined workers retain their charges.

The installed per-session ceiling covers a 128 MiB trace and one separately
admitted retry: 256 MiB output, four content windows plus the existing 4 MiB
metadata read. The coordinator moves its existing published-source read before
planning and reuses the same observation for preparation; it adds no SQL/API
request, credential or permission. The plan narrows each profile session to twice
its accepted registration limit and the corresponding one/two-window read budget.
Non-profile sessions retain their existing at-most 16 MiB/24 MiB output/read caps.
No source deadline is renewed through reservation. An older insufficient protected
installation ceiling refuses profile preparation rather than silently increasing.

Response admission reserves claim/close transitions for every selected window
plus final independent retirement. Metadata observation preserves that room based
on the bounded remaining session output. Allocation planning checks both window
key rows and all corresponding audit records. New profile capacity qualification
must fund four content windows, four key rows, twelve content unwraps and fifteen
owner transitions (prepare, two observations, four windows, retirement). Existing
immutable allocation funding is not enlarged or reinterpreted by these changes.

## Complexity gate

1. Observed problem: both regression tests fail; every profile above 8 MiB is
   unavailable for its required native download, including the 16 MiB default.
2. Accepted risk: native downloads of every gathered artifact are required;
   the old ceiling is an implementation staging choice.
3. Typical path: yes, the builtin profile default crosses the old ceiling.
4. Precedent: reuse the existing generic framed reader and 64 MiB SQL transfer
   windows; no new protocol family or third-party streaming mechanism.
5. Added privileges/credentials/destinations: zero; reuse the existing source read.
6. Added persistent failure states: zero; existing uncertain response retirement.
7. Added operator tuning: zero.
8. External dependencies: existing object storage, SQL and key service only.
9. Aggregate bounds: at most two windows per 128 MiB profile, one 1 MiB delivery
   chunk at a time plus bounded storage decoding; nine frames/two pages reserved
   per window. No whole-profile buffer. Actual peak memory and end-to-end runtime
   remain measurements to obtain, not inferred from these constants.
10. Rollback: profile admission must remain disabled until qualification; active
    work uses immutable original bounds and existing retirement. Mixed-version
    handling and rollback require validation before enabling profiles.
11. Smaller alternative: reducing profile output to 8 MiB contradicts the selected
    profile defaults/maxima; native download cannot be replaced by a query view.

## Required evidence

Domain and SQL completion tests are necessary but insufficient. Test real encrypted
multi-frame objects, unaligned resumed ranges, all native bytes/hashes, key opening
per window, window transitions, end-to-end cancellation/revocation and conservative
failure spend. Exercise the native transport beyond its former frame ceiling.
Qualify 64 MiB pprof and 128 MiB trace maxima with the composed acquisition/SQL/
publication/download path and measured resources. Open downloaded profiles in the
compatible local Go tool. Verify actual terminal exit, source hashes and cleanup.
No capability or full workflow is claimed qualified by this decision record.

## Component evidence (2026-11-03)

Synthetic two-hop TLS tests transfer a full 64 MiB pprof-shaped byte stream with
resume/conditional semantics and a 128 MiB trace-shaped stream across two distinct
64 MiB conversations, with exact bytes and full-file hashes. These bytes test
transport, not format semantics. The 128 MiB test opens the preparation keys once
and each window's keys once. A separate real PostgreSQL/S3 test stores a valid
12,502,769-byte pprof via multipart encrypted streaming, independently verifies
and reads it, and successfully opens it with `go tool pprof -symbolize=none`.
`test/results/profile-streaming-s3-sql-3-environment.json` records exit 0,
unchanged tested source and no cleanup failures. The first two retained attempts
caught fixture time precision and missing pprof PeriodType respectively; neither
was reported as passed. This is component evidence with synthetic key/authority
inputs, not installed acquisition, raw approval or download qualification.

The two-window control regression also reproduced admission with only three
remaining transitions; it now requires five (two claim/close pairs plus retirement).
The source/plan regressions retain original expiry through reservation and keep
small artifacts from consuming profile-sized reservations.
