# Installed journey current case-link regression

Base source: `62bfc0bbab4d7a5be1c79495039ecbe894cb8d4d`.
Scope: only the installed journey fixture and its in-process unit tests. The
product intentionally permits `get_capture` to return `Succeeded` while its
independently authorized optional case navigation link is unavailable. This is
a separately identified fixture defect; native49 reached `get_case` and failed
later at bucket-policy readback before download.

The corrected fixture continues fresh `get_capture` reads for the exact accepted
capture until a current case link is present. Terminal failure, wrong identity,
and cancellation fail immediately. Both existing passive waits share one
five-minute deadline fixed when the phase starts; the second wait does not renew
it. Fresh `get_case` still authorizes the selected case. Poll cadence, effect and
resolution budgets, and all downstream native-byte, revocation, retention and
deletion checks are unchanged.

## Measured RED and GREEN

The RED overlay extracts the existing immediate failure decision into the actual
called helper while adding regressions. The exact files executed before the fix
are preserved as `*.go.red.txt`, which do not participate in Go package discovery.

Both commands ran in the active worktree with:

```sh
TMPDIR=/home/phil/.cache/asservat-build/tmp
GOTMPDIR=/home/phil/.cache/asservat-build/tmp
GOMAXPROCS=2
GOFLAGS='-buildvcs=false -p=1'
```

Focused RED:

```sh
go test ./test/integration -run '^TestInstalledJourney(PublishedCaptureWaitsForCurrentCaseLink|CaseLinkRequiresFreshDecode|CaseLinkHonorsOriginalCancellation)$' -count=1 -v
```

Actual exit **1**, package time **0.016s**, command wall time **13.676850s**.
The published-before-link, repeated-missing-link, progressing-before-link, and
fresh-decode-with-omitted-link checks failed at the original immediate refusal.
Identity, unsuccessful terminal-state and cancellation cases passed.

Applied the separate GREEN correction, then `gofmt -w` on both owned files and
`git diff --check --` those files; both formatting/check commands exited **0**.

Focused GREEN:

```sh
go test -race ./test/integration -run '^TestInstalledJourney(PublishedCaptureWaitsForCurrentCaseLink|CaseLinkRequiresFreshDecode|CaseLinkHonorsOriginalCancellation)$' -count=1 -v
```

Actual exit **0**, package time **1.063s**, command wall time **19.784625s**.
Owned source hashes matched before and after both test commands. Exact argv,
environment overrides, timestamps, terminal exits, hashes and raw output are in
`red-command-result.json`, `red.log`, `green-race-command-result.json`, and
`green-race.log`; matching originals are in the recovered cache under
`case-link-red.*` and `case-link-green-race.*`.

The two stage patches retain the reviewed RED/GREEN application sequence.
`final.patch` includes final gofmt. No full integration race or external fixture
was run for this change; the parent will qualify the combined case-link and
bucket-policy candidate separately. Sources are frozen at the recorded GREEN
hashes. Independent final review found no blockers; see `independent-review.md`.
