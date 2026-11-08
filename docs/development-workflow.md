# Completing a feature efficiently

Maintainer-approved workflow, 2026-11-03. Apply this alongside
[validation](validation.md), with one active user workflow and one integration
candidate. Park unrelated feature branches; do not discard their checkpoints.

## Work and review

The integrator owns the candidate and the next observable user outcome. Assign
short tasks against that exact base: implementation with file ownership,
integration review, or a reproduction. Agents report the commit, actual test
exit and remaining gap. They do not independently run broad gates or dispatch
hosted suites. Freeze sources only after every writer has completed or explicitly
acknowledged the freeze; an interim passing test report does not end editing. Integrate completed changes promptly instead of building long
chains of dependent branches.

Before the first full CI push, finish the independent producer/consumer
review, including private and public result envelopes and charged refusal
ownership. Before the installed test, follow the feature through installer output, public
request, approval/admission, dispatch, storage credentials, publication, native
download, projection and cancellation. Check producer output against the real
consumer, including evidence types, data classes, client policies and resource
limits. Service fixtures must exercise the compiled process SQL grants;
administrator or ad hoc fixture roles can hide missing column and row-lock
permissions. Protected installation-root fixtures each need a fresh database. Use a small composed regression for each discovered mismatch; do not
build another test framework or duplicate the production workflow with mocks.

## Verification tiers

1. While editing: run the failing regression and affected tests. Use
   `make profile-preflight` for profiles or `make argument-preflight` for the
   finite syscall argument workflow. These run local
   race/component tests without Docker, collection, privileged access or a
   deployment; it does not establish installed qualification.
2. Once integrated: run `make pre-push` and the affected service fixtures.
   For profiles, `make profile-service-preflight` runs the real write-only
   producer/publication and funded summary ledger against owned SQL/S3 fixtures.
   Run the full Go gate once per final candidate, locally or in exact-commit CI;
   do not repeat unchanged package evidence merely because another agent also
   worked on the feature. For browser flows or installed-driver changes, run
   `make console-browser-check`: reuse the exact driver against compiled React,
   real metadata HTTP decoding and controlled local service facts before the
   costly installed run. Component tests that inject a controller do not cover
   that boundary. Required checks and their assertions remain intact.
3. Before costly installed dispatch, inspect the automated review and resolve
   concrete findings. For migration changes, compile the DDL and exercise empty upgrade/rollback
   in owned PostgreSQL early. sqlc generation does not compile deferred PL/pgSQL
   expressions; include representative expression execution. Run the existing
   upgrade fixture and the initial-schema bundle/history checks as well as the affected SQL fixture; ordinary migration success does not
   prove the installation path accepts the release. With sources frozen, run the
   selected installed workflow in a fresh owned environment. Record the exact commit, real exit, source inventory and cleanup.
   A failure returns to a focused reproduction and boundary review before another
   costly dispatch. No automatic full rerun after an unexplained failure.

Keep one current feature ledger in `docs/implementation-progress.md`: outcome,
candidate, checks, next blocker. Retain original reports and consequential ADRs;
avoid new checkpoint essays for routine fixes. Reuse evidence only when its
relevant sources and environment are unchanged, and state its scope.

## Required PR check events

Before treating a green `ci-ok` as satisfying the PR rule, read back its event,
head and conclusion, for example with
`gh run view RUN_ID --json event,headSha,conclusion`. GitHub evaluates required
workflow-job checks only from eligible events, including `pull_request` and
`push`; a successful `workflow_dispatch` on the same head does not fulfill the
PR ruleset. See [GitHub's required-check event documentation](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks#checks-from-some-workflow-jobs-are-not-evaluated).

If an incident leaves the PR without its eligible run, preserve the qualified
head and verify the missing event before spending another full matrix on manual
CI. Retrigger the existing PR once by closing and reopening it without a source
change, then verify the actual PR run. Record manual CI as code validation,
separately from required-check and merge readback. Native qualification uses
`workflow_dispatch` intentionally and remains unchanged. This changes no
workflow, ruleset, required check or gate.

PR160 demonstrates the distinction: manual CI41818290363 passed with
`workflow_dispatch`; required PR CI41821140504 passed with `pull_request` on the
same `80593f93` head. The normal merge `5b765322` has the identical complete tree,
so its native qualification remains applicable without another installed run.

## Retained debugging environments

The context harness already supports `--keep-on-failure`; use it for an owned
local fixture that does not start a privileged collector. For example:

```sh
python3 scripts/test-context-storage.py --run '^TestNamedComponent$' --keep-on-failure
# Inspect the exact owned cluster named in the emitted kept-resource manifest.
kind get kubeconfig --name <recorded-cluster> > /path/to/private/debug-kubeconfig
python3 scripts/test-context-storage.py --cleanup-kept /path/to/kept-manifest.json
```

Replace the illustrative test name with an actual selected test. Retention
keeps the original private fixture directory (mode 0700), including fixture
configuration and kubeconfig paths, alongside the recorded resources. The
manifest records `workDirectory`; cleanup removes it only after resource
cleanup succeeds. It preserves diagnostic state; it is not a supported resume of the Go test or a
new installation. Inspect logs and reproduce the failing boundary against the
retained resources only where the existing helper supports it. Do not bypass
immutable workload/image pins to make an update work. Record any debug edits;
final qualification always starts fresh and uses frozen sources.

Privileged collectors remain restricted to disposable VMs. Hosted runner state
cannot survive job teardown, and the existing 20-minute job limit stays in
force. Do not introduce a remote-access service, paid VM or persistent runner
merely to implement this debugging preference.

## Local installed loop

Installed focuses that start no node collector run on this workstation with
Docker and kind, in about 13 minutes instead of a hosted round trip:

```sh
cd web && npm ci --prefer-offline && cd ..   # once per fresh worktree
make installed-focus FOCUS=manual-logs       # ARGS=--keep-on-failure to retain a failure
```

This is the `continuation-<focus>` command from `scripts/ci-native.sh` with
`TMPDIR` on `~/.cache/asservat-build/tmp` (the harness needs 4 GiB of build
scratch; `/tmp` is a small zram disk). It owns two fresh kind clusters
(three for `clusters`) and needs about 10 GiB of free memory.

Local-capable focuses: `chain`, `journey`, `browser`, `restart`, `clusters`,
`upgrade`, `policy`, `alert`, `logresource`, `share`, `manual-logs`
(`LOCAL_FOCUSES` in the Makefile; the target rejects every other value). All
other focuses load eBPF collectors; the harness also refuses them without
`/etc/asservat-disposable-host`. Never create that file on a workstation.

Each run is a fresh installation: clusters, database and images are never
reused, because protected installation roots require clean state. The
development-only rerun below is the one explicit exception. The harness
records its phase end times in `phaseSeconds` of
`test/results/context-storage-environment.json` and prints them at the end;
the Go test's own lines with elapsed seconds are in
`test/results/context-storage-timing.log`. A warm local run (2026-11-07)
spent about 55 s in harness setup (previously about 100 s: Keycloak now
starts while the clusters are created, all clusters are created
concurrently, and the Go test package compiles meanwhile), 200 s in the
unified bootstrap runner
(produce 28 s, schema 84 s, prepare 38 s, retire 39 s), 215 s in the
installer continuation up to the focus, about 2 minutes in the
`manual-logs` focus and its cleanup, and 15 s removing fixtures. A measured
`make installed-focus FOCUS=manual-logs` on 2026-11-08 took 777 s wall
time: 100 s harness setup (images 31 s, services 23 s, concurrent clusters
36 s), 664 s Go test (unified runner 28/88/38/40 s, `manual-logs` 158 s) and
14 s cleanup, leaving no owned kind cluster, container or network.

## Several focuses per installation

`ASSERVAT_JOURNEY_FOCUS=a,b` runs compatible focuses in sequence after one
bootstrap, each as its own subtest
`installer-continuation/<focus>` with its own watchdog budget, result and
timing (`focusResults` in `context-storage-environment.json`). This is how
the `all` dispatch runs most installed suites: `scripts/ci-native.sh`
defines groups such as `continuation-journey+policy`, which replace their
members in `--list`; each member (`continuation-journey`) stays a
dispatchable suite for targeted reruns (`--names` lists both).
`make installed-focus` accepts one focus only.

Only focuses with the same bootstrap share an installation:
`installedFocusBootstrapSignature` (in
`test/integration/installed_multi_focus_test.go`) compares what the
bootstrap derives from the focus (fast fixture, clusters, collector,
approvals, console scopes, object partitions), and the Go test refuses a
list that differs, repeats a focus, includes `chain` or `clusters`, or puts
an order-sensitive focus in the wrong place (`installedLastFoci`,
`installedFirstFoci`). Additive fixture parts (Alertmanager,
metrics-server, the upgrade image, the hub-worker crash, the
evidence-owner role, collector ring disk and live values) are installed
when any listed focus needs them. Per-focus budgets add up (root records,
normal and resolution lanes, the workload's context reserve, identity
limits), so no focus runs on what an earlier one left. Processing is
initialized once. Between two focuses the teardown deactivates every
active policy over MCP, waits until every recording source has ended and
released its slot, deletes the AccessBindings the finished focus added and
waits until they leave the permission projection, waits until the shared
workload trigger budget holds what the next focus spends, and waits until
the workload is available. A later focus does not start after a failure.


## Fast focus re-run (development only)

To iterate on an authority, timing or wiring bug inside one focus, install
once and then rerun only the focus. This is never a qualification: reports
carry `"qualification": false`, the harness refuses these modes when `CI` or
`GITHUB_ACTIONS` is set, and `make installed-focus` without them stays a fresh
installation.

```sh
make installed-keep FOCUS=manual-logs   # fresh install + focus, then keep everything
make installed-rerun                    # rebuild, redeploy if changed, focus only
make installed-rerun                    # again, as often as needed
make installed-teardown                 # remove the kept run, verify nothing is left
```

`installed-rerun` and `installed-teardown` use the newest manifest in
`~/.cache/asservat-build/kept/`; pass `KEPT=<manifest>` to pick another.

- **Keep** runs the ordinary fresh `installed-focus` run with
  `--keep-installed`. Before the focus starts, the Go test writes the inputs
  the focus needs (installation, root and cluster IDs, public endpoint and
  root, regional target) to `installed-state.json` in the private fixture
  directory. Afterwards the harness keeps the clusters, fixture containers,
  images, networks and that directory, and records them in the kept manifest.
  Go-side fixture cleanup is skipped as with `--keep-on-failure`.
- **Rerun** (`--rerun-installed`) checks that every kept cluster and fixture
  container still exists, is labelled for that run and is running. It then
  rebuilds the hub binary, fixture proxy and console. If any of them differs
  from the deployed image, it builds a new labelled image, loads it into the
  hub cluster and moves the hub there through the product's own image change
  (`installer-upgrade`, ADR-227), at the next release revision. Then it runs
  only `TestInstalledFocusRerunWithKeptInstallation`. That test reopens the
  kept database, clusters and Keycloak realm and calls the same focus function
  as the full run. Cluster/fixture creation, the unified bootstrap runner, the
  installer continuation and the regional install are skipped. Its log and
  report are `test/results/installed-focus-rerun.log` and
  `installed-focus-rerun-environment.json` (`wallSeconds`, `phaseSeconds`,
  `imageChanged`).
- **Teardown** (`--cleanup-kept`) removes the run's clusters, containers,
  volumes, images (including every rerun image), networks and private
  directory after checking each belongs to that run. Then it lists every
  Docker container, volume, network and image labelled for the run and every
  kind cluster named for it; anything left fails the teardown. The evidence
  is in `test/results/kept-cleanup-<run>.json` (`leftovers`).

Limits:

- Only `manual-logs` is wired for reruns so far (`RERUN_FOCUSES` in the
  harness, `installedRerunFocus` in Go). Wiring another focus means making
  its run-once inputs (idempotency keys, synthetic source names, root-wide
  totals, operator capacity) per-run, as for `manual-logs`.
- Product state from earlier runs (cases, artifacts, spent query units,
  browser sessions) stays, so a rerun is not a clean first run. Query units
  are never refunded, so the keep run's synthetic operator settings fund four
  focus runs instead of one (`installedKeptRuns`): query units, the normal
  and resolution audit lanes, the regional context reserve, the pool's
  system object partition (four runs fit the fixture's 8 GiB system byte
  reserve) and the browser login, session and logout caps. The harness refuses a fourth rerun.
- A rerun gives its capture/download idempotency keys and synthetic
  ephemeral container a per-run suffix, skips processing initialization
  once an earlier run completed it (the product refuses a second one), and its root-wide logs
  query accounting check subtracts what was charged before the rerun
  started. In ordinary runs these adjustments are zero or absent.
- The image change moves hub-api, hub-worker, key service, publisher and
  federation, and with hub-api the console. The regional connector and the
  download/query worker Jobs keep the kept run's image; changes there need a
  fresh keep run.
- The keep run extends two synthetic fixture lifetimes from 30/60 minutes to
  three hours: the OpenBao token-reviewer token and the owner issuer root.
  Product settings are unchanged. The connector and worker fixture roots stay
  at two hours, so reruns are refused 90 minutes after the keep run started.
- Hub image changes are not yet reliable for `manual-logs`. In both measured
  image-change reruns the hub moved and settled, but the focus's
  single-attempt `preview_capture` right after the move was refused with
  `facts/storage/expired/readiness-tail` (an immediate second call
  succeeded). Use reruns to iterate on Go test code, which the rerun always
  recompiles; after hub product changes keep a fresh installation.
- Final qualification still starts fresh with frozen sources.

Measured on 2026-11-08: `installed-keep FOCUS=manual-logs` 669 s (setup
58 s, Go test 608 s, focus 155 s); `installed-rerun` without an image change
184 s (rebuild and hash 8 s, focus 175 s); image-change reruns 232 s and
133 s (image built and loaded in 21–23 s, then the failure above);
`installed-teardown` 52 s, after which no kind cluster, container, network
or image of the run was left.

## Prefer measured simplification

Fix the demonstrated bottleneck first. For example, sharing immutable compiled
manifest schemas removes repeated per-artifact allocation without a new upload
scheduler. Add scheduling, caching or infrastructure only when the existing
measurements show the simpler approach cannot deliver the required workflow.
