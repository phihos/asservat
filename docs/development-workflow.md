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
reused, because protected installation roots require clean state. The harness
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

## Prefer measured simplification

Fix the demonstrated bottleneck first. For example, sharing immutable compiled
manifest schemas removes repeated per-artifact allocation without a new upload
scheduler. Add scheduling, caching or infrastructure only when the existing
measurements show the simpler approach cannot deliver the required workflow.
