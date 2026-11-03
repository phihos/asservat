# Completing a feature efficiently

Maintainer-approved workflow, 2026-11-03. Apply this alongside
[validation](validation.md), with one active user workflow and one integration
candidate. Park unrelated feature branches; do not discard their checkpoints.

## Work and review

The integrator owns the candidate and the next observable user outcome. Assign
short tasks against that exact base: implementation with file ownership,
integration review, or a reproduction. Agents report the commit, actual test
exit and remaining gap. They do not independently run broad gates or dispatch
hosted suites. Integrate completed changes promptly instead of building long
chains of dependent branches.

Before the installed test, follow the feature through installer output, public
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
   worked on the feature. Required checks and their assertions remain intact.
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

## Prefer measured simplification

Fix the demonstrated bottleneck first. For example, sharing immutable compiled
manifest schemas removes repeated per-artifact allocation without a new upload
scheduler. Add scheduling, caching or infrastructure only when the existing
measurements show the simpler approach cannot deliver the required workflow.
