# ADR-092 — Independent source admission probes in the private hub namespace

Date: 2026-10-11. Status: selected under continuing implementation authorization. Requirements: REQ-DEP-005, REQ-FED-001, REQ-DB-005; part of TASK-02/07/11 and S-01/S-02.

## Observed problem

The ADR-091 native context run passed the configuration-worker case but failed the existing combined owner case: the namespace-wide admission denial masked the independently expected owner-configuration denial on its first dry-run probe. Both guards rejected the update, but that result did not establish the required source guard's enforcement. Repeating a request until the desired denial happens would not make source observation reliable. The failed suite and unchanged-source/cleanup report are retained as `config-reconcile-first-context-storage.*` under test/results.

## Decision

Keep both protections and their exact independent enforcement proofs. Add a finite, installation-owned `configurationProbes` list to the private owner deployment projection and workload administration plan. Each entry names one ConfigMap and one ServiceAccount in that same pinned private namespace. Permit at most eight distinct pairs; reject unknown fields, wildcards, invalid names, missing/null lists in the deployment projection and duplicates. An explicit empty list means no exceptions. This is installer input, not an end-user permission or an additional approval step.

For each pair, the namespace policy permits only core ConfigMap UPDATE, no subresource, with `request.dryRun` explicitly true and the exact ServiceAccount username and object name. Ordinary RBAC remains required. Source admission remains independently pinned and must return its own expected denial. Missing or ineffective source protection still fails that reader. The workload probe remains a separate Deployment update and must receive the workload policy's exact denial.

Real updates, creates, deletes, other actors, other ConfigMaps, Secrets, workload mutation, token minting and exec remain subject to the unchanged namespace policy. In particular, removing source protection cannot turn this narrow probe exception into permission to persist an update. Do not exempt all dry-runs, ConfigMaps, probe groups or a service account's other requests. The installation must continue to give normal probes only get/update on their named source, not the broader attack rights used by integration tests.

[Kubernetes dry-run semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run) guarantee no persistence and reject incompatible side-effecting admission. This distinction supports the exception; a failed RBAC request or unrelated admission denial still does not qualify source protection.

Include the exact probe list in the workload protection digest, expected policy specification and mounted deployment validation. Copy caller-owned lists before retaining the plan. Changes require policy requalification and owner process replacement, like other protected deployment input. The private pre-release v1 contract gains a required field; there is no existing production installation or public API migration to preserve.

## Evidence and remaining work

Unit tests cover closed input, finite/unique exact scopes and caller-memory isolation. The native combined test repeatedly verifies the source denial with both policies active. After stopping the nested owner runtime it deliberately removes source protection, proves only the named dry-run can succeed without changing resourceVersion, and verifies the namespace policy still denies persistent updates, other actors/objects, Secrets and create/delete. The fixture then recreates an unaccepted binding for the enclosing missing-protection test; it never substitutes that new UID for the original accepted pin.

Actual terminal gate and integration outcomes belong in [implementation progress](../implementation-progress.md). This fixes policy composition; it does not qualify clean installation history, restore detection, native in-Pod runtime or public evidence collection.
