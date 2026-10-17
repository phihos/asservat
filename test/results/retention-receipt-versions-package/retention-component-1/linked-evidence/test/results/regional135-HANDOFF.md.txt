# ADR135 frozen handoff

Frozen payload: `changes/`, 45 paths (38 Go), including the generated SQL query and both native fixture files. Only two existing paths change: `internal/domain/configuration/owner_administration.go` and `internal/adapters/kubernetes/owner_workload_guard.go`; both exact original files are in `bases/`. All other payload paths must be absent before integration. No SQL migration, schema-head/inventory/model change, dependency/library change, public enablement or live edit was made.

- Manifest SHA256: `2a686130fc06b3a9646c52afca2d76d3ddc79186b0d7239997d0ca35d7995bba`.
- Conservative dependency manifest SHA256: `fbd8e7e95a0ba477995ddaa78eacb0fdece93e349b9895e5ca546bb2c3e16071` (1,305 current Go/module/SQL/harness/catalog source hashes).
- `sql-generation-dependencies.json` records the exact existing SQL inputs used by sqlc v1.31.1; every hash was rechecked against live at freeze. The only generated delta is `internal/adapters/postgres/custodydb/context_start_owners.sql.go`.
- `payload.patch` is an optional additive patch; `manifest.json` with `base_sha256`/`payload_sha256` is the integration authority. No changes to this package after freeze.
- Parent owns decisions index/catalog/progress integration. Existing component roots already cover the new transport package. No shared index is included.

## Concrete change

The hub can attach one still-live accepted request to a connector-originated standby HTTP/2 stream and sign a purpose-separated exact API-context reference. Regional execution obtains current human observations interactively from the original live request, never persisted groups or a forwarded public token. The regional wrapper checks the reference against existing accepted SQL/process/capability ports and calls the existing ADR134 runner; no new key preparation is permitted by historical or uncertain execution preparation. A finite result never claims catalog publication or evidence delivery.

The stream owns EOF detection and joined cancellation through blocked identity/runner work, uses Go's standard TLS1.3/HTTP2 machinery, and retains original setup/work/trust/peer bounds. Passive standby lasts at most its original 30 seconds; effect observations remain at most five seconds. Per-cluster reserved standby and capture capacity is checked against whole-process maxima (64/16). Owner conversations are independently supervised; an ended connection cannot carry old work into a new standby. Hello accounting is symmetric. There is no address/callback from a capture caller, durable dispatch queue or generic RPC framework.

The concrete connector API reader checks the actual Deployment/ReplicaSet/Pod, current Pod-bound TokenReview and SSR, owned connector CSR/leaf, separate immutable API settings and exact input metadata pins. Its independent API epoch cannot follow a changed connector process. The new optional owner-guard branch admits only required exact CapacityReservation main CREATE and status UPDATE accounts; independently pinned StartAdmission remains mandatory. Omitted optional capability preserves legacy guard behavior/bytes.

The defaulted Deployment template is pinned in full. Only explicitly qualified controller hash/node placement and Kubernetes default scalar aliases are normalized; security fields, sidecars, mounts and projected-token shape remain exact. Secret metadata GET uses PartialObjectMetadata, which is not an authorization restriction: the protected installer must approve the entire dedicated Secret object using `dedicatedToAPI`. Actual named GET is restricted to those approved role-owned objects. File selection/subPath does not establish whole-object ownership; normal selected-file syntax is accepted only with the separate whole-object approval.

## Verification completed

All build sessions are terminal; no build or external fixture remains running from this agent. Every Go command used `GOMAXPROCS=2 GOFLAGS=-p=2` and a dedicated build TMPDIR. Decisive commands ran against the sparse Go overlay; `-vet=off` separates compilation/races from the known absent-directory vet limitation, not a passing vet claim.

| Handle | Check | Actual result / preserved log |
| --- | --- | --- |
| 99535 | Before-fix shorter peer proof regression | Exit 1 as expected; `logs/overlap-before.log` rejects valid overlapping original intervals. Corrected verifier takes the minimum without extending authority. |
| 64977 | Before-fix maximum legal 16-input settings | Exit 1 as expected at old 8 KiB; `logs/settings-bound-before.log`. New private settings cap is 16 KiB; existing operation limits unchanged. |
| 94689 | Actual loopback TLS/H2 plus JOSE/contracts races | Exit 0; `logs/http2-race-first.log`. Synthetic accepted registry/routes/API process remain explicit. |
| 28713 | Standalone new contextstart race binary | Exit 0, all 12 top-level tests; `logs/stream-race-second.log`, compiled by `logs/stream-compile-second.log`. Direct stage execution avoids absent live package-directory chdir only. |
| 12381 | Transport/settings/guard selected races | Exit 0; `logs/transport-settings-race.log`. |
| 29580 | Bootstrap/Postgres compile | Exit 0; `logs/owner-discovery-compile.log`. |
| 10176 | Native integration source compile | Exit 0; `logs/native-reader-compile.log`. |
| 18438 | Final affected races plus latest fixture compile | Exit 0; `logs/final-affected-race.log`. Eight packages; integration native case skipped without its owned environment. |
| 31251 | Existing-package vet with new package dependency | Exit 1 only because vet cannot chdir to the absent live `internal/transport/contextstart` directory; `logs/final-existing-package-vet.log`. Integrated real vet remains required. |
| 40046 | Spec gate with existing spec venv | Exit 0: 89 schemas, 49 tools, 173 examples, 176 requirements/scenarios, 9,482 assertions; `logs/final-spec-venv.log`. |
| 20252 | Architecture static gate | Exit 0: 12 apps, 24 components, 14 interfaces, 1,204 positive/120 rejected cases; `logs/final-architecture-check.log`. |

The final affected command was:

```sh
go test -vet=off -race -overlay=STAGE/overlay.json \
  -run 'TestAPIContext|TestConnectorAPI|TestOwnerAPIContext|TestConnectorProcessObservation|TestContextStartActualHTTP2' \
  -count=1 -timeout=90s \
  ./internal/contracts ./internal/adapters/jose ./internal/adapters/kubernetes \
  ./internal/adapters/mtls ./internal/application/execution ./internal/bootstrap \
  ./internal/adapters/postgres ./test/integration
```

The spec/architecture gates ran the unchanged repository scripts through a sparse staged source tree and `/home/phil/.cache/asservat-build/spec-venv/bin/python`. The initial system-Python missing-dependency failure remains in `logs/final-spec-check.log`. Earlier compile/vet/chdir and intermediate malformed test-edit logs are retained; they are not passing results. All final source is the hash-frozen payload; no further edit occurred after the final gates.

## Immediate integrated qualification

Run actual integrated vet/races and SQL regeneration/check after copying all payloads. In particular, run the complete new `internal/transport/contextstart` package at its real path. Regeneration must add only the new query file; no migration/head/model replacement is expected.

Exact native selector:

```text
^TestConnectorAPIProcessWithRealKubernetes$
```

Use the owned `scripts/test-context-storage.py --run` path with its normal compiled WorkerImage and source/cleanup accounting; no new environment variable or harness mutation is required. This native test has been compiled, **not run**. The fixture creates an actual guarded Deployment and observes the API-defaulted Pod/ReplicaSet, real TokenReview/SSR, input pins, whole-object named Secret RBAC/foreign-name denial, and actual CRD main/status transitions through the production reader/preparer. Its accepted source, certificate registry/CA and preparation grant are explicitly synthetic; the process runs on the test host. No deployed regional command or actual SQL connector enrollment is claimed.

The fixture logs only bounded static API operation-class counts and phase elapsed/original remaining time. If five-second composition fails, inspect those readings rather than whole-test duration. Do not increase authority deadlines or silently bypass current checks. The full frame-by-frame peer/process composition may perform more API work than this reader fixture and still needs separate measurement.

## Remaining required work / next package

1. Qualify the concrete reader/start path and correct actual defaulting/RBAC/timing defects from evidence, preserving original deadlines.
2. Qualify real SQL candidate discovery and a complete retained signed exchange connected to SQL52 accepted intent, actual regional collection/storage, independent verification/publication and native retrieval, including cancellation/unknown outcomes. The loopback H2 test does not provide real installed authority.
3. Provision a dedicated hub sign-only work key, regional verify-only trust, exact protected API profile/input ownership and named RBAC, independent API start admission, and the actual regional command/loader. The current OwnerDeployment projection does not yet emit this optional API capability; no chart/runtime enablement is added here.
4. Integrate the still-live bridge with explicit fresh-current same-key continuation. Historical accepted replay remains passive; a lost start reply must not imply failed admission or permit a new unqualified key/effect.

The first installed public context investigation remains disabled until these producers and the combined path are implemented and qualified. No worker/collector-key root is introduced into the hub by this package.
