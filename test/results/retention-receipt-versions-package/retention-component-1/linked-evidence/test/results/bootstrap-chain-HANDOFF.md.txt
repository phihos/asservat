# ADR131 scratch child and full command-chain qualification source

Frozen nine-path isolated package. No live source edits or external fixtures were performed. The preceding 28-path command package is unchanged. Apply only after verifying every original hash in `manifest.json`; the five modified paths match the current live tree, including the parent's appended native-passive qualification paragraph. Four new paths must be absent. Unowned live provider-name validation, schemas, SQL50 and capability changes remain dependencies, not copied payloads.

Manifest SHA256: `d9721295605e4d8027b5ed53df227b9379240bfef1babd227ce671826fb75a55`.
Patch SHA256: `d5539e3dddf8fd9e316aa150f8a4855dc4aeea3b9a47d1ecdeb5c8b2c4a17cd8`.
Evidence manifest SHA256: `fc6cee592d5696d3982b4910b64fdaec3ef5111390268d075a2e99d518f48ae4`.

## Change and boundary

The product's fixed dedicated tmpfs mount is a scratch parent, not the private projection directory. Producer and retirement create/open its fixed `projection` child with exact current UID/0700, real-directory/tmpfs and confinement checks; foreign/shared/aliased children are denied without adoption or chmod. The existing private-file and exclusive-lock checks remain unchanged. Schema/preparation use child subPaths in the staged Restricted runner. No guard, credential privilege, authority duration, runtime enablement or SQL behavior changes.

The new exact selector owns a fresh empty SQL database and one Kubernetes cluster. The actual compiled `/asservat` binary executes producer → schema → preparation → retirement in one Restricted Pod, with real generated manager, actual original activation Pod and independent encrypted activation history checks. A fresh second runner has no SQL/DDL/provider input mounts and must repeat all four commands passively with unchanged original identities. The fixture never injects manager activation, completion flags or recovery authority. Its administrator account and upstream provider setup remain explicitly fixture-owned initial trust.

The adapter's metadata-only request trace and this compiled command's setup-file absence are different evidence scopes. This fixture adds no product tracing or expanded product RBAC. Current native `emptyDir`/fsGroup/subPath ordering and the full command chain are **not yet qualified**.

## Actual checks

All Go commands ran from `/home/phil/Projekte/asservat`, using `GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp` and the isolated overlay in this directory.

- Handle 29915: `go test -overlay <stage>/overlay.json ./internal/bootstrap ./test/integration -run '^$' -count=1` — exit 0, `evidence/compile-first.log`.
- Python selector regression: `python3 <stage>/changes/scripts/test-initial-bootstrap-selection.py` — exit 0, three tests, `evidence/selector-tests.log`. It mocks external execution and starts no fixture.
- Handle 87533: `go test -overlay <stage>/overlay-before.json ./internal/bootstrap -run '^TestInitialBootstrapScratchCreatesPrivateOwnedChild$' -count=1` — expected exit 1, `evidence/scratch-before.log`. The preserved former direct-volume composition returns the native shared parent; the unchanged private-root gate rejects it. This is a composition regression, not a claim that a previously nonexistent helper was run from live source.
- Handle 86266: `go test -race -overlay <stage>/overlay.json ./internal/bootstrap ./test/integration -run '^TestInitialBootstrap' -count=1` — exit 0; bootstrap 1.073s, integration 1.049s; `evidence/scratch-chain-race.log`. External tests skipped without their explicit environment.
- Final direct exec (no yielded session): `go vet -overlay <stage>/overlay.json ./internal/bootstrap ./test/integration` — exit 0; `evidence/vet.log`.

No build remains active. Code and harness sources were unchanged between the final race and vet. The architecture document was subsequently rebased solely to retain the parent's native-passive evidence paragraph. No staged full spec gate is claimed: parent's current canonical-reference correction is outside this package.

## Parent-owned native run

After integration and repository gates, with frozen sources and no parallel heavy jobs:

```sh
python3 scripts/test-context-storage.py --initial-bootstrap-chain
```

This dedicated mode selects only `^TestInitialBootstrapChainWithRealServices$`, sets its explicit opt-in, omits fixture migrations/runtime grants and requires the named test to pass. Do not substitute an ordinary custody run or a schema-already-migrated context fixture. The test's original overall context is eight minutes; each native runner has a 300-second active deadline and 310-second observation bound. Product authority intervals are unchanged.

Record actual terminal exit, selected test entries, original image/Pod evidence, unchanged source hashes and owned cleanup. The selector has not been executed here.

## Remaining work

Official Helm runner composition and complete native command qualification remain pending. The managed SQL/provider source Secret copies are retained by the current v2 guard; successful manager retirement does not mean those copies were removed. `MANAGED-COPY-CLOSURE.md` is a separate design proposal only. Parent prefers a fresh installer-selected v3 lifecycle with an independently proven permanent occupied-name policy, leaving v2 strict and unmodified. No permissive deletion path is included in this payload.
