# Native response version boundary qualification

Date: 2026-10-27. Requirements: REQ-DLD-002/003/004.
Status: actual worker subprocess/transport checks pass; the first shared SQL
pair attempt failed before claim. Its fixture TLS correction and operational
rollout remain unqualified. This is test-only qualification work.

The old production tree is canonical PR100 main
`eed8594020645fe6d10f8c6565e69a6235c7507d`; the new tree is PR101
`fa69b01948edf9d7baf1f00453e1482a224fd4ea`. Neither production tree is patched.
The same finite [helper](../../test/fixtures/native-version-helper/main.go) is
compiled separately in each module/worktree by
[the build script](../../scripts/build-native-version-helpers.py). It invokes
that tree's actual NativeOwners and RunWorkerConversation implementations.
There is no copied old predicate, import alias, module replacement, compatibility
negotiation or product fallback. The repository's existing profiler replacement
under vendor remains unchanged; builds use pinned modules with `-mod=readonly`
and GOPROXY disabled, rather than treating that directory as go-mod-vendor.

The build checks tracked and untracked production-source drift, records the
pinned production tree, fixture SHA-256, compiler version and executable SHA-256,
and bounds each build to 120s. A private output directory is create-only. Helpers
read at most 256KiB from stdin and emit at most the parent's 4KiB output bound;
no credential is in argv or diagnostic logs. Outputs contain fixed stages/classes,
operation hashes, sequence/cutoff and numeric protocol counters. The parent checks
both executable hashes and the exact fixture-source hash before use, and joins
each at-most 20s subprocess. These are fixture provenance controls, not a new
product authorization system.

## Actual local worker results

`TestNativeActualVersionWorkerWire` runs the actual new native hub handler and
frame gates over loopback h2/mTLS with actual old/new worker executables. Human,
operation/SQL authority, initial metadata and stored source facts are explicitly
synthetic. The deterministic 2MiB body uses the PCAPNG native type to exercise a
framed window; it is not a collected or parsed PCAPNG artifact.

- Old worker/new hub and new worker/new hub each return two exact 1MiB chunks
  under one original three-second operation, acknowledge both chunks and
  positively join. Preparation and framed response each open the synthetic
  reader once; no response restart is used.
- The old worker refuses the new twenty-second command in its actual worker
  parser, before any reader call, data frame or success acknowledgement. The
  same new-worker/new-hub twenty-second command succeeds as a fast control;
  that control does not claim renewal or delivery beyond five seconds.
- After the first acknowledged chunk of an old short conversation, waiting
  beyond its original end makes the new consumer refuse the next read and ACK.
  The old conversation ends Uncertain. A second frame can already have been
  transmitted before the cutoff; that is not a successful post-cutoff disclosure
  or acknowledgement.

The parent race run also covers six invalid/oversized/wrong-role helper input
cases across both executables. The combined command exits 0 in 4.508s; helpers
are actual separately built ordinary binaries, not race-instrumented binaries.
Initial wire fixture attempts failed at compilation (typed integer fields), then
at Open because the synthetic admission had not bound the worker's blank routing
reference to the exact fixed operation. The corrected fixture performs that
explicit synthetic binding before actual HubOperation.Attach; logs 1/2 remain
negative evidence. Corrected normal and parent-race runs pass.

Actual first builds took 12.964s old and 1.446s new. The build manifest and result
logs are in `~/.cache/asservat-build/native-mixed-version-build-1/manifest.json`
and `~/.cache/asservat-build/codex-bf86-resume/native-mixed-*.log`. Both binaries
compile schema 100; a common schema floor does not prove native semantic support.

## Shared SQL owner pair remains unqualified

The additional `download-worker-native-owner-mixed` case reuses the existing
native exchange's real PostgreSQL, encrypted S3 audit, enrollment/certificate,
metadata preparation and unchanged narrow runtime roles. It is added only when
`ASSERVAT_NATIVE_VERSION_HELPERS` names the frozen manifest, so ordinary fixture
selection is unchanged. No alternate bootstrap or administrator child process
is introduced. Each helper receives only the existing native_owner_runtime
connection and the parent's existing synthetic topology/profile/root inputs;
its actual recovery/retention guards still validate current SQL state.

The proposed selection is:

```sh
ASSERVAT_NATIVE_VERSION_HELPERS=/path/to/frozen/manifest.json \
  python scripts/test-custody.py --run \
  '^TestContextAdmissionWithRealServices$/^download-worker-native-owner-mixed$' \
  --result-name native-owner-mixed-1
```

The case must demonstrate actual old ClaimNativeOperation creating a short SQL
row, new observation while live, original-expiry refusal and no renewal revival;
then a new twenty-second owner that old observation immediately refuses. A new
independent delivery lease must advance the same owner's sequence without
changing its original operation/deadline. The actual old historical-close outcome is recorded, including rejection. If
needed, bounded new-side fixture teardown closes the exact unchanged operation;
that must not be reported as old cleanup compatibility. A closed owner cannot
revive. A hash of each returned
operation checks identity preservation. An existing-admin fixture snapshot checks
that source/window identities, original deadlines, allocations, spent/uncertain
charges and used-key masks never reset or refill. No payload success is claimed
by this SQL-only sequence. The case retains the existing 20s native phase bound.
The first owned SQL attempt on 517ce699 failed at the old helper's constructor,
before any old claim/observation/renewal effect: Go 6.088s, selected subtest 5.64s,
runner phase 8.878s, exit 1 and no passing selected tests. All 3,191 frozen source
hashes matched, cleanup was empty, and both owned containers and their network
were absent. The environment report SHA-256 is
`b3a87db33b2a3b87891ad7fe124e29ad81a10f37dd08b30f00120e930c2c7f6a`;
report, Go/provider logs and the original frozen build manifest are archived in
`~/.cache/asservat-build/codex-bf86-resume/native-owner-mixed-1-artifacts`.
This is a fixture setup failure, not a mixed-version refusal qualification.

The fixture pool installs verified pgTLSBridge TLSConfig separately from its
original `sslmode=disable` connection string. Serializing only ConnString dropped
that configuration; the helper rebuilt TLS=nil and the unchanged ledger
constructor correctly refused it. The correction acquires an existing pool
connection, reads its verified tls.Conn chain, transfers only the public root
plus the configured ServerName/minimum version through bounded private stdin,
and releases the connection before child work. It adds no SQL query, bridge,
probe, new trust source or insecure fallback. Helpers restore verified TLS and
clear fallback connections; the ledger validation is unchanged.

An explicit-file real local TLS unit proves preserved trust succeeds while a
wrong root/name and absent TLS fail closed (parent race exit 0, 1.065s). Its first
negative test accidentally reused httptest's same default certificate as the
wrong root; that failed fixture is retained, and the corrected test generates
a distinct unrelated CA. This checks helper configuration, not PostgreSQL
startup/authentication or mixed adapter effects. Rebuilt old/new executables
retain their exact production trees, with fixture SHA-256
`79b4e18e4381a82ea05f5c4be198856c81f24259ea5686f23ab2d6f8795de748`
and the new immutable build2 manifest. Build1 remains unchanged.
The corrected build2 worker/boundary parent race suite exits 0 in 4.504s, and
full canonical pre-push plus explicit-file helper vet exit 0. These checks do
not qualify a mixed SQL claim or the actual PostgreSQL authentication path.
The next owned PG/S3 run requires root coordination and fresh source freezing;
no retry has run. Initial accounting counters and their snapshot hash are now
logged without identities or payloads, alongside operation hashes/sequences and
actual old cleanup results.

Canonical `make pre-push` exits 0 with the existing spec virtualenv and pinned
sqlc, including 218 console checks; explicit-file helper vet and Python syntax
checks exit 0. The first pre-push attempt failed because this new worktree had
no console dependencies. The repository's locked `make console-install` completed
in 3s, then the full second pre-push passed. Those logs remain separate; the
initial setup failure is not counted as a passing gate.

## Complexity and remaining scope

This adds two test executables and one optional targeted fixture case, with
zero product files, dependencies, privileges, configuration fields, runtime
services, background tasks, watches or runtime network paths. The helper uses at most one
physical SQL connection per sequential invocation; it has no source/admin/key
credentials. Existing pools and the server connection ceiling stay unchanged.
The first implementation is about 1,000 test/script lines, including bounded
protocol DTOs, build/provenance checks and actual transport fixtures. It reuses
existing installation/bootstrap, guard and role setup instead of duplicating it.
The observed benefit is direct old-worker refusal evidence that same-version
tests could not supply; the shared SQL and operational-version risks are still
unqualified. There is no per-deployment runtime cost and no compatibility
mechanism to configure, upgrade or roll back.

Actual old serving-hub and old connector transport boundaries remain outside
these first cases. Installed near-full pacing/aggregate costs remain in their
separate frozen qualification. Operational drained rollout is also pending:
the installer release code rolls hub processes/followers, which does not prove
regional connector or acquisition-worker image/profile rollout. No built-in
drain command was established. A quiet fixture or passing worker wire test must
not be presented as a complete live rolling-upgrade or operational drain proof.
