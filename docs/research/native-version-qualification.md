# Native response version boundary qualification

Date: 2026-10-27. Requirements: REQ-DLD-002/003/004.
Status: actual worker, serving-hub and connector subprocess/transport cases
and the scoped shared SQL owner pair pass. Protected installed mixed-role
admission and operational rollout remain unqualified.
This is test-only qualification work.

The old production tree is canonical PR100 main
`eed8594020645fe6d10f8c6565e69a6235c7507d`; the new tree is PR101
`fa69b01948edf9d7baf1f00453e1482a224fd4ea`. Neither production tree is patched.
The same finite [helper](../../test/fixtures/native-version-helper/main.go) is
compiled separately in each module/worktree by
[the build script](../../scripts/build-native-version-helpers.py). It invokes
that tree's actual NativeOwners, RunWorkerConversation, NativeFrameGate,
HubOperation, RelayConversation and native h2/mTLS handler implementations.
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

## Actual old serving-hub and connector results

`TestNativeActualVersionServingWire` adds four actual-process cases. Each old
role first passes a three-second positive using the same certificate, listener,
source and synthetic admission setup as its twenty-second negative. The hub
case runs the old hub and new worker; the connector case runs the new hub,
old relay and new worker. Each short case delivers exactly 65,536 deterministic
bytes, acknowledges the final sink once and joins successfully. The connector
positive opens exactly one authenticated upstream conversation.

Both twenty-second cases preserve the actual old frame-gate constructor's
`operation` refusal, classified unavailable. Neither constructs a replacement
proof, extends processing freshness or reaches a later command predicate. The
fixture then serves the real old h2/mTLS handler with this retained error: one
request reaches synthetic admission with the exact verified client leaf. The
construction refusal and authenticated request count are recorded separately.
Neither negative delivers/acknowledges bytes or opens an upstream conversation.
The new worker performs its separate synthetic preparation read once, then its
actual Open fails before a response reader or data frame. This is an old gate
refusal carried through a real wire boundary, not evidence that an old hub
successfully constructed the long conversation or that full protected peer
admission ran. No particular refused HTTP reply is claimed: server shutdown may
interrupt its flush after the recorded admission refusal.

The parent owns each loopback listener before starting children and passes its
duplicated FD through `ExtraFiles`; the child accepts only an inherited loopback
TCP listener. Existing bounded stdin/result transport and subprocess joining
remain in use. There is no readiness endpoint, free-port reservation race,
polling, new fixture service or extra bootstrap. Missing inherited listener
fails closed in both binaries, alongside the existing input-boundary cases.

Immutable build3 compiles the same production revisions named above: old
1.547s, new 1.550s. Its provenance is:

| Binding | SHA-256 |
| --- | --- |
| Fixture source | `ddd041dbd5904ecf3463ed8553154bd79460f82c2e07bd825c8ded095b2575b0` |
| Old binary | `7cd5127ca6ea15335dd585ff1f762d6d67631eb969065a6f1439615f55b44965` |
| New binary | `109e8e89bd46ec4ea9bc2e38e57635e3dd106eb43297c522ebe5fd35c5da7351` |
| Build3 manifest | `e6a342c0394bffac967a7ca6f0b70ad70d0adb22168ec62122f4b7b1fd9c7692` |

The new four-case normal run passes in 0.128s (subtest 0.11s). Combined worker,
serving and eight input-boundary cases pass under parent race in 4.762s; the
serving subtest takes 0.19s. Explicit-file helper TLS race passes in 1.064s and
helper vet exits 0. Child binaries are ordinary, not race-instrumented. The
initial new test compile failed on one unused import; its log remains retained.
Logs are `native-mixed-serving-{1,2}.log`,
`native-mixed-components-race-4.log` and `native-mixed-helper-{race,vet}-3.log`
under `~/.cache/asservat-build/codex-bf86-resume`; the frozen manifest is
`~/.cache/asservat-build/native-mixed-version-build-3/manifest.json`. No external
fixture or collector ran for these additional cases. They do not supersede the
separate build2 SQL evidence or qualify a later production source revision.

## Shared SQL owner pair and retained initial failure

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
After root review and slot coordination, the next single owned PG/S3 run used
fresh frozen source as recorded below. Initial accounting counters and their
snapshot hash are logged without identities or payloads, alongside operation
hashes/sequences and actual old cleanup results.

### Scoped real SQL result after the TLS correction

`native-owner-mixed-2` passes exact source
`0b0c1d2a7faab6b335a8a34761be080f9483a282`: selected subtest 14.33s, parent 14.71s,
Go 15.772s, runner phase 18.596s and terminal exit 0. It executes the actual old/new
binaries from immutable build2 against the same existing-role PostgreSQL/S3
fixture. All 3,191 frozen repository source hashes matched; helper/manifest hashes
were unchanged; cleanup failures were empty. The exact owned PostgreSQL/S3
containers and their network were independently confirmed absent afterward.

The actual old ClaimNativeOperation creates the short row and the new adapter
observes the exact returned operation hash. After its original end, new observe
and renewal deny. The new twenty-second owner is immediately unavailable to old
observe, while new observe succeeds. Fresh independent delivery authority then
advances sequence 3→4 on the identical original operation hash; an expired short
observation is never reused. The old adapter's exact historical Close returns
success and persists closure for both short and new long rows. New-side teardown
was not needed in this run. Closed renewal remains refused.

The initial accounting snapshot and every comparison remain unchanged:

| Counter | Observed retained value |
| --- | --- |
| Charged output/read | 351 B / 8,388,608 B |
| Requests | 1 |
| Reserved responses/windows | 1 / 1 |
| Charged native backing rows/keys | 1 / 0 |
| Preparation used-role mask | 7 |
| Native key rows/used-role mask | 0 / 0 |

The snapshot SHA-256 is
`ba0d992f21207bbea0e1709dc46f9e37f6da90d4a7a39908c51b853c4f4de70c`.
It includes original session/source-window identities and deadlines, generations,
reserved audit bytes, window ordinal/outcome and key accounting. Their equality
is checked after each accepted or refused version operation; no limit, charge,
key slot, source or deadline is reset to make the sequence pass. No response
payload is delivered by this SQL-only sequence, and no native response key is
opened. Initial metadata preparation has its existing three spent roles.

The environment report SHA-256 is
`1f465f6ddf695c3124d04282114a3525283c771b64a5422f4aba79c529fb04a6`.
Its exact passed name is
`TestContextAdmissionWithRealServices/download-worker-native-owner-mixed`.
The report, Go log, runner log and original build2 manifest are archived under
`~/.cache/asservat-build/codex-bf86-resume/native-owner-mixed-2-artifacts`.
This qualifies this owner-adapter boundary with the fixture's explicitly
synthetic initial authority/bootstrap/Pod inputs; it does not qualify a deployed
mixed serving peer/connector or operational rollout.

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
tests could not supply, plus the scoped real SQL owner result above. Remaining
protected installed mixed-role admission and operational-version behavior are
unqualified. There is no
per-deployment runtime cost and no compatibility
mechanism to configure, upgrade or roll back.

The serving extension adds 385 net test/helper lines (422 added, 37 removed),
including eight additional subprocess invocations and four inherited listeners.
It reuses the existing certificate/source and bounded runner instead of another
bootstrap. Installed near-full pacing/aggregate costs remain in their separate
frozen qualification. Operational drained rollout is also pending:
the installer release code rolls hub processes/followers, which does not prove
regional connector or acquisition-worker image/profile rollout. No built-in
drain command was established. A quiet fixture or passing worker wire test must
not be presented as a complete live rolling-upgrade or operational drain proof.

ADR-227 leaves regional connector and download-worker operational upgrade work
unfinished. The installer rolls hub-worker, hub-api and present key/publisher/
federation followers, then checks settled image/generation state. Worker profile
revision/suspension fences old-profile admissions and retains historical cleanup;
it is not a graceful drain. Current qualification therefore supports the fresh
matched-installation path, not longer-response operation across old peers or a
live rolling upgrade. A supported stop-admissions/join/matched-image-and-profile/
resume sequence remains later ADR-227 work; these tests add no drain framework.
