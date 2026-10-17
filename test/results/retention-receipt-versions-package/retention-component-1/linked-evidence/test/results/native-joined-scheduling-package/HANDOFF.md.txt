# Positive native Join scheduling — frozen six-path package

## Scope and contract refinement

The worker's existing success predicate still requires a positively Joined conversation, no run error and successful joined stream Close. After that predicate, the next iteration immediately rereads the projected token, generates a fresh cryptographic nonce and opens a new normally authenticated/admitted connection. Only the unconditional one-second success delay is removed. Authenticated NoCommand retains its existing one-second idle backoff and original observation/setup checks. Errors, nil streams, unknown/lost results, Uncertain and failed close still terminate automatic selection. Original parent/worker ends and the 32,768 total-conversation ceiling are unchanged. No command is replayed, slot/refund granted or authority reused across the new Hello.

ADR121 and worker-startup previously explicitly applied the delay to both outcomes. Parent approved their narrow scheduling refinement: idle backoff is for NoCommand, not completed work inside an active download with its original short authority. Native-exchange already described its one-second rule as idle backoff. No wire, SQL, schema, lease or approval contract changes.

The fixture's nativeSQLWorkerLoop gets the matching success-only continue after RunWorkerConversation has positively returned Joined and joined its owned stream. Its fixed synthetic worker token remains fixture authority; the product loop continues actual projected-token reads. The production code's independent post-Run Close-success check remains unchanged.

## Actual verification

One sequential immutable-overlay job, handle **47341**, is terminal exit **0**. GOMAXPROCS=2, GOFLAGS=-p=2, explicit stage TMPDIR. All **1,465** internal/embed/migration/API/integration/bundle/module dependency hashes, base hashes and staged payload hashes match before and after every command.

- **Before:** exit **1**, command 3.219s. The newly added meaningful regression runs against original product code. Its first command positively joins and closes; the idle wait advances the deterministic clock by one second, so the next fresh Hello misses a separate original 500ms pending-command interval. Failure: `positive Join consumed the next original command interval in idle backoff`. No compiler/setup failure is substituted.
- **After focused races:** exit **0**, command 4.491s; Go 1.443s. Nine top-level / 40 named passing entries. The new regression reaches the fresh second Hello before that original cutoff, with new token read/nonce, cleared prior token and closed prior stream. Additional tests retain parent cancellation, worker expiry, shorter parent deadline and the 32,768 ceiling for both positive Joined and NoCommand. Existing disposition cases retain one-second idle backoff, original idle deadline, unknown open/result, false Joined, failed Close, wrong/stale/extended idle, nil stream, readiness and joined child shutdown behavior.
- **Integration source compile:** exit **0**, command 12.328s; `-race ./test/integration -run '^$'`. No native/external test executed.
- **Affected vet:** exit **0**, 5.620s, bootstrap and integration packages.

Exact commands and source closure checks are retained in `evidence/{before,after,fixture-compile,vet}.json` and matching logs. Overlay paths refer to the immutable original stage. No broad suite or specification gate was rerun for this narrow change; parent owns combined integration/document gates and native qualification.

## Evidence boundary and next task

The regression uses synthetic callbacks and a deterministic clock. It proves unnecessary scheduling delay under a shorter next-command interval, not a measured native availability fix. The actual trace's approximately 1.16s Wait is consistent with this delay but includes other setup work. Parent separately identified expired fixture permission/retention/fleet observations and a 30-second synthetic human session. Those fixture renewals are outside this package; no original five-second request deadline is raised here.

After verifying `manifest.json`, integrate the exact six payloads, recheck affected repository contracts and run the parent-owned ordinary/range/interrupted native qualification with frozen sources and cleanup verification. Unknown transport results retain spend and stop selection. Do not classify positive intentional ranges as complete interrupted reconstruction. No builds remain active and no live source was edited by this package.

Copied code intended only for future evidence archives should use `.go.txt` outside product/package source directories so it cannot accidentally become another Go package.
