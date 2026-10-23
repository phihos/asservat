# Shared approved projection and admitted-worker enrollment component checkpoint

Candidate ADR-219/221 uses the existing acquisition Job/binary, worker enrollment
listener, native transport, key service and physical worker capacity for approved
pod-status content. ReadApproved remains independent of Download; the hub does
not unwrap evidence. The installed composition uses a finite original 60-second
query with four paid polls and two read batches, and independent worker-owned
identity enrollment. Query and native-download parents keep distinct SQL/key
checks and audit identity.

This archive records local component checks only. Real SQL/S3 lifecycle, final
consolidated-role grants, full repository gates and the installed read-only
OAuth-to-approved-content journey remain pending on the integrated candidate.
No local result here is an installed startup or latency qualification.

## Actual checks

- `sqlc-first`: generation exit 0. The three initial compile-only attempts each
  exited 1 with their actual errors retained. Subsequent browser and SQL-hook
  compile passes establish compilation of the corrected integration package.
- `focused-race-first`: actual exit 1, 295.023 seconds, 2869 Go/SQL/module hashes
  unchanged. Four C18 assertions assumed repeated external authority reads.
  The selector also accidentally included unchanged slow Kubernetes projection
  families. Parent requested SIGINT; both owned processes were independently
  absent afterward. This is an **incomplete selection**, not a passing gate.
- `focused-race-second`: actual exit 1, 80.036 seconds, 2870 hashes unchanged.
  An unused test import and two older presentation tests required correction.
  Completed new shared identity/cleanup, native H2/mTLS, public composition,
  capacity, protected placement and installed helper tests passed. The worker
  package matched no tests in this selector; its later full package run passed.
- `focused-race-final`: exit 0, 8.971 seconds, hashes unchanged. Analysis race
  package 1.358 seconds, selected presentation race tests 5.399 seconds.
- `affected-native-race`: exit 0, 43.204 seconds, hashes unchanged. Full evidence,
  native transport and worker packages passed (3.489 / 37.409 / 1.100 seconds).
- `public/`: console check 168 tests, build and browser gate passed. The first
  browser attempt was intentionally interrupted after selecting a cold cache;
  its receipt is retained separately. The completed browser gate exited 0,
  Go 19.341 seconds / wrapper 39.689 seconds, all 2993 source hashes unchanged.
- `sql-lifecycle/`: the new real-service qualifier compiled with race enabled,
  `-run '^$'`, exit 0, wrapper 21.775 seconds / Go 1.064 seconds, all 2651
  Go/module hashes unchanged. This runs **no SQL fixture body**. One subsequent
  test-only call to the existing source refresh helper prepares current config
  for the independent enrollment request; it does not change original query or
  worker dates. Final source hashes record that change.

Each JSON receipt contains the exact command, environment, actual exit and
source hashes. Full stdout/stderr is retained. These are functional results;
concurrent local checks and synthetic providers exclude performance claims.

## Explicit changes to test expectations

ADR-219 retains one completed authority observation per original request.
The old C18 group/source/retention/recovery/path mutation expectations and
presentation tests that discovered a newly shortened external lease were
replaced with tests for immutable original observations, fresh construction on
each paid poll, original expiry/cancellation and current SQL refusal. The
retention-negative now exercises PermitReadBatch; the socket test supplies its
short original cutoff before Call. No statement that all old security assertions
were unchanged is intended. Independent review is in `public/`.

The actual H2/mTLS tests cover fixed query-only content without NativeData,
joined completion, cancellation, wrong worker/query/key and spent-batch replay.
Authority/source/SQL ports in those protocol tests are synthetic. The small
admitted-enrollment test proves that an expired original human observation need
not own identity enrollment, while exact current worker proof, final identity,
token-buffer ownership, original caller bounds and joined cancellation remain.
Actual SQL/current-configuration and provider qualification is separate.

## Next qualification

Merge with ADR-222 before executing
`python scripts/test-custody.py --run '^TestSharedProjectionLifecycleWithRealServices$'`.
Its canonical hub duties must use the same hub-runtime pool; key-acquisition
remains separate. The test uses real compiled SQL roles, encrypted audits and
published evidence, with controlled Job/Pod/proof/signing and positive native
join inputs. The final installed fixture additionally requires a real read-only
OAuth token without evidence:download, a denied native preparation with no
session effect, one original query/worker, spent key slots and joined closure,
and exact approved fields matching the later native download. Existing native,
revocation, expiry and deletion assertions remain required.
