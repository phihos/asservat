# Connector API proof reuse correction

Frozen five-path payload in `changes/`, exact existing originals in `bases/`.
Manifest SHA256: `5100f59c002a270f041a718a82e8d6a0534266584d4ebe88c3731ca405521437`.
No live changes, SQL migration/generation, dependency changes, public enablement or external fixture was performed. Frozen ADR135 and the separate ADR139 listener stage are unchanged.

## Change and bounds

The concrete ConnectorAPIExecutionProtection retains one positively completed full process proof and coalesces overlapping proof/current-check calls. Its original CheckedAt and earliest ValidUntil survive reuse. The initiating caller owns synchronous production; cancellation, expiration or a known-change generation prevents late positive publication. Waiters retain independent cancellation and cannot detach that producer. A failed current read has no stale fallback.

Every non-overlapping reuse still checks actual connector credential/source/registration, execution SSR and live namespace/account, both exact guard policy/binding pairs, immutable settings, complete current Deployment/ReplicaSet/Pod workload digest and all approved mounted-input metadata. Rechecks can shorten authority, never re-anchor or extend it. The client stays at QPS20/Burst20 and every original caller/preparation/binding deadline remains unchanged. Legacy bare-Pod behavior is unchanged.

The native fixture records deltas separately for process construction, process read, PrepareStart, ReadyStart and ConsumeStart. It preserves the existing real changed-input negative and whole-object Secret/foreign-name checks. It emits only static operation classes, counts and elapsed durations, not request/response values or credentials.

## Actual verification

All owned build handles are terminal. Commands used `GOMAXPROCS=2 GOFLAGS=-p=2`, stage `overlay.json` and dedicated `TMPDIR=STAGE/tmp` against the current integrated live tree.

| Handle | Command | Result |
| --- | --- | --- |
| 14659 | `go test -overlay=STAGE/overlay.json -race ./internal/adapters/kubernetes -run '^TestConnectorAPI' -count=1` | Exit 0, 1.082s; `logs/race.log`. |
| 27860 | `go test -overlay=STAGE/overlay.json ./test/integration -run '^$' -count=1` | Exit 0, actual fixture source compiles; `logs/integration-compile.log`. No native tests ran. |
| 26702 | `go vet -overlay=STAGE/overlay.json ./internal/adapters/kubernetes ./test/integration` | Exit 0, `logs/vet.log`. No overlay-layout caveat for these existing packages. |

Six new proof-state tests include deterministic in-flight waiter handshakes, unchanged original dates, shorter waiter deadline, cancelled waiting caller, producer cancellation/expiry/known change, failed current proof without fallback, forbidden re-anchoring/extension/process replacement, and invalidation during blocked recheck. Synthetic completed proofs in these tests do not supply native authority.

Failing-before evidence is the actual third reader run, copied byte-for-byte to `evidence/regional135-native-reader-after-deadline-fix.log`. It passed actual defaulted process/input and Secret negatives, but local PrepareStart created one CapacityReservation then failed its after-read at 4.995665377s, with 4.333884ms remaining. It did not reach Ready. Earlier aggregate counts cannot be described as per-phase counts. The new phase measurements are for the next native comparison; no corrected native success is claimed.

The focused code changes have no public schema change. Full repository/spec/architecture gates were not rerun in this stage; parent may combine them with integration.

## Next exact qualification

Parent-owned context native selector:

```text
^TestConnectorAPIProcessWithRealKubernetes$
```

Use the existing owned context harness and unchanged original five-second grants. Require the whole actual Prepare/Ready/Consume path and changed-input negatives; record per-phase API count/duration and the harness source/cleanup verdict. If the cumulative current checks still exhaust the original interval, preserve the failure and propose the next bounded reuse step from measured phase evidence. Do not increase QPS/deadlines or reset authority to manufacture a pass.

This correction does not qualify the full installed HTTP/2 exchange. Its production connector credential source itself performs repeated current configuration proofs, while this native fixture's accepted connector source/CA/registry remain synthetic. Frame observation leases and source-proof coalescing remain separately reviewed follow-up work. ADR139 real SQL owner enumeration and signed SQL52/API/storage exchange through the actual same-port listener remain staged/unqualified. No per-frame lease or general cache is added here.
