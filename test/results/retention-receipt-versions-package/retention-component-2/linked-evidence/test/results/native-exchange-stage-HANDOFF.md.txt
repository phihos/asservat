# SQL45 / ADR116 context native exchange handoff

Frozen 53-path source payload in `work/`, `changes.patch`, `manifest.json` and
`paths.txt`. Parent merges only manifest paths after matching base hashes.
Manifest SHA256: be30c75fbd5f545c200fa44c3c55acf257c2b70a9ae146355757537dc853600c.
Patch SHA256: b46b3d767072d54a8df37981f5397872be5be1cc486f87e6aa227f4bf0d13864.
The 28 production API files exactly match the independently frozen
`worker-api-snapshot-v2` (manifest 27ce8d84f4fefe493f152ed5a3bbf8d0129416e13af147efc65639c64ed7f1e4).

## Scope

Purpose-specific outbound h2/TLS 1.3 acquisition→connector→exact original hub
exchange, with actual current request closures, exact stored worker/source/key
pins and distinct preparation/observe/content operations. Actual native data
still uses the existing <=4096-byte pod-status decoder. The generic SQL42
response/window ledger is reused; this does not qualify a large-artifact reader
or 1 TiB throughput. Collection writers stay wrap-only; the separately scoped
acquisition worker legitimately has selected-object unwrap. Hub/connector have
no unwrap credential.

SQL45 adds download_native_backing, download_native_owner, download_native_key:
finite per-allocation row/key/update/history backing; one exact worker locator;
three nonrefundable response-window unwrap slots. Preparation reuses its existing
three batch slots. NativeKeyAuthority resolves a closed purpose union and never
falls through after denied/unknown consumption. Row close fences work without
claiming quiescence. Cleanup requires existing positive worker retirement and
finite backup/WAL cooling; no expiry-only refund.

The hub registers live local ownership before SQL publication. An exact
same-process factory carries the original current-identity check; no credentials
or serialized CurrentIdentity cross the private wire. Protected actual peer,
Pod proof, registry/configuration and original bounded SQL observations remain
mandatory. Connector clients use the connector role; owner certificate relay is
unchanged. Commands are nonce-bound to the exact original lookup and worker.

One native chunk is pending per hop. The hub's final exact count/flush gates the
regional ACK; unknown/partial writes stay spent, and Close joins active work.
The relay additionally owns one bounded ahead-of-phase control input, because
an HTTP client context alone does not detect upstream EOF without a response
body Read. Its cleanup is joined, and it never queues another payload chunk.
Current owned-refresh pauses consume only the exact C02 pause proof; generic
Busy is not retry authority. Initial claim/version/end stay fixed, and a settled
claim permits one fresh batch attempt only.

Command-only ceiling is 640 KiB; other controls remain 64 KiB, payload 1 MiB,
startup control unchanged. Domain maximal-source regression measured 570,968
bytes; conservative arithmetic is 571,084. See COMMAND-BOUNDS.md. Parent owns the
provisional 64 MiB native-v2 profile floor, pending deployed RSS qualification.

## Actual verification

All commands used the isolated stage, GOMAXPROCS=2, -p 2 and the explicit build
TMPDIR `/home/phil/.cache/asservat-build/tmp`. No external lab was run here.
Logs are in `../stage/`:

- `native-command-size-before.log`: terminal 1; old 64 KiB decoder rejected the
  existing domain-valid 570,968-byte command.
- `native-v2-race-second.log`: terminal 1; new actual two-hop cancellation test
  showed a blocked regional read was not interrupted within 1s. Command/large
  h2-source regressions already passed. This failure was not hidden by a longer
  test timeout.
- `native-v2-race-third.log`: terminal 0, `go test -p 2 -race -run '^TestNative'
  -v ./internal/contracts ./internal/transport/native ./internal/adapters/mtls
  ./internal/application/evidence`. Cancellation joins in 0.03s; actual two-hop
  maximal-source preparation passes. Lost final ACK remains Uncertain. Router
  exact owner/single attachment/joined capacity, prior lease/known-revocation,
  pause/ACK, actual h2 and final HTTPS success regressions pass.
- `native-v2-vet.log`: terminal 0, focused `go vet` over those packages plus
  domain/authorization, objectstore, postgres and test/integration. Includes the
  corrected struct tag; no source-vet warnings suppressed.
- `native-v2-full-focused-race.log`: full affected domain/authorization,
  evidence, mTLS, objectstore, postgres and native transport race suites pass;
  contracts initially failed only because this sparse stage omitted canonical
  example files. These dependency-only fixtures were copied from live source.
- `native-v2-contracts-final.log`: complete contracts race suite terminal 0.
- `native-v2-integration-compile.log`: `go test -p2 -run '^$' ./test/integration`
  terminal 0, no tests run. SQL45/S3 fixture remains externally unqualified.

`native-result-binding-before.log` / `after.log` also preserve the earlier
failing-before worker-public-key replacement regression and its passing fix.

## Parent-owned merge/gates

Regenerate shared sqlc models/queries against the combined current schema;
only the new native_exchange.sql.go is included here. Do not overwrite shared
models, roles or schema head from this sparse tree. Add schema45's three tables
to the pristine inventory and relevant narrow runtime roles, update schema head,
and add `internal/transport/native` to C20 package roots. Review migration45 and
run actual SQL before claiming its trigger/backing/role qualification. Parent
owns ADR/spec/traceability indices and profile/startup/Secret/Job changes.

The integration hook only adds mode `download-worker-native-exchange` to the
existing download_sessions fixture; existing modes are unchanged. Suggested
selection: `^TestCustodyWithRealServices$/^download-worker-native-exchange$`.
This composes real SQL45/SQL42, encrypted S3, enrolled acquisition TLS, three-slot
remote A-KEY, two h2 hops and the actual final HTTPS sink. Expected exact native
body/checksum, completed SQL accounting and preparation/window slot independence
are asserted. Synthetic protected bootstrap, issuer, current human session, Pod
proof and connector serving/peer admission are explicitly identified. This is
not a deployed acquisition/connector/real-SSO qualification. Its joined observer
loop refreshes those synthetic source observations without changing any original
request/operation/byte deadline.

## Remaining runtime/source work

1. Parent ADR121 v2 startup/native worker loop, profile/control/Secret/Job
   consistency and scoped temporary S3 credential expiry. Use v2 API snapshot.
2. Protected hub/connector native listener composition using the existing
   NativePeers/HubAdmission/ConnectorAdmission/NativeOwnerForwarder and real
   current serving credentials/routes. Concrete adapter code is present but
   this fixture's admissions are explicitly synthetic; production listener and
   connector credential producers must not be replaced by fixture certificates.
3. Protected NativeHistoryQualification/backing producer, finite supervisor and
   cleanup; test backing constants are synthetic arithmetic inputs, not measured
   production WAL/backup qualification.
4. Compose public prepare/get/cancel and authenticated GET with the real admitted
   worker/result owner, SQL46 stop state and C02 refresh owner; no constructor here
   mounts a public tool/content route or bypasses raw/client/retention checks.
5. Deployed whole-path qualification, memory and slow-consumer measurements.
   The 4 KiB context test cannot expose large-file/VPN throughput limits. Five
   seconds remains a hard authority bound; chunk ceilings are not minima.

Automatic lost-final-ACK reconciliation is deliberately unavailable: socket
close/expiry cannot prove all former participants joined. Recovery is explicit
exact-worker cancellation, positive termination/retirement, then a newly paid
admission if current limits permit it. Uncertain spend stays charged. Neither
this fixture nor the component checks claim that recovery path is wired in the
public UI. No generic raw/share authority or public runtime is enabled.
