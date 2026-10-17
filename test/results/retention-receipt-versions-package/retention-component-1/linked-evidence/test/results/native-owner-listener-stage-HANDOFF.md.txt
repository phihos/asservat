# ADR122 optional native owner listener and installed reader composition

Frozen staged payload; no live files changed and no external fixture run by this agent. Parent can apply only after exact manifest base/payload verification. Go overlay points at the live tree plus these staged files. No migration, generated SQL, module, deployment template or shared index changes are included.

## Changed contracts

- Optional audited OwnerPool.NativePort and wire nativePort. Absent/zero-valued Go fields keep historical JSON bytes exactly; nonzero native port is 1024..65535, distinct from enrollment port. Explicit JSON zero is outside the canonical schema. Native forwarder exclusively uses this separate port on already independently verified owner Pod addresses/process TLS identity. Enrollment Service/handler stay unchanged.
- Optional closed deployment.native installs connector issuer roots, exact cluster/control-namespace HTTPS API pins, immutable retention topology pins and finite connection/concurrency limits. Input document remains bounded at 256 KiB. Native config and accepted native port must be present together. Fixed token filenames and separate sql-native-read.json credentials are required; no ambient settings are imported.
- Concrete postgres.NativeReaders exposes current worker/certificate/native locator/read facets only. The original worker profile is selected from independently current SQL; Hello cannot pick it. Existing recovery, retention, enrollment and operation checks remain. NativeOrigins now accepts narrower NativeOperationReader; mutation methods stay in NativeOperations. The live TerminalLease implementation is retained unchanged.
- OwnerRuntime composes actual NativePeerChecks, real installed worker API attestation, current connector registry and owner serving checks. It optionally supervises a separate h2/TLS1.3 receiver, registers only its exact Pod/process route, and retains the original actual request callbacks. No bearer or CurrentIdentity is manufactured.
- Native Serve bounds sockets before TLS, one conversation per socket/one simultaneous stream, small h2 flow-control/header limits, ten-second original socket lifetime and certificate shortening. Original operation/identity/proof bounds remain <=5s. Root cancellation closes I/O and joins handlers/callbacks. Server leaf must have only serverAuth; clientAuth connector credentials cannot serve.

## Actual checks

Environment: GOMAXPROCS=2, TMPDIR=/home/phil/.cache/asservat-build/tmp, go -p 2, isolated Go overlay. No native labs.

- focused-first.log and listener-after.log: preserved actual HTTP/1-only TLS negative failure. A TLS1.3 Dial can return before server-side completed-handshake verification rejects the client Finished. This is fixed with an explicit ClientHello h2-offer check plus existing final negotiated-protocol verification.
- listener-after-final.log: actual h2 duplex, joined cancellation and HTTP1/client-only server negatives pass race, exit 0.
- integration-compile.log: preserved initial compile failure caused by a test variable name collision, fixed without behavior changes.
- integration-compile-final.log: integration fixture compiles, exit 0, no external tests run.
- race-final.log: all seven full package race suites exit 0: bootstrap4.495s, transport/native2.318s, postgres1.216s, mtls8.561s, kubernetes148.968s, domain/fleet1.008s, contracts1.310s.
- check-native-schemas.py: staged canonical positive/negative schema tests pass with installed spec-venv, real format checker and offline references. DER validity, duplicate semantic identities, distinct ports and cross-field concurrency remain separately enforced runtime tests.
- **Affected vet and combined design/spec gates are pending**, held for parent external qualification. Parent requested packaging without another heavy build and will run integrated checks.

## Native fixture and exact remaining work

The owned test/integration/native_exchange_test.go now installs a separate synthetic native_metadata_runtime SQL role. It has SELECT and only immutable-key lock UPDATE privileges. Existing owner/key-bind/history credentials remain separate. The fixture uses actual NewNativeReaders and native.Serve, checks exact worker/certificate identity, asserts SQLSTATE42501 for operation close/key consumption through the reader, preserves exact352byte/hash/SQLCompleted and all three distinct Joined conversations. This changed fixture has only compiled. Parent should run TestContextAdmissionWithRealServices/download-worker-native-exchange (not the similarly named custody parent), with frozen sources and terminal cleanup/hash evidence.

Its SQL/S3/A-KEY/h2 effects are real. Protected installation/bootstrap, human/session/Pod proof, certificate issuer and serving facts remain synthetic; this is not real deployed connector/owner authority. The prior strict native pass used the preceding transport and roles, and does not qualify this new source.

Parent needs narrow shared ADR122 index/spec integration, integrated vet/architecture/spec gates, then the strict fixture above. No SQL inventory/head update is needed. The next implementation increment is the actual connector process-owned client enrollment/renewal supervisor and a distinct worker-facing serverAuth producer, plus protected native input/role/API projection provisioning and cleanup. Do not use fixture callback certificates, hub-owner substitutes or a connector clientAuth leaf as production server identity.

The existing context conversation still freezes one original <=5s operation/proof/route sequence and supports the approved <=4096-byte context path. It does not qualify long-file streaming across fresh authority intervals. Larger-file window/segment handling must preserve finite backing, fresh authority and joined old buffers; no old frame revival or lease extension. No public native route, hub unwrap or production runtime enablement follows from this package.
