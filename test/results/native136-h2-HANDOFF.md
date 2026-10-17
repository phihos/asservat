# ADR136 HTTP/2 phase deadline correction

Five paths staged over integrated ADR136/137/138, no live edits. Three production
files plus two focused tests; no public wire/schema, SQL, configuration or native
protocol change. Original bases and all payload hashes are in manifest.json.

The handler formerly left its initial five-second socket write deadline armed
while the application positively finished audited metadata and deliberately
acquired a fresh identity for content. A valid delayed content setup then lost
HTTP/2 to an INTERNAL_ERROR stream reset. An expired HTTP deadline cannot be
renewed by the first byte's later SetWriteDeadline.

The application now notifies the HTTP factory only after positive preflight,
before closing its first batch or waiting for fresh identity/SQL/provider work.
The callback may re-arm an idle socket only while the original preflight is
still current; it intersects the original response/session/metadata-read and
latest preflight access bounds plus both caller contexts. It emits no bytes,
creates no authority and can run once only. Missing/expired acknowledgement,
cancellation, a failed deadline update or a repeated phase transition denies.
The actual response cannot exceed that idle cap. Conditional/error preflights
never enter the phase. Every write still uses the unchanged short current lease.

The existing sink's post-chunk behavior is preserved: download_response.go
joins cancellation callbacks after Flush, verifies the original piece deadline,
then restores only the original response idle bound. The new actual h2 second
regression verifies an idle interval beyond the old byte lease followed by a
separate current lease; no old handle is renewed.

## Verification

All tests use isolated Go overlays, GOMAXPROCS=2 GOFLAGS=-p=2 and the dedicated
/home/phil/.cache/asservat-build/tmp. No external lab, SQL generation or native
worker/provider fixture was run.

- Failing before, exec chunk7887e1 exit1: actual TLS/HTTP2 test
  TestNativeContentHTTP2BodySetupSurvivesOriginalPreflightDeadline reports
  INTERNAL_ERROR from the peer at the150ms original preflight deadline.
  evidence/before.log and exact before_test.go.txt preserved. The structural
  optional method check lets this test compile against the original API.
- After, handle27203 terminal0: browser races1.654s and evidence races1.132s,
  evidence/after-race.log. Selector:
  ^Test(NativeContent|NativeHTTP2|NativeHTTPResponse|NativeResponseFreshBatch|ResponseTransfer)
- Affected two-package vet, exec chunkeadad6 exit0, evidence/vet.log.

Actual transport tests are local TLS/h2 with explicitly synthetic immutable
metadata/response/leases. They prove socket-phase behavior, not regional worker,
SQL, SSO or installed-runtime qualification. Application tests separately prove
positive audit -> phase transition -> fresh batch -> response ordering, retention
shortening, conditional non-entry, and zero reservations/output after failure.

## Apply

Verify the three existing base hashes and two new-path absences; apply changes/.
The unchanged sink and test-helper/module dependency hashes are separately pinned.
Parent runs combined gates/native qualification and owns any progress update.
All paths and evidence are now frozen; no active build remains.
