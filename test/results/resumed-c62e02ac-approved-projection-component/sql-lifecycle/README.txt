Shared approved-query SQL/S3 lifecycle qualifier draft, 2026-10-23.
Owner: /root/review_pr41. Active shared219 sources remain frozen for CI checks.
Applied exactly the two agreed files after CI source-freeze release.
Compile-only passed actual exit0 (session95642/chunk4e9c38), wrapper21.775s,
integration package1.064s [no tests to run], all2651 Go/module hashes unchanged.
No external fixture or behavioral test run by this qualifier owner.

Proposed files (exclusive agreed with CI):
- NEW test/integration/shared_projection_lifecycle_test.go
- test/integration/context_query_ledger_fixture_test.go: callback extraction,
  retain accepted worker profile; original top-level and cleanup unchanged.

Exact external selection after final integration/source freeze:
python scripts/test-custody.py --run '^TestSharedProjectionLifecycleWithRealServices$'
Parent alone launches the sequential external fixture.

Uses the existing pristine capacity SQL/S3 setup and independently published
actual encrypted context. One real read-only authority leads to one admitted
query and one worker via actual ProjectionWorkerAdmission + ProjectionRuntime.
All query/worker/enrollment/certificate/native/key transitions use actual adapters
and compiled installed runtime roles. Invocation and worker/enrollment/certificate
objects use real encrypted create-only S3 audit and separate acknowledgement.
The first human context is explicitly canceled before independent enrollment.
A new paid poll binds the activated identity, spends one read start and three key
roles, records exact private native closure and requires real outcome audit before
public batch closure. Readback proves original query unchanged, no download row,
one worker/certificate, spent roles7, still charged query, no active batch.

Controlled inputs: protected workload/configuration source, human token identity,
Job/Pod/token attestation, synthetic issuer signing real X.509, positive private
transport join. No dummy download session or DownloadAuthority, and no admin
writes of worker/certificate/key state. This is not installed TLS/Kubernetes,
actual key crypto transport or cold-start/performance qualification. Native
framed join is independently covered by TestNativeApprovedProjection*.

ADR222 MERGE ADAPTATION REQUIRED before external run:
This pre222 draft selects existing compiled purposes directly. On the integrated
candidate replace all query/metadata/normal journal/ack/enrollment/activation
purpose selections with the single identical base.roles["hub-runtime"] pointer.
Keep base.roles["key-acquisition"] separate and existing capacity-profile-read.
Do not clone union credentials, open separate facet pools, or add compatibility
fallback. Parent owns integrating that canonical selection after222.

Complexity: one 400-line lifecycle test with local providers and approximately
seven lines added to existing setup. Zero production mechanisms, config knobs,
new harnesses or runtime privileges. Existing broader ledger/lock/expiry tests
remain unchanged. Exact execution result remains pending.

Post-compile reviewed change: one existing f.refresh(t) before independent
worker enrollment observes the current accepted source after the human call
closed. Original query/worker dates remain exact. CI approved no repeated
compile for this established helper call; final source-ready hashes include it.
