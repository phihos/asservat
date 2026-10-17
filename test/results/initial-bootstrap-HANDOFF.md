# ADR131 guarded checkpoint

Frozen payload: 20 new files, 165,242 bytes. All bases are absent in live; no shared-source replacement or SQL migration is present. `manifest.json` records every base/payload hash plus relevant source dependency hashes. `payload.patch` is equivalent to `files/`.

Manifest SHA256: `90fc2b2d91005c37f35f5fefcdbe8024442c90ebf08599245b01706c0f812fa0`.
Patch SHA256: `83afdd88b8da6fc093bfb6d1a2a4949da09bdce4fcb333613eca406cf93c64f5`.

Scope: static/private contracts and canonical schemas; actual guarded Kubernetes prelude/private seed/fixed create receipts; generated existing preparer projection; trusted SQL manager one-use creation and exact replay; manager restriction, measured history grant transfer and existing-session termination; ADR131 and architecture note; focused tests and an isolated real-service test source. No runtime/public/Helm route is enabled. SQL49/50 and shared installation sources are untouched.

The final source moved read-only projection/native-policy readiness before the one-use create claim. BeginManagerClose also independently opens the exact retained projection and requires actual complete eight-step handover before accepting the restrictive manager close claim. It is still not a joined process or SQL closure receipt. Final SQL retirement independently checks current exact activation/history, original DB incarnation, manager/grant origins, no sessions and login rejection.

Actual checks, GOMAXPROCS=2, -p 2, TMPDIR=/home/phil/.cache/asservat-build/tmp, using the staged Go overlay:

- Final `go test -race ... ./internal/adapters/kubernetes ./internal/adapters/postgres ./test/integration -run '^TestInitialBootstrap' -count=1`: exit 0; Kubernetes 1.073s, Postgres 1.026s, integration 1.049s. Evidence `checkpoint-race.log`.
- Final `go vet ... ./internal/contracts ./internal/adapters/kubernetes ./internal/adapters/postgres ./test/integration`: exit 0. Evidence `checkpoint-vet.log`.
- Earlier affected contracts/Kubernetes/Postgres/integration compilation plus pure tests: exit 0, retained as `projection-manager-compile.log`.
- Draft202012 schema validation and local reference resolution for all three new canonical schemas using the existing spec virtual environment: exit 0, `schemas.log`. This is not the full repository spec/architecture gate.

The actual-service selector is **UNRUN**:

`^TestInitialBootstrapManagerWithRealServices$`

It consumes the existing owned custody PostgreSQL/S3/OpenBao fixture via ASSERVAT_CUSTODY_FIXTURES. It creates/drops one separate empty database, applies the actual embedded schema, creates the actual finite manager and purpose/history roles, writes/verifies encrypted initial activation, demonstrates existing manager authority survives flags-only restriction, then exercises exact grant-chain transfer and session closure. Protected seed/witness/history-read authority is explicitly synthetic; no Kubernetes/bootstrap/Pod authority is claimed by this SQL fixture. The default custody regex does not select this new name; parent must select it explicitly or add the scoped harness selection after review. Source compilation/skip is not service qualification.

Remaining work is explicit: (1) fixed command/file projection compositor, with distinct producer/DDL/preparer/retirement credentials and no credential loading on completed passive replay; (2) actual guarded bootstrap-to-original-Pod native fixture replacing the prior manually pinned prerequisites; (3) official Helm runner packaging; (4) separately qualified final deletion of Asservat-created SQL/provider source Secret copies while retaining original occupied names and preserving operator-owned originals. Seed clearing alone cannot clean copied still-valid S3 credentials. Current guard does not permit their deletion and this checkpoint does not claim final private-copy cleanup.

Parent's separate ADR130 capability-aware loader/final-input/SQL-incarnation correction is required at the direct preparation and activation boundaries; no outer-only bootstrap check replaces it. No external lab or live source write was performed by this checkpoint.
