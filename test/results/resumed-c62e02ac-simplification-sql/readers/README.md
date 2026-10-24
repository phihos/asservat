# Real SQL shared metadata-reader qualification

Frozen commit `114dd8996554ebda93de6d4a3740e340ed07243a`; exact command and environment are in command.json. This ran the whole TestCapacityProducerWithRealPostgres in a fresh owned PostgreSQL/S3/OpenBao fixture after the five role scenarios passed and were cleaned up.

Actual harness exit 0, wall 90.857 seconds; Go package 79.525 seconds. The new compiled-shared-metadata-readers subtest passed in 1.77 seconds. Its original caller expiry, identity expiry and explicit cancellation after the permission-row lock passed in 0.40, 0.40 and 0.02 seconds respectively. Existing managed publication/download-session, account envelope, renewal, regional qualification and non-additive-refusal scenarios also passed; exact selections are retained in fleet.log/result.json.

The helper verifies the actual compiled metadata login's manifest/grants, constructs all seven typed adapters on one cold MaxConns7 pool configured under the unchanged32 governor, and performs concurrent exact-scope reads against the already published synthetic capture. It also checks excluded SQL operations, current identity scope, seven held connections with eighth acquisition expiry, reacquisition and joined cleanup. It does not measure saturation of the whole process governor or claim installed proof.

All 2750 harness inputs match the frozen commit and remained unchanged. cleanupFailures=[]; exact container IDs and exact network are independently absent. Raw readbacks are in owned-resource-checks.json and exact-network-readback.json. No retries or source changes occurred during either green fixture.

Protected Kubernetes/root and human inputs remain synthetic; SQL/TLS/SCRAM, encrypted custody/publication and service-provider execution are real. Full installed simplification qualification remains separate.
