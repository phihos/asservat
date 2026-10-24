# Frozen candidate SQL role qualification

Commit: `c6be50caf35c904bccd2e44c5d773652dd9752a9`.

The exact command and environment are in command.json. The owned PostgreSQL/S3/OpenBao fixture ran the five selected public-runtime-role cases. Harness exit 1, wall 33.875 seconds; Go package 19.506 seconds. Matrix failed during whole-inventory `verify` (6.11 seconds); unknown-claim, lost-completion, held-lock and recovery-after-lock passed. The lost-completion case includes complete compiled role creation/reconciliation and runtime grant verification. The subsequent seven-reader fixture was not started.

All 2750 harness inputs matched this commit before and after; sourceUnchangedDuringTest is true. cleanupFailures is empty. Independent direct readback confirms all three exact container IDs and the exact network absent; label-scoped container/network lists are empty.

The original wrapper result.json and owned-resource-checks.json are preserved: their ownedResourcesAbsent false is a wrapper diagnostic parsing error, because Docker returned lowercase `no such object`. cleanup-readback.json contains fresh raw subprocess outputs and the corrected absence verdict, also accepting Docker's exact named-network `not found` message. This does not change the failing test outcome.

The full test log and PostgreSQL provider log are retained. No provider timeout/cancellation/deadlock/connection-limit messages were found. The original closed `verify` error does not distinguish final inventory deadline from expired fixture fleet observation. The matrix refreshes that synthetic observation once to five seconds before the complete 81-role call. No exact failure cause is claimed yet; a subsequent test-only diagnostic has been prepared separately, not executed here.

Real SQL/TLS/SCRAM, S3 and OpenBao are exercised. Protected Kubernetes/root and human inputs are synthetic; this is not installed-workflow qualification.
