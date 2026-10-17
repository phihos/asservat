# ADR-091 — Protected fleet and owner configuration reconciliation

Date: 2026-10-11. Status: selected for implementation under continuing maintainer authorization. Requirements: REQ-FED-001, REQ-DEP-005, REQ-DB-005, REQ-DLD-003; part of TASK-02/07/11 and S-01/S-02.

## Problem

The owner runtime now loads real providers, but its integration fixture maintained configuration/recovery freshness through a fixture timer. An installed service needs independently scoped observation rather than granting the API process authority to accept its own configuration or recover a restored database. The existing plain fleet-settings reader also requires independently qualified protection before its output can drive SQL.

## Decision

Use the existing `hub-worker` application role for configuration reconciliation, separate from `hub-api`. Add a private installation-managed deployment projection, fixed rotating credential files and three independent SQL roles: fleet observation, owner-configuration observation, and owner-configuration audit acknowledgement. No role can clear recovery, replace the issuer epoch, accept a replacement source, enroll a peer or unwrap evidence. New installations still start suspended and recovery-blocked through database defaults.

Add `ProtectedFleetSettings`, composing the existing closed fleet-settings parser with the shared ConfigMap admission guard. Independently pin administrator actors, namespace UID, source UID, policy UID/generation and binding UID/resourceVersion. Verify actual enforcing admission using a separate non-administrator dry-run probe; an RBAC denial alone is insufficient. Read the exact source twice, require the same canonical revision, recheck admission and retain the earliest original interval. The ordinary parser remains observation-only and cannot establish protected writers on its own.

Run fleet and owner observation in independent serial loops under a shared cancellation root. Each call has at most five seconds and waits one second before another attempt, including after errors. Existing observers retain their own negative watermarks, encrypted audit gate and original deadlines. A delayed owner audit cannot stall fleet suspension checks. Shutdown cancels both loops and joins started work within six seconds. This finite cleanup bound does not make an uncooperative dependency safe; process termination remains the outer containment boundary.

Use the pinned client-go leader-election implementation with one installation-created, name/UID-pinned Kubernetes Lease to schedule this singleton work. Lease duration is fifteen seconds, renewal deadline ten seconds and retry interval two seconds. Runtime has only get/update on the exact Lease and never creates, deletes or adopts a replacement. Lease loss cancels observation and joins it. Do not release the Lease early while work may still be running; let the original record expire. Namespace replacement, deleting objects, incompatible/coordinated-election fields and excessive recorded duration are unavailable.

Leader election is scheduling, not authorization or strict fencing. [The upstream documentation](https://pkg.go.dev/k8s.io/client-go/tools/leaderelection) explicitly makes this distinction. Every observation must still carry current native protection, original freshness, source revision and monotonic SQL checks. A partition can create a temporary observation gap or overlapping candidates; it cannot clear recovery or extend a prior observation. The fifteen-second scheduling window does not extend the five-second source validity. Do not enable coordinated leader election or treat Lease timestamps as trusted observation time.

Normalize fleet observation/failure timestamps to PostgreSQL microseconds. Equal stored observation time may not extend a deadline, change the accepted revision or undo suspension/fencing. This closes the reproduced equal-timestamp extension before placing the observer in an autonomous loop.

## Dependencies and scope

Reuse the existing pinned client-go v0.37.0 dependency rather than implementing leader election. Its API has an upstream stability disclaimer and remains behind this small adapter. `go mod tidy` also declares the inherited go-difflib indirect dependency and adds a goleak checksum used by upstream tests. The runtime import graph includes `k8s.io/apimachinery/pkg/util/diff` and its established go-difflib implementation; it is not a newly selected product diff engine. Goleak is not in the runtime graph. Direct/indirect classifications were normalized without upgrading existing versions. Run the vulnerability and architecture gates against the actual expanded import graph.

No SQL migration, new public API, identity provider, broker or permission model is added. The worker's private startup input does not contain a recovery-approval switch. Installation-generated projections, credential provisioning, initial recovery acceptance, restore/checkpoint reconciliation and native in-Pod operation remain required. The chart remains configuration-only.

## Validation

Test exact Lease identity/CAS/no-creation and bounded record handling, independent serial observation during a blocked source, current provider loading and joined cancellation. The native fixture must use real Kubernetes admission and role grants, a real Lease, real SQL projection/audit roles, S3 and OpenBao. It must prove blocked initial recovery, automatic observation after one explicitly fixture-owned initial acceptance, source-protection loss and lease-loss shutdown without a fixture refresh timer. The separate SQL regression must reproduce equal-timestamp extension before the correction and reject it afterward. Record actual exits, unchanged hashes and cleanup in [implementation progress](../implementation-progress.md); none of these component checks completes the public investigation workflow.
