# Native ADR117 correction

Frozen two-file patch against current integrated117. Original12-file package is unchanged.

Native first run failed target Namespace deletion: Namespace REST requests populate request.namespace with their own name. The generated key matcher had required empty namespace for cluster-wide Namespace resources. The fix omits only that irrelevant comparison for core namespaces while retaining exact group/resource/name. All ordinary namespaced and cluster-RBAC constraints are unchanged. Added native bootstrap Namespace deletion regression; target regression already failed before the fix. Upstream local source k8s.io/apiserver@v0.37.1/pkg/endpoints/request/requestinfo.go lines191-203 explicitly populates this field.

Fixture cleanup previously deleted its policy/binding then immediately removed occupied objects while the admission cache still enforced the removed policy. Cleanup now retries only a definite Forbidden attributed to the exact owned continuity policy, with unchanged original UID preconditions and existing30-second cleanup deadline. Other errors still fail cleanup; no product guard, deadline or permission is relaxed.

Verification: focused Kubernetes/integration race compiled and passed (12.503s/1.054s); native integration skipped without owned fixture. No real API rerun by this agent. Original parent run remains a failure; qualification awaits parent native rerun of TestInitialPreparationSupervisorWithRealKubernetes.

Command: TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -race -p 2 -overlay=/home/phil/.cache/asservat-build/planning/initial-preparer-native-fix-20261011/overlay.json ./internal/adapters/kubernetes ./test/integration -run 'TestInitialPreparer|TestInitialPreparationSupervisorWithRealKubernetes' -count=1
