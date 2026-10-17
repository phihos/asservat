# ADR117 fixture cleanup status correction

Frozen two-file fixture-only patch. Product policy and runtime code are unchanged.

Upstream Kubernetes VAP dispatcher first formats an admission.NewForbidden error, then replaces its Reason/Code with the policy reason, defaulting to Invalid/422, and appends the exact policy/binding denial in Status.Details.Causes. Thus the native log said forbidden while apierrors.IsForbidden correctly returned false. See k8s.io/apiserver@v0.37.1/pkg/admission/plugin/policy/validating/dispatcher.go:309-316.

Cleanup now accepts only structured Status Invalid/422 or Forbidden/403 carrying the exact removed policy name, same binding and canonical continuity denial cause. String-only, other-policy/binding, generic invalid or500 errors do not qualify. Existing original UID preconditions and thirty-second cleanup bound remain unchanged.

The meaningful unit regression reproduces the upstream status override, explicitly asserts IsForbidden=false, requires the exact structured case to be recognized and rejects unrelated errors. Focused race terminal0,1.051s. Native not rerun here; the parent second native run remains overall FAIL despite its fourteen passing functional subtests. Parent must rerun TestInitialPreparationSupervisorWithRealKubernetes and confirm teardown.

Command: TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -race -p 2 -overlay=/home/phil/.cache/asservat-build/planning/initial-preparer-cleanup-status-20261012/overlay.json ./test/integration -run '^TestInitialPreparationCleanupStatus$' -count=1
