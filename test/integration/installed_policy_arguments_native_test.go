package integration

import "asservat.local/asservat/internal/domain/artifact"

const installedPolicyArgumentsName = "regional-finite-arguments"

// Authored operator inputs only: accepted scope, mechanism pins and authority
// are produced by the installed catalog/compiler/approval pipeline.
func installedPolicyArgumentsSpec(cluster, namespace, workload string) map[string]any {
	spec := installedPolicyRecordingSpec(cluster, namespace, workload)
	spec["profileComposition"] = manualArgumentsCaptureInput(cluster, namespace, workload, false)["profile_composition"]
	return spec
}

func installedPolicyArgumentsBinding(original map[string]any) map[string]any {
	return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "policy-argument-automation"}, "spec": map[string]any{
		"effect": "Allow", "subjects": original["subjects"], "roles": []any{"workload-maintainer", "evidence-owner"}, "scope": original["scope"], "reason": "finite installed policy argument qualification",
		"automation": map[string]any{"allowedActions": []any{"syscallTrace"}, "maxLifetimeSeconds": 3600, "maxExecutions": 1, "maxBytes": artifact.RecordingNativeLimit, "maxObservedBytes": 128 << 20, "maxObservedEvents": 10000},
	}}
}

func installedPolicyArgumentsGrantInput(policyUID string) map[string]any {
	return map[string]any{
		"policy_name": installedPolicyArgumentsName, "policy_uid": policyUID, "idempotency_key": "native-policy-arguments-collection", "lifetime_seconds": 600,
		"limits":             map[string]any{"max_executions": 1, "max_collected_bytes": artifact.RecordingNativeLimit, "max_observed_bytes": 128 << 20, "max_observed_events": 10000},
		"observation_limits": map[string]any{"max_session_seconds": 15, "max_observed_bytes": 128 << 20, "max_observed_events": 10000, "max_bytes_per_second": 16 << 20, "max_concurrent_sessions": 1},
	}
}

func installedPolicyArgumentsRawInput(caseID, digest string, nativeBytes int64) map[string]any {
	return map[string]any{"case_id": caseID, "artifact_digests": []string{digest}, "operations": []string{"download_artifact"}, "reason": "Inspect the synthetic policy write arguments locally.", "max_bytes": nativeBytes, "expires_in_seconds": 300, "idempotency_key": "native-policy-arguments-raw"}
}
