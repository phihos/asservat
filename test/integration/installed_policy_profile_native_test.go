package integration

const installedPolicyProfileName = "regional-finite-go-profile"
const installedPolicyProfileLimit = int64(16 << 20)

func installedPolicyProfileSpec(cluster, namespace, workload string) map[string]any {
	spec := installedPolicyRecordingSpec(cluster, namespace, workload)
	spec["profileComposition"] = manualProfileArguments(cluster, namespace, workload)["profile_composition"]
	return spec
}

func installedPolicyProfileBinding(original map[string]any) map[string]any {
	binding := installedPolicyArgumentsBinding(original)
	binding["metadata"].(map[string]any)["name"] = "policy-profile-automation"
	spec := binding["spec"].(map[string]any)
	spec["reason"] = "finite installed policy profile qualification"
	spec["automation"] = map[string]any{"allowedActions": []any{"profile"}, "maxLifetimeSeconds": 3600, "maxExecutions": 1, "maxBytes": installedPolicyProfileLimit, "maxObservedBytes": 0}
	return binding
}

func installedPolicyProfileGrantInput(policyUID string) map[string]any {
	return map[string]any{"policy_name": installedPolicyProfileName, "policy_uid": policyUID, "idempotency_key": "native-policy-profile-collection", "lifetime_seconds": 600,
		"limits": map[string]any{"max_executions": 1, "max_collected_bytes": installedPolicyProfileLimit, "max_observed_bytes": 0}}
}

func installedPolicyProfileRawInput(caseID, digest string, nativeBytes int64) map[string]any {
	return map[string]any{"case_id": caseID, "artifact_digests": []string{digest}, "operations": []string{"download_artifact"}, "reason": "Inspect the synthetic policy CPU profile locally.", "max_bytes": nativeBytes, "expires_in_seconds": 300, "idempotency_key": "native-policy-profile-raw"}
}
