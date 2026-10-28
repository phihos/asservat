package integration

// These are authored inputs for the forthcoming guarded installed focus. They
// contain no accepted scope, authority, Pod/capture identity or fixture permit.
// The production source/compiler and public grant service must derive those.
const installedPolicyRecordingName = "regional-finite-packets"
const installedPolicyRecordingFilter = "tcp[13] & 16 != 0"

func installedPolicyRecordingComposition() map[string]any {
	return map[string]any{
		"components": []any{map[string]any{"id": "network", "profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": []any{
			map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
			map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
			map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"},
			map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
			map[string]any{"actionID": "sample", "field": "packetFilter", "value": installedPolicyRecordingFilter},
		}}}, "maxTotalBytes": 16 << 20, "maxDuration": "10s",
	}
}

func installedPolicyRecordingSpec(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target":    map[string]any{"cluster": cluster, "namespace": namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "crashed", "kind": "exit", "options": map[string]any{"reasons": []any{"Error", "OOMKilled"}}}},
		"when":      map[string]any{"detector": "crashed"}, "profileComposition": installedPolicyRecordingComposition(),
		"budgets":   map[string]any{"cooldown": "5s", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": "10m", "suspended": false, "observation": map[string]any{"mode": "allAuthorized"},
		"evaluation": map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"},
	}
}

func installedPolicyRecordingGrantArguments(policyUID, key string) map[string]any {
	return map[string]any{
		"policy_name": installedPolicyRecordingName, "policy_uid": policyUID, "idempotency_key": key, "lifetime_seconds": 600,
		"limits":             map[string]any{"max_executions": 2, "max_collected_bytes": 16 << 20, "max_observed_bytes": 128 << 20},
		"observation_limits": map[string]any{"max_session_seconds": 10, "max_observed_bytes": 64 << 20, "max_bytes_per_second": 16 << 20, "max_concurrent_sessions": 1},
	}
}
