package integration

// Installed producer helpers: every acceptance, grant, start and stop goes
// through the existing product API. SQL below is independent readback only.

func installedLivePolicyGrantInput(name, id, projection string) map[string]any {
	out := map[string]any{"policy_name": name, "policy_uid": id, "idempotency_key": "live-policy-review-" + id, "lifetime_seconds": 300, "limits": map[string]any{"max_executions": 2, "max_collected_bytes": 16 << 20, "max_observed_bytes": 0}}
	// Observed bytes are granted only with an observation window (HTTP).
	if projection == "httpHeaders" {
		out["limits"].(map[string]any)["max_observed_bytes"] = 128 << 20
		out["observation_limits"] = map[string]any{"max_session_seconds": 300, "max_observed_bytes": 128 << 20, "max_bytes_per_second": 16 << 20, "max_concurrent_sessions": 1}
	}
	return out
}
