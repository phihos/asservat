package integration

func manualProfileArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components":    []any{map[string]any{"id": "cpu", "profileRef": map[string]string{"catalog": "builtin", "name": "go-cpu", "version": "v1"}}},
			"maxTotalBytes": 16 << 20, "maxDuration": "30s",
		},
	}
}
