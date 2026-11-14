package integration

// ADR-282 manual-http focus: the namespace CaptureProfile "http-capture" v1
// is the builtin network profile republished with an httpHeaders profile at
// the specified defaults (and maxima): 1024 flows, 32 KiB header block,
// 256 KiB per flow, 16 MiB total reassembly, 30 s idle timeout.
const (
	manualHTTPProfileName    = "http-capture"
	manualHTTPProfileVersion = "v1"
)

// manualHTTPArguments is the public finite HTTP header request: one
// on-trigger action, no history, five seconds after start, a reviewed filter.
// Unlike raw output, the extract downloads under ordinary eligibility, so the
// request carries no result_access.
func manualHTTPArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "namespace", "name": manualHTTPProfileName, "version": manualHTTPProfileVersion},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
					map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "5s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "15s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "15s",
		},
	}
}
