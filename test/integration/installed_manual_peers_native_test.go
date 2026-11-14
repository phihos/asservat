package integration

// ADR-283 manual-peers focus: one finite manual packet-header recording of
// the target Pod restricted to a Kubernetes peer. The installed journey's
// ordinary traffic reaches the target through the API server's Pod proxy
// (a node address outside the target namespace), and Kubernetes peers must
// name the target's own namespace. The focus therefore runs one synthetic
// client Pod in the target namespace that exchanges traffic with the target
// and selects it with a frozen resourceRef Pod peer. The proxy traffic keeps
// running in parallel, so the recording proves the peer filter excludes it.
const (
	manualPeersClient = "peer-client"
	manualPeersPort   = 8080
)

// manualPeersArguments is the public request: the builtin network profile
// (header-only packets) with a frozen resourceRef Pod peer on TCP 8080.
func manualPeersArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "packetPeers", "value": map[string]any{
						"entries":      []any{map[string]any{"resourceRef": map[string]any{"kind": "Pod", "namespace": namespace, "name": manualPeersClient}}},
						"protocol":     "tcp",
						"ports":        []int{manualPeersPort},
						"resolution":   "frozen",
						"maxEndpoints": 4,
						"maxStaleness": "5s",
					}},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "10s",
		},
	}
}
