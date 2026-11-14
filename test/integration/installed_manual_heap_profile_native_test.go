package integration

import (
	"os"
)

const manualHeapProfileName = "go-heap-snapshot"

// This selector belongs only to the installed fixture; it never reaches a
// product configuration or changes the existing manual-profile focus/budget.
func installedHeapProfileVariant() bool {
	switch variant := os.Getenv("ASSERVAT_PROFILE_VARIANT"); variant {
	case "", "cpu":
		return false
	case "accepted-heavy":
		if installedJourneyFocus() != "profile-comparison" {
			panic("accepted-heavy fixture variant requires profile-comparison focus")
		}
		return false
	case "trace":
		if installedJourneyFocus() != "manual-profile" {
			panic("trace fixture variant requires manual-profile focus")
		}
		return false
	case "heap":
		if installedJourneyFocus() != "manual-profile" {
			panic("heap fixture variant requires manual-profile focus")
		}
		return true
	default:
		panic("unknown installed profile fixture variant: " + variant)
	}
}

func manualHeapProfileArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components":    []any{map[string]any{"id": "heap", "profileRef": map[string]string{"catalog": "namespace", "name": manualHeapProfileName, "version": "v1"}}},
			"maxTotalBytes": 16 << 20, "maxDuration": "15s",
		},
	}
}
