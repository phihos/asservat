package integration

import (
	"encoding/json"
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

func manualHeapProfileDefinition() (map[string]any, error) {
	raw, err := os.ReadFile("../../internal/application/planning/profiles/go-cpu-v1.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Definition map[string]any `json:"definition"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	doc.Definition["displayName"] = "Go heap allocation snapshot"
	doc.Definition["description"] = "Heap allocation samples without forcing garbage collection."
	recipe := doc.Definition["recipe"].(map[string]any)
	recipe["description"] = doc.Definition["description"]
	recipe["maxDuration"] = "15s"
	action := recipe["actions"].([]any)[0].(map[string]any)
	action["id"] = "heap"
	parameters := action["parameters"].(map[string]any)
	parameters["type"], parameters["mode"], parameters["forceGC"] = "heap", "snapshot", false
	delete(parameters, "duration")
	action["limits"].(map[string]any)["timeout"] = "5s"
	doc.Definition["editableFields"] = []any{map[string]any{"actionID": "heap", "field": "actionMaxBytes", "label": "Output limit"}}
	return doc.Definition, nil
}
