package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/pprof/profile"
)

const manualHeapProfileName = "go-heap-snapshot"

// This selector belongs only to the installed fixture; it never reaches a
// product configuration or changes the existing manual-profile focus/budget.
func installedHeapProfileVariant() bool {
	switch variant := os.Getenv("ASSERVAT_PROFILE_VARIANT"); variant {
	case "", "cpu":
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

func qualifyManualHeapNative(t *testing.T, ctx context.Context, native []byte, captureID string) {
	t.Helper()
	p, err := profile.ParseData(native)
	if err != nil || p.CheckValid() != nil || len(p.Sample) == 0 || p.DurationNanos != 0 {
		t.Fatal("downloaded heap snapshot is invalid or invents a sampling duration", err)
	}
	const path = "../results/manual-heap.pb.gz"
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(ctx, "go", "tool", "pprof", "-top", "-sample_index=inuse_space", "-symbolize=none", path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "main.main") {
		t.Fatalf("native pprof cannot open retained fixture heap allocation samples: %v\n%s", err, out)
	}
	if err := os.WriteFile("../results/manual-heap-pprof.txt", out, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("manual heap %s: %d authenticated native bytes, %d samples, native snapshot duration unknown; go tool pprof opened inuse_space without symbol lookup", captureID, len(native), len(p.Sample))
}
