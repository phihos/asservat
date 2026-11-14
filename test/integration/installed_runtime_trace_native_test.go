package integration

import (
	"bytes"
	"context"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"github.com/google/pprof/profile"
)

const manualRuntimeTraceName = "go-runtime-trace"

func installedRuntimeTraceVariant() bool {
	// Reuse the closed selector's validation even when this is not a trace.
	installedHeapProfileVariant()
	return os.Getenv("ASSERVAT_PROFILE_VARIANT") == "trace"
}

func manualRuntimeTraceArguments(cluster, namespace, workload string) map[string]any {
	args := manualHeapProfileArguments(cluster, namespace, workload)
	c := args["profile_composition"].(map[string]any)
	c["components"] = []any{map[string]any{"id": "trace", "profileRef": map[string]string{"catalog": "namespace", "name": manualRuntimeTraceName, "version": "v1"}}}
	c["maxTotalBytes"], c["maxDuration"] = 32<<20, "20s"
	return args
}
func manualRuntimeTraceDefinition() (map[string]any, error) {
	d, err := manualHeapProfileDefinition()
	if err != nil {
		return nil, err
	}
	d["displayName"], d["description"] = "Go runtime trace", "Finite Go scheduler and execution trace."
	r := d["recipe"].(map[string]any)
	r["description"], r["maxDuration"], r["maxTotalBytes"] = d["description"], "20s", 32<<20
	a := r["actions"].([]any)[0].(map[string]any)
	a["id"] = "trace"
	p := a["parameters"].(map[string]any)
	p["type"], p["mode"], p["duration"], p["forceGC"] = "runtimeTrace", "interval", "5s", false
	l := a["limits"].(map[string]any)
	l["maxBytes"], l["timeout"] = 32<<20, "10s"
	d["editableFields"] = []any{map[string]any{"actionID": "trace", "field": "actionMaxBytes", "label": "Output limit"}}
	return d, nil
}

func validateManualRuntimeTrace(ctx context.Context, native []byte, path string) ([]byte, error) {
	if err := diagnostics.CheckGoTrace(bytes.NewReader(native)); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, native, 0600); err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := installedOutput(call, installedLocalToolTimeout, "go", "tool", "trace", "-pprof=sched", path)
	if err != nil {
		return nil, err
	}
	p, err := profile.ParseData(out)
	if err != nil {
		return nil, err
	}
	if err = p.CheckValid(); err != nil {
		return nil, err
	}
	return out, nil
}
