package integration

import (
	"os"
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
