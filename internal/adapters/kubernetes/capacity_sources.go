package kubernetes

import "strings"

// CapacitySourceNames are the fixed names derived from the installation.
func CapacitySourceNames(installation string) (guard, namespaceGuard, probeNamespace, processingSource, processingGuard string) {
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	return prefix + "-capacity-guard", prefix + "-capacity-ns-guard", prefix + "-capacity-probe", installedProcessingSource(installation), prefix + "-processing-guard"
}
