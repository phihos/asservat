package contracts

import "strings"

// ADR-204 decision 1: the installed download workers' hub-cluster objects.
// Every name derives from the separately validated installation UUID; the
// installer resolves UIDs and pins them, no download caller names any.
func downloadWorkerName(installationID, suffix string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + suffix
}

// DownloadWorkerNamespaceName is the workers' own namespace (Pod Security
// restricted). Workers never run in the hub namespace.
func DownloadWorkerNamespaceName(installationID string) string {
	return downloadWorkerName(installationID, "-downloads")
}

// WorkerConfigurationAuditKeyName is the worker configuration observer's own
// audit Transit key (ADR-204 decision 7), on the configuration audit mount.
func WorkerConfigurationAuditKeyName(installationID string) string {
	return downloadWorkerName(installationID, "-worker-configuration-audit")
}

// NativeKubernetesTokenFile and NativeKubernetesProbeTokenFile are a pinned
// worker API's two token files in the owner's backend projection: the API
// client and the worker profile guard's separate probe. They are keyed by
// cluster UUID and namespace name, both fixed before the namespace exists, so
// the installed owner template, pinned before the worker namespace is
// created, can project them; every client still checks the pinned namespace
// UID on each read.
// NativeKubernetesTokenFile names the projected token for a worker
// namespace; Helm renders it, so it carries no generated ID.
func NativeKubernetesTokenFile(_, namespace string) string {
	return "native-kube-" + namespace + ".token"
}
func NativeKubernetesProbeTokenFile(clusterID, namespace string) string {
	return "native-kube-probe-" + clusterID + "-" + namespace + ".token"
}
