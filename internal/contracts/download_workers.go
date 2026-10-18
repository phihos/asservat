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

// DownloadWorkerAccountName is the worker Pods' account; it holds no rights.
func DownloadWorkerAccountName(installationID string) string {
	return downloadWorkerName(installationID, "-download-worker")
}

// DownloadWorkerPriorityClassName is the cluster-scoped zero-priority,
// non-preempting class the worker template names (ADR-069).
func DownloadWorkerPriorityClassName(installationID string) string {
	return downloadWorkerName(installationID, "-download-worker")
}

// DownloadWorkerControlName is the immutable worker.json control ConfigMap.
func DownloadWorkerControlName(installationID string) string {
	return downloadWorkerName(installationID, "-download-worker-control")
}

// DownloadWorkerStoreName is the immutable store credential Secret
// (credentials.json), the only place the download evidence principal lives.
func DownloadWorkerStoreName(installationID string) string {
	return downloadWorkerName(installationID, "-download-worker-store")
}

// DownloadWorkerProfileName is the guarded worker-profile.json source and
// DownloadWorkerProfileGuardName its administrator admission guard (ADR-070).
func DownloadWorkerProfileName(installationID string) string {
	return downloadWorkerName(installationID, "-worker-profile")
}
func DownloadWorkerProfileGuardName(installationID string) string {
	return DownloadWorkerProfileName(installationID) + "-guard"
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
func NativeKubernetesTokenFile(clusterID, namespace string) string {
	return "native-kube-" + clusterID + "-" + namespace + ".token"
}
func NativeKubernetesProbeTokenFile(clusterID, namespace string) string {
	return "native-kube-probe-" + clusterID + "-" + namespace + ".token"
}
