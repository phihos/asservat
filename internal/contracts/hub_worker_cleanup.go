package contracts

// HubWorkerCleanup is the hub-worker's cleanup section of HubWorkerConfig: the
// capture/normal/resolution operation audit retirement. Its presence starts
// the child; it holds no values. The child uses the worker's PostgreSQL,
// audit store and audit Transit key, the four cleanup roles of
// HubWorkerProvider.Roles and the HubWorkerProvider.ContextDeletionSigning
// key. The permission root is the generated PermissionRootID; the audit store
// ID and the signing key's versions are read from SQL and OpenBao at startup.
type HubWorkerCleanup struct {
}

// Fixed files under HubWorkerDeploymentRoot for the cleanup child.
const (
	// HubWorkerCleanupStorageFile is the cleanup object-store principal
	// (`<name>-s3-operation-cleanup`, key credentials.json).
	HubWorkerCleanupStorageFile = "cleanup-storage.json"
	// HubWorkerCleanupVerifyStorageFile is the independent verification
	// principal (`<name>-s3-operation-verify`, key credentials.json).
	HubWorkerCleanupVerifyStorageFile = "verify-storage.json"
)
