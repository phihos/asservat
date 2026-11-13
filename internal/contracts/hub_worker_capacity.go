package contracts

// HubWorkerCapacity is the hub-worker's capacity section of HubWorkerConfig.
// Its child starts when the section is present. The embedded settings are the
// Helm `capacity` values (the former bootstrap.continuation.public.capacity
// group, same field names); the hub-worker initializes the capacity root from
// them once and then reconciles the EvidenceStoragePool/EvidenceBudgetPolicy
// sources named by Pool and Policy.
type HubWorkerCapacity struct {
	InstallerCapacitySettings
	// ProcessingSource names the Helm-rendered processing source ConfigMap
	// in the release namespace; its UID is read by name.
	ProcessingSource string `json:"processingSource"`
	// Paths are the installed download paths of the processing source
	// (ADR-192); empty when no regional download path is configured.
	Paths []DownloadEnvironmentPath `json:"paths"`
	// SharedQueries reserves shared context query capacity; true when
	// downloads (the publisher) are enabled.
	SharedQueries bool `json:"sharedQueries"`
}

// Fixed capacity files under HubWorkerDeploymentRoot.
const (
	// HubWorkerCaptureAccountKeyFile is the raw 32-byte capture account MAC
	// key: key `accountKey` of the `<name>-audit-mac` Secret. Its version is
	// InstallationIDs.RoleSetupID + "-account/v1".
	HubWorkerCaptureAccountKeyFile = "capture-account.key"
	// Capacity SQL logins in the `<name>-sql-hub-worker` Secret.
	HubWorkerCapacitySQLFile        = "sql-capacity.json"
	HubWorkerCapacityCaptureSQLFile = "sql-capacity-capture.json"
)
