package contracts

// CapacityValues are the Helm `capacity` values
// (specs/contracts/capacity.schema.json, ADR-335 D2 and D8). The chart
// resolves the evidenceStorage default; the hub-worker derives every other
// default. Sizes are Kubernetes quantities; share, limit and namespaceLimit
// also accept a percentage of the evidence storage.
type CapacityValues struct {
	EvidenceStorage    string                 `json:"evidenceStorage"`
	StorageAssurance   string                 `json:"storageAssurance,omitempty"`
	CapturesPerCluster int64                  `json:"capturesPerCluster,omitempty"`
	NamespaceLimit     string                 `json:"namespaceLimit,omitempty"`
	Workload           CapacityWorkloadValues `json:"workload,omitzero"`
}

type CapacityWorkloadValues struct {
	Share                  string             `json:"share,omitempty"`
	Limit                  string             `json:"limit,omitempty"`
	Dump                   CapacityDumpValues `json:"dump,omitzero"`
	MaxConcurrentExpensive int64              `json:"maxConcurrentExpensive,omitempty"`
	OnFull                 string             `json:"onFull,omitempty"`
}

type CapacityDumpValues struct {
	Burst                  int64 `json:"burst,omitempty"`
	MinimumIntervalSeconds int64 `json:"minimumIntervalSeconds,omitempty"`
}

// HubWorkerCapacity is the hub-worker's capacity section of HubWorkerConfig.
// Its child starts when the section is present: it initializes the capacity
// root once and reconciles the pool and per-cluster policies derived from
// the values.
type HubWorkerCapacity struct {
	CapacityValues
	// Revision is the Helm release revision; a helm upgrade raises it and
	// so applies changed values.
	Revision int64 `json:"revision"`
	// ProcessingSource names the Helm-rendered processing source ConfigMap
	// in the release namespace; its UID is read by name.
	ProcessingSource string `json:"processingSource"`
	// Paths are the installed download paths of the processing source
	// (ADR-192); empty when no regional download path is configured.
	Paths []DownloadEnvironmentPath `json:"paths"`
	// SharedQueries reserves shared context query capacity; true when
	// downloads (the publisher) are enabled.
	SharedQueries bool `json:"sharedQueries"`
	// RemoteClusters are the joined mode=cluster clusters (values clusters):
	// each is qualified once and observed from its connector's deliveries
	// (ADR-331).
	RemoteClusters []RemoteCluster `json:"remoteClusters,omitempty"`
}

// CapacityNamespaceKeys are the namespace label keys the capacity
// observation reads: the evidence opt-out label.
func CapacityNamespaceKeys() []string { return []string{"asservat.io/evidence"} }

// CapacityBackup is the internal backup profile of the capacity history and
// the connector backing.
func CapacityBackup() InstallerCapacityBackup {
	return InstallerCapacityBackup{HorizonSeconds: 1, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 1, WALCopies: 1}
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
