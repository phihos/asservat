package contracts

// InstallerCapacitySettings is the operator's capacity profile (ADR-190):
// every value a qualified deployment supplies. The installer mints the
// identities and derives the root, account version, pool UID, guard digests,
// processing source and slot arithmetic; it invents no measured value.
type InstallerCapacitySettings struct {
	Pool                string                      `json:"pool"`
	Policy              string                      `json:"policy"`
	NamespaceKeys       []string                    `json:"namespaceKeys"`
	Accounts            int64                       `json:"accounts"`
	Records             int64                       `json:"recordsPerAccount"`
	AdmissionSeconds    int64                       `json:"admissionSeconds"`
	Lanes               InstallerCapacityLanes      `json:"lanes"`
	StopRetainedSeconds int64                       `json:"stopRetainedSeconds"`
	Backup              InstallerCapacityBackup     `json:"backup"`
	Footprints          InstallerCapacityFootprints `json:"footprints"`
	PurgeLeases         int64                       `json:"purgeLeases"`
	Processing          InstallerCapacityProcessing `json:"processing"`
	Metadata            InstallerCapacityMetadata   `json:"metadata"`
	Envelope            InstallerCapacityEnvelope   `json:"envelope"`
	Backends            []InstallerCapacityBackend  `json:"backends"`
}

type InstallerCapacityLane struct {
	Accounts        int64 `json:"accounts"`
	Records         int64 `json:"recordsPerAccount"`
	RetainedSeconds int64 `json:"retainedSeconds"`
}

// Capture uses the top-level accounts and records.
type InstallerCapacityLanes struct {
	CaptureRetainedSeconds int64                 `json:"captureRetainedSeconds"`
	Normal                 InstallerCapacityLane `json:"normal"`
	Resolution             InstallerCapacityLane `json:"resolution"`
	Processing             InstallerCapacityLane `json:"processing"`
}

type InstallerCapacityBackup struct {
	HorizonSeconds       int64 `json:"horizonSeconds"`
	CleanupBudgetSeconds int64 `json:"cleanupBudgetSeconds"`
	ProofWindowSeconds   int64 `json:"proofWindowSeconds"`
	BackupCopies         int64 `json:"backupCopies"`
	WALCopies            int64 `json:"walCopies"`
}

type InstallerCapacityFootprint struct {
	RowBytes           int64 `json:"rowBytes"`
	TransitionWALBytes int64 `json:"transitionWALBytes"`
}

// Operator-qualified history footprints; no release measurement exists.
type InstallerCapacityFootprints struct {
	Capture    InstallerCapacityFootprint `json:"capture"`
	Operation  InstallerCapacityFootprint `json:"operation"`
	Processing InstallerCapacityFootprint `json:"processing"`
	Native     InstallerCapacityFootprint `json:"native"`
	Stop       InstallerCapacityFootprint `json:"stop"`
	// ProcessingState is the processing root history (at least 16 KiB rows),
	// distinct from the processing release audit lane above.
	ProcessingState InstallerCapacityFootprint `json:"processingState"`
}

type InstallerCapacityProcessing struct {
	MaxRules           int64 `json:"maxRules"`
	MaxRootTransitions int64 `json:"maxRootTransitions"`
}

type InstallerCapacityMetadata struct {
	FixedRowBytes            int64 `json:"fixedRowBytes"`
	AccountRowBytes          int64 `json:"accountRowBytes"`
	RecordRowBytes           int64 `json:"recordRowBytes"`
	RecordWALBytes           int64 `json:"recordWALBytes"`
	RecordKeyAttempts        int64 `json:"recordKeyAttempts"`
	TransitionWALBytes       int64 `json:"transitionWALBytes"`
	ConfigurationTransitions int64 `json:"configurationTransitions"`
}

type InstallerCapacityAmount struct {
	Bytes   int64 `json:"bytes"`
	Objects int64 `json:"objects"`
}

type InstallerCapacityEnvelope struct {
	SystemObjects InstallerCapacityAmount `json:"systemObjects"`
	SQLBytes      int64                   `json:"sqlBytes"`
	BackupBytes   int64                   `json:"backupBytes"`
	WALBytes      int64                   `json:"walBytes"`
	KeyAttempts   int64                   `json:"keyAttempts"`
}

type InstallerCapacityBackend struct {
	StorageProfile string                  `json:"storageProfile"`
	Usable         InstallerCapacityAmount `json:"usable"`
}
