package contracts

import (
	"time"
)

// InitialSchemaMaxHead bounds the five-digit migration identifier carried as
// public provenance. It is not a supported-release selector: SQL/bootstrap
// independently require the exact compiled bundle head and digest.
const InitialSchemaMaxHead int64 = 99999

// This protected public plan is installed in the stable bootstrap namespace.
// It contains no credentials, secret-payload digests, provider replies or evidence.
type InitialPreparationPlan struct {
	SchemaInitialization string                     `json:"schemaInitialization,omitempty"`
	Handover             string                     `json:"handover,omitempty"`
	HistoryManager       *InitialSQLHistoryManager  `json:"historyManager,omitempty"`
	HistoryProbe         *WorkerObjectReference     `json:"historyProbe,omitempty"`
	ProbeAudience        string                     `json:"probeAudience,omitempty"`
	PrivateState         *WorkerObjectReference     `json:"privateState,omitempty"`
	Continuation         string                     `json:"continuation,omitempty"`
	InstallationID       string                     `json:"installationID"`
	RequestID            string                     `json:"requestID"`
	ClusterID            string                     `json:"clusterID"`
	BootstrapNamespace   WorkerObjectReference      `json:"bootstrapNamespace"`
	RootName             string                     `json:"rootName"`
	ProbeName            string                     `json:"probeName"`
	ContinuityName       string                     `json:"continuityName"`
	Administrators       []OwnerDeploymentActor     `json:"administrators"`
	Workload             InitialPreparationWorkload `json:"workload"`
}

// InitialSQLHistoryManager pins the separately trusted original SQL setup manager.
// This public identity is bound by the protected plan before role creation.
type InitialSQLHistoryManager struct {
	Name string `json:"name"`
	OID  uint32 `json:"oid"`
}

type InitialPreparationWorkload struct {
	Namespace              string `json:"namespace"`
	Name                   string `json:"name"`
	WriterAccount          string `json:"writerAccount"`
	ProbeAccount           string `json:"probeAccount"`
	Configuration          string `json:"configuration"`
	Credentials            string `json:"credentials"`
	Image                  string `json:"image"`
	RegistryAuthentication string `json:"registryAuthentication,omitempty"`
	Witness                string `json:"witness"`
	FleetSource            string `json:"fleetSource"`
	WitnessGuard           string `json:"witnessGuard"`
	FleetGuard             string `json:"fleetGuard"`
	WorkloadGuard          string `json:"workloadGuard"`
	StagingGuard           string `json:"stagingGuard"`
	Journal                string `json:"journal"`
}

type InitialPreparer struct {
	Providers   *InitialProviderProfile     `json:"providers,omitempty"`
	SQLMaterial *WorkerObjectReference      `json:"sqlMaterial,omitempty"`
	Services    *InitialPreparationServices `json:"services,omitempty"`
	Format      string                      `json:"format"`
	Plan        InitialPreparationPlan      `json:"plan"`
	RootUID     string                      `json:"rootUID"`
	Continuity  OwnerDeploymentGuard        `json:"continuity"`
	Staging     OwnerDeploymentGuard        `json:"staging"`
	Kubernetes  OwnerProviderEndpoint       `json:"kubernetes"`
}

type InitialPreparationPodRequestCompletion struct {
	Outcome     string    `json:"outcome"`
	CompletedAt time.Time `json:"completedAt"`
}

// Closed public desired input. Private replies and credentials remain separate.
type InitialPreparationServices struct {
	Format string        `json:"format"`
	Fleet  FleetSettings `json:"fleet"`
	// IssuerEpoch accompanies Fleet; fleet.json no longer carries it.
	IssuerEpoch string                  `json:"issuerEpoch"`
	Kubernetes  OwnerProviderEndpoint   `json:"kubernetes"`
	Postgres    OwnerPostgresEndpoint   `json:"postgres"`
	AuditStore  OwnerAuditStore         `json:"auditStore"`
	KeyService  ConfigurationKeyService `json:"keyService"`
}

// InitialPreparationSchema binds one initial, empty-database setup. It is public
// provenance only; no field authorizes activation, recovery or schema rollback.
type InitialPreparationSchema struct {
	AttemptID    string                   `json:"attemptID"`
	BundleDigest string                   `json:"bundleDigest"`
	Head         int64                    `json:"head"`
	DatabaseOID  uint32                   `json:"databaseOID"`
	PostmasterAt time.Time                `json:"postmasterAt"`
	DDLRole      InitialSQLHistoryManager `json:"ddlRole"`
	Manager      InitialSQLHistoryManager `json:"manager"`
	ClaimedAt    time.Time                `json:"claimedAt"`
	CompletedAt  *time.Time               `json:"completedAt,omitempty"`
}
