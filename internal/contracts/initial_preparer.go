package contracts

import (
	"io"
	"time"
)

const InitialSchemaProtocol = "asservat-initial-schema/v1"

const InitialPreparerFormat = "asservat-initial-preparer/v1"
const InitialPreparationRootFormat = "asservat-initial-preparation-root/v1"
const InitialPreparationActivationProtocol = "asservat-initial-preparation-activation/v1"
const InitialPreparationHandoverProtocol = "asservat-initial-preparation-handover/v1"

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

// Entries use ADR-102's one-pending-intent representation. An acknowledged
// receipt never changes. Retired identities stay occupied for this installation.
type InitialPreparationRoot struct {
	Schema         *InitialPreparationSchema     `json:"schema,omitempty"`
	Activation     *InitialPreparationActivation `json:"activation,omitempty"`
	Format         string                        `json:"format"`
	InstallationID string                        `json:"installationID"`
	RequestID      string                        `json:"requestID"`
	PlanDigest     string                        `json:"planDigest"`
	RootUID        string                        `json:"rootUID"`
	Phase          string                        `json:"phase"`
	Creates        []InitialPreparationCreate    `json:"creates"`
}

func DecodeInitialPreparer(r io.Reader) (InitialPreparer, error) {
	return decodeClosedRPC[InitialPreparer](r, InitialPreparationMaxBytes)
}
func DecodeInitialPreparationRoot(r io.Reader) (InitialPreparationRoot, error) {
	return decodeClosedRPC[InitialPreparationRoot](r, InitialPreparationMaxBytes)
}

// A finite typed continuation; this is provenance, never activation authority.
// The declared capability is pinned before first CREATE in the public plan.
type InitialPreparationActivation struct {
	Handover    *InitialPreparationHandover          `json:"handover,omitempty"`
	Inputs      *InitialPreparationPublicInputs      `json:"inputs,omitempty"`
	Pod         *InitialPreparationPod               `json:"pod,omitempty"`
	Credentials *InitialPreparationCredentialBinding `json:"credentials,omitempty"`
}

const InitialPreparationPodRequests = 16

type InitialPreparationPod struct {
	Requests       []InitialPreparationPodRequest `json:"requests"`
	OperationID    string                         `json:"operationID"`
	TemplateDigest string                         `json:"templateDigest"`
	Receipt        *InitialPreparationReceipt     `json:"receipt,omitempty"`
	SpecDigest     string                         `json:"specDigest,omitempty"`
}

// Public binding only: no private bytes or digest of a secret payload. Once
// accepted, these exact original dates are retained even after expiry.
type InitialPreparationCredentialBinding struct {
	Material      WorkerObjectReference `json:"material"`
	StartupDigest string                `json:"startupDigest"`
	NotBefore     time.Time             `json:"notBefore"`
	NotAfter      time.Time             `json:"notAfter"`
}

// One concrete HTTP CREATE invocation. A positive completion applies only to
// this request; observing the same Pod later never completes another request.
// The finite owner identifier is provenance, not authentication or authority.
type InitialPreparationPodRequest struct {
	ID         string                                  `json:"id"`
	OwnerID    string                                  `json:"ownerID"`
	StartedAt  time.Time                               `json:"startedAt"`
	Until      time.Time                               `json:"until"`
	Completion *InitialPreparationPodRequestCompletion `json:"completion,omitempty"`
}
type InitialPreparationPodRequestCompletion struct {
	Outcome     string    `json:"outcome"`
	CompletedAt time.Time `json:"completedAt"`
}

const InitialPreparationServicesFormat = "asservat-initial-preparation-services/v1"

// Closed public desired input. Private replies and credentials remain separate.
type InitialPreparationServices struct {
	Format     string                  `json:"format"`
	Fleet      FleetSettings           `json:"fleet"`
	Kubernetes OwnerProviderEndpoint   `json:"kubernetes"`
	Postgres   OwnerPostgresEndpoint   `json:"postgres"`
	AuditStore OwnerAuditStore         `json:"auditStore"`
	KeyService ConfigurationKeyService `json:"keyService"`
}
type InitialPreparationPublicInputs struct {
	IntentDigest string                     `json:"intentDigest"`
	Creates      []InitialPreparationCreate `json:"creates"`
}

// Handover retains the original reviewed identities and each one-use request.
// It is public provenance; none of these values activates SQL or recovery.
type InitialPreparationHandover struct {
	Cleanup       *InitialPreparationCleanup           `json:"cleanup,omitempty"`
	OperationID   string                               `json:"operationID"`
	StartupDigest string                               `json:"startupDigest"`
	Input         WorkerObjectReference                `json:"input"`
	Credentials   WorkerObjectReference                `json:"credentials"`
	ReviewedAt    time.Time                            `json:"reviewedAt"`
	Staging       *InitialPreparationStagingRetirement `json:"staging,omitempty"`
	Launch        *InitialPreparationLaunch            `json:"launch,omitempty"`
}
type InitialPreparationStagingRetirement struct {
	FirstConflict         *InitialPreparationConflictCompletion `json:"firstConflict,omitempty"`
	Retry                 *InitialPreparationConditionalRetry   `json:"retry,omitempty"`
	ID                    string                                `json:"id"`
	PolicyResourceVersion string                                `json:"policyResourceVersion"`
	StartedAt             time.Time                             `json:"startedAt"`
	Until                 time.Time                             `json:"until"`
	Receipt               *InitialPreparationPolicyReceipt      `json:"receipt,omitempty"`
}
type InitialPreparationPolicyReceipt struct {
	UID             string `json:"uid"`
	Generation      int64  `json:"generation"`
	ResourceVersion string `json:"resourceVersion"`
}
type InitialPreparationLaunch struct {
	FirstConflict      *InitialPreparationConflictCompletion `json:"firstConflict,omitempty"`
	Retry              *InitialPreparationConditionalRetry   `json:"retry,omitempty"`
	ID                 string                                `json:"id"`
	PodResourceVersion string                                `json:"podResourceVersion"`
	StartedAt          time.Time                             `json:"startedAt"`
	Until              time.Time                             `json:"until"`
	Observed           bool                                  `json:"observed,omitempty"`
}

// ConflictCompletion is produced only by the original conditional UPDATE owner
// after the exact qualified API 409 response. It is never inferred from GET.
type InitialPreparationConflictCompletion struct {
	CompletedAt time.Time `json:"completedAt"`
}

// One retry can be claimed after a durable original conflict. Its interval is
// the parent's immutable original interval; a persisted claim is lookup-only.
type InitialPreparationConditionalRetry struct {
	ID              string    `json:"id"`
	ResourceVersion string    `json:"resourceVersion"`
	ClaimedAt       time.Time `json:"claimedAt"`
}

// Cleanup is a finite record of positively acknowledged rights reductions and
// exact object removal. It contains no credential or secret-content digest.
type InitialPreparationCleanup struct {
	OperationID        string                             `json:"operationID"`
	ActivatedClaimID   string                             `json:"activatedClaimID"`
	StartedAt          time.Time                          `json:"startedAt"`
	PodResourceVersion string                             `json:"podResourceVersion"`
	SQLState           WorkerObjectReference              `json:"sqlState"`
	ProbeAnchor        WorkerObjectReference              `json:"probeAnchor"`
	Steps              []InitialPreparationCleanupReceipt `json:"steps"`
}
type InitialPreparationCleanupReceipt struct {
	Step        string    `json:"step"`
	CompletedAt time.Time `json:"completedAt"`
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
