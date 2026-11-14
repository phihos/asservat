package contracts

import (
	"time"
)

// InitialBootstrapPassiveFormat is selected by the fixed installer command.
// Legacy adapter profiles retain their original guard/state contract.
const InitialBootstrapPassiveFormat = "asservat-initial-bootstrap/v2"

// InitialBootstrap contains only administrator-selected static desired input.
// The producer derives object names and obtains every Kubernetes UID/SQL OID.
// Credentials use fixed separate private files; this document may enter Helm.
type InitialBootstrap struct {
	Format                 string                    `json:"format"`
	Name                   string                    `json:"name"`
	BootstrapNamespace     string                    `json:"bootstrapNamespace"`
	TargetNamespace        string                    `json:"targetNamespace"`
	Image                  string                    `json:"image"`
	RegistryAuthentication string                    `json:"registryAuthentication,omitempty"`
	Administrators         []OwnerDeploymentActor    `json:"administrators"`
	ProbeAudience          string                    `json:"probeAudience"`
	Kubernetes             OwnerProviderEndpoint     `json:"kubernetes"`
	Postgres               OwnerPostgresEndpoint     `json:"postgres"`
	AuditStore             OwnerAuditStore           `json:"auditStore"`
	KeyService             ConfigurationKeyService   `json:"keyService"`
	Fleet                  InitialBootstrapFleet     `json:"fleet"`
	Providers              InitialBootstrapProviders `json:"providers"`
}

type InitialBootstrapFleet struct {
	Issuer              string            `json:"issuer"`
	Clients             []string          `json:"clients"`
	Subjects            []IdentitySubject `json:"subjects"`
	Groups              []string          `json:"groups"`
	DeliveryProfiles    []string          `json:"deliveryProfiles"`
	MaxActiveBootstraps int               `json:"maxActiveBootstraps"`
	MaxBootstrapHistory int               `json:"maxBootstrapHistory"`
	MaxClusters         int               `json:"maxClusters"`
}

type InitialBootstrapProviders struct {
	IssuerPolicy string `json:"issuerPolicy"`
	WrapRole     string `json:"wrapRole"`
	WrapPolicy   string `json:"wrapPolicy"`
	UnwrapRole   string `json:"unwrapRole"`
	UnwrapPolicy string `json:"unwrapPolicy"`
}

// Private original material. The explicit external profile is unchanged; the
// bundled profile records its independently observed setup identity. Generated
// installation/request IDs are bound after seed acceptance.
type InitialBootstrapMaterial struct {
	Format          string                          `json:"format"`
	IssuerToken     string                          `json:"issuerToken"`
	SetupToken      string                          `json:"setupToken,omitempty"`
	Storage         OwnerStorageCredential          `json:"storage"`
	StorageUseUntil time.Time                       `json:"storageUseUntil"`
	RegistryConfig  []byte                          `json:"registryConfig,omitempty"`
	BundledIdentity *BundledInitialProviderIdentity `json:"bundledIdentity,omitempty"`
}

type InitialBootstrapPrelude struct {
	Namespace        WorkerObjectReference  `json:"namespace"`
	Account          WorkerObjectReference  `json:"account"`
	Role             WorkerObjectReference  `json:"role"`
	Binding          WorkerObjectReference  `json:"binding"`
	Marker           WorkerObjectReference  `json:"marker"`
	ContinuityMarker WorkerObjectReference  `json:"continuityMarker"`
	TokenAnchor      WorkerObjectReference  `json:"tokenAnchor"`
	CopyMarker       *WorkerObjectReference `json:"copyMarker,omitempty"`
	Guard            OwnerDeploymentGuard   `json:"guard"`
}

// InitialBootstrapState is producer-owned private state, never Helm values,
// a public root, witness or recovery record. Passwords are unissued material
// until their corresponding original intent is acknowledged. Inventory is a
// fixed compiled set, not caller-defined Kubernetes bodies or effects.
type InitialBootstrapState struct {
	Format         string                        `json:"format"`
	DesiredDigest  string                        `json:"desiredDigest"`
	InstallationID string                        `json:"installationID"`
	RequestID      string                        `json:"requestID"`
	ClusterID      string                        `json:"clusterID"`
	IssuerEpoch    string                        `json:"issuerEpoch"`
	SeedUID        string                        `json:"seedUID,omitempty"`
	Prelude        InitialBootstrapPrelude       `json:"prelude"`
	Passwords      InitialBootstrapPasswords     `json:"passwords"`
	Material       *InitialBootstrapMaterial     `json:"material,omitempty"`
	ProviderMint   *InitialBootstrapProviderMint `json:"providerMint,omitempty"`
	Manager        *InitialBootstrapManager      `json:"manager,omitempty"`
	Creates        []InitialBootstrapCreate      `json:"creates"`
	Projection     *WorkerObjectReference        `json:"projection,omitempty"`
	PassiveHistory *InitialBootstrapCreate       `json:"passiveHistory,omitempty"`
	Retired        bool                          `json:"retired,omitempty"`
}

type InitialBootstrapPasswords struct {
	Manager     string `json:"manager"`
	Preparation string `json:"preparation"`
	Audit       string `json:"audit"`
	Activation  string `json:"activation"`
	History     string `json:"history"`
}

type InitialBootstrapManager struct {
	OperationID  string                    `json:"operationID"`
	StartedAt    time.Time                 `json:"startedAt"`
	Until        time.Time                 `json:"until"`
	DatabaseOID  uint32                    `json:"databaseOID"`
	PostmasterAt time.Time                 `json:"postmasterAt"`
	Receipt      *InitialSQLHistoryManager `json:"receipt,omitempty"`
	Closing      *InitialBootstrapClose    `json:"closing,omitempty"`
	RetiredAt    *time.Time                `json:"retiredAt,omitempty"`
}

type InitialBootstrapClose struct {
	OperationID string    `json:"operationID"`
	StartedAt   time.Time `json:"startedAt"`
	Until       time.Time `json:"until"`
}

type InitialBootstrapCreate struct {
	Step        string                     `json:"step"`
	OperationID string                     `json:"operationID"`
	Receipt     *InitialPreparationReceipt `json:"receipt,omitempty"`
}

// InitialBootstrapProviderMint is one original provider POST intent. The token
// is retained only in private Material; Response is the positive issued identity.
// Unknown POSTs never reopen this claim or authorize another mint.
type InitialBootstrapProviderMint struct {
	OperationID   string                 `json:"operationID"`
	StartedAt     time.Time              `json:"startedAt"`
	Until         time.Time              `json:"until"`
	ExpiresBefore time.Time              `json:"expiresBefore"`
	Response      *InitialProviderParent `json:"response,omitempty"`
}
