package contracts

import (
	"io"
	"time"
)

const InitialProviderProfileFormat = "asservat-initial-provider-profile/v1"
const InitialProviderMaterialFormat = "asservat-initial-provider-material/v1"
const InitialProviderTokenMaxBytes = 1024

// Explicit protected installation input, never inferred from a token or endpoint.
// Policies use the finite JSON ACL profile validated by the provider adapter.
type InitialProviderProfile struct {
	Format       string                `json:"format"`
	Material     WorkerObjectReference `json:"material"`
	IssuerPolicy string                `json:"issuerPolicy"`
	WrapRole     string                `json:"wrapRole"`
	WrapPolicy   string                `json:"wrapPolicy"`
	UnwrapRole   string                `json:"unwrapRole"`
	UnwrapPolicy string                `json:"unwrapPolicy"`
}

// Original immutable bootstrap material. S3 credentials are externally managed;
// their declared use interval is not proof that Asservat can revoke them.
type InitialProviderMaterial struct {
	Format          string                 `json:"format"`
	InstallationID  string                 `json:"installationID"`
	RequestID       string                 `json:"requestID"`
	IssuerToken     string                 `json:"issuerToken"`
	Storage         OwnerStorageCredential `json:"storage"`
	StorageUseUntil time.Time              `json:"storageUseUntil"`
	RegistryConfig  []byte                 `json:"registryConfig,omitempty"`
}

func DecodeInitialProviderMaterial(r io.Reader) (InitialProviderMaterial, error) {
	return decodeClosedRPC[InitialProviderMaterial](r, InitialProviderMaterialMaxBytes)
}
func (InitialProviderMaterial) String() string   { return "protected initial provider material" }
func (InitialProviderMaterial) GoString() string { return "protected initial provider material" }

// Original provider-issued identity and hard end, retained independently of each
// request deadline. No token or secret-payload digest belongs in the public root.
type InitialProviderParent struct {
	Accessor  string    `json:"accessor"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type InitialPreparationProviders struct {
	ProfileDigest string                      `json:"profileDigest"`
	Parent        InitialProviderParent       `json:"parent"`
	Wrap          *InitialProviderIssue       `json:"wrap,omitempty"`
	Unwrap        *InitialProviderIssue       `json:"unwrap,omitempty"`
	Projection    *InitialPreparationSQLState `json:"projection,omitempty"`
}
type InitialProviderIssue struct {
	ID            string                   `json:"id"`
	StartedAt     time.Time                `json:"startedAt"`
	Until         time.Time                `json:"until"`
	ExpiresBefore time.Time                `json:"expiresBefore"`
	Response      *InitialProviderResponse `json:"response,omitempty"`
}
type InitialProviderResponse struct {
	Token     string    `json:"token"`
	Accessor  string    `json:"accessor"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (InitialProviderResponse) String() string       { return "protected initial provider credential" }
func (InitialProviderResponse) GoString() string     { return "protected initial provider credential" }
func (InitialProviderIssue) String() string          { return "protected initial provider issue claim" }
func (InitialProviderIssue) GoString() string        { return "protected initial provider issue claim" }
func (InitialPreparationProviders) String() string   { return "protected initial provider progress" }
func (InitialPreparationProviders) GoString() string { return "protected initial provider progress" }
