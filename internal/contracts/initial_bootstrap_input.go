package contracts

import "io"

const InitialBootstrapInputFormat = "asservat-bootstrap-input/v1"

// The selected bundled provider projects this fixed public certificate file.
// It is resolved before canonical installation input is compiled; it never
// excludes the actual trust bytes from the immutable installation identity.
const InitialBootstrapBundledPostgresRoots = "bundledPostgres"
const InitialBootstrapPostgresCAFile = "postgres-ca.crt"
const InitialBootstrapBundledSeaweedRoots = "bundledSeaweed"
const InitialBootstrapObjectStoreCAFile = "objectstore-ca.crt"
const InitialBootstrapObjectStorePlanFile = "objectstore-plan.json"

// Public installer input for the official chart. Only static operator choices
// occur here; the product obtains all UIDs, SQL OIDs and original effect IDs.
// PEM roots are normalized before private files or effects are touched.
type InitialBootstrapInput struct {
	Format                 string                          `json:"format"`
	Name                   string                          `json:"name"`
	BootstrapNamespace     string                          `json:"bootstrapNamespace"`
	TargetNamespace        string                          `json:"targetNamespace"`
	RunnerAccount          string                          `json:"runnerAccount"`
	Administrators         []OwnerDeploymentActor          `json:"administrators,omitempty"`
	Image                  string                          `json:"image"`
	RegistryAuthentication string                          `json:"registryAuthentication,omitempty"`
	ProbeAudience          string                          `json:"probeAudience,omitempty"`
	IdentitySource         string                          `json:"identitySource,omitempty"`
	Kubernetes             InitialBootstrapEndpointInput   `json:"kubernetes"`
	Postgres               InitialBootstrapPostgresInput   `json:"postgres"`
	AuditStore             InitialBootstrapAuditStoreInput `json:"auditStore"`
	KeyService             InitialBootstrapKeyServiceInput `json:"keyService"`
	Fleet                  InitialBootstrapFleet           `json:"fleet"`
	Providers              InitialBootstrapProviders       `json:"providers"`
}
type InitialBootstrapEndpointInput struct {
	Endpoint string `json:"endpoint"`
	RootsPEM string `json:"rootsPEM,omitempty"`
}
type InitialBootstrapPostgresInput struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	MaxConnections int32  `json:"maxConnections"`
	RootsPEM       string `json:"rootsPEM"`
	RootsSource    string `json:"rootsSource,omitempty"`
}
type InitialBootstrapAuditStoreInput struct {
	Endpoint    string `json:"endpoint"`
	Region      string `json:"region"`
	Bucket      string `json:"bucket"`
	RootsPEM    string `json:"rootsPEM"`
	RootsSource string `json:"rootsSource,omitempty"`
}
type InitialBootstrapKeyServiceInput struct {
	Endpoint    string `json:"endpoint"`
	AuditMount  string `json:"auditMount"`
	AuditKey    string `json:"auditKey"`
	RootsPEM    string `json:"rootsPEM"`
	RootsSource string `json:"rootsSource,omitempty"`
}

const InitialBootstrapBundledOpenBaoRoots = "bundledOpenBao"
const InitialBootstrapKeyServicePlanFile = "openbao-plan.json"
const InitialBootstrapKeyServiceCAFile = "openbao-ca.crt"
const InitialBootstrapKeyServiceBackendFile = "openbao-backend-id"
const InitialBootstrapKeyServiceTokenFile = "keyprovider-setup-token"

func DecodeInitialBootstrapInput(r io.Reader) (InitialBootstrapInput, error) {
	return decodeClosedRPC[InitialBootstrapInput](r, InitialBootstrapMaxBytes)
}
