package contracts

import "io"

const InitialBootstrapInputFormat = "asservat-bootstrap-input/v1"

// Public installer input for the official chart. Only static operator choices
// occur here; the product obtains all UIDs, SQL OIDs and original effect IDs.
// PEM roots are normalized before private files or effects are touched.
type InitialBootstrapInput struct {
	Format                 string                          `json:"format"`
	Name                   string                          `json:"name"`
	BootstrapNamespace     string                          `json:"bootstrapNamespace"`
	TargetNamespace        string                          `json:"targetNamespace"`
	RunnerAccount          string                          `json:"runnerAccount"`
	Image                  string                          `json:"image"`
	RegistryAuthentication string                          `json:"registryAuthentication,omitempty"`
	ProbeAudience          string                          `json:"probeAudience,omitempty"`
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
}
type InitialBootstrapAuditStoreInput struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	RootsPEM string `json:"rootsPEM"`
}
type InitialBootstrapKeyServiceInput struct {
	Endpoint   string `json:"endpoint"`
	AuditMount string `json:"auditMount"`
	AuditKey   string `json:"auditKey"`
	RootsPEM   string `json:"rootsPEM"`
}

func DecodeInitialBootstrapInput(r io.Reader) (InitialBootstrapInput, error) {
	return decodeClosedRPC[InitialBootstrapInput](r, InitialBootstrapMaxBytes)
}
