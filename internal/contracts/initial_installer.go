package contracts

import (
	"io"
	"time"
)

const InitialInstallerFormat = "asservat-initial-installer/v1"
const InitialInstallerRoot = "/run/asservat/initial-installer"

// Installation-owned inputs; no credentials or user-supplied activation flag.
// InitialSchemaExpectation is immutable preparation provenance. SQL still checks
// this exact incarnation under its own transaction; it never authorizes recovery.
type InitialSchemaExpectation struct {
	BundleDigest string    `json:"bundleDigest"`
	Head         int64     `json:"head"`
	DatabaseOID  uint32    `json:"databaseOID"`
	PostmasterAt time.Time `json:"postmasterAt"`
}

type InitialInstaller struct {
	SchemaInitialization string                    `json:"schemaInitialization,omitempty"`
	Schema               *InitialSchemaExpectation `json:"schema,omitempty"`
	Handover             string                    `json:"handover,omitempty"`
	Format               string                    `json:"format"`
	InstallationID       string                    `json:"installationID"`
	IssuerEpoch          string                    `json:"issuerEpoch"`
	ClusterID            string                    `json:"clusterID"`
	Namespace            WorkerObjectReference     `json:"namespace"`
	Witness              WorkerObjectReference     `json:"witness"`
	WriterAccount        WorkerObjectReference     `json:"writerAccount"`
	ProbeAccount         WorkerObjectReference     `json:"probeAccount"`
	Pod                  WorkerObjectReference     `json:"pod"`
	PodSpecDigest        string                    `json:"podSpecDigest"`
	Configuration        string                    `json:"configuration"`
	FleetSource          WorkerObjectReference     `json:"fleetSource"`
	WitnessGuard         OwnerDeploymentGuard      `json:"witnessGuard"`
	FleetGuard           OwnerDeploymentGuard      `json:"fleetGuard"`
	WorkloadGuard        OwnerDeploymentGuard      `json:"workloadGuard"`
	Kubernetes           OwnerProviderEndpoint     `json:"kubernetes"`
	Postgres             OwnerPostgresEndpoint     `json:"postgres"`
	AuditStore           OwnerAuditStore           `json:"auditStore"`
	KeyService           ConfigurationKeyService   `json:"keyService"`
}

func DecodeInitialInstaller(r io.Reader) (InitialInstaller, error) {
	return decodeClosedRPC[InitialInstaller](r, OwnerDeploymentMaxBytes)
}
