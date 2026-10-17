package contracts

import "io"

const InitialBootstrapPassiveBundleFormat = "asservat-bootstrap-passive-history/v1"
const InitialBootstrapPassiveBundleMaxBytes = 128 << 10
const InitialBootstrapPassiveLocatorMaxBytes = 2048

// This private, immutable projection contains only the original history reader
// credential. It cannot replace setup SQL, provider or administrator material.
type InitialBootstrapPassiveBundle struct {
	Format        string                      `json:"format"`
	Seed          WorkerObjectReference       `json:"seed"`
	Configuration InitialPreparer             `json:"configuration"`
	Observation   InitialBootstrapObservation `json:"observation"`
	History       OwnerSQLCredential          `json:"history"`
}

// The metadata-only seed locator is a receipt, never current read/effect
// authority. It contains no credentials, secret-payload hash or chosen address.
type InitialBootstrapPassiveLocator struct {
	Format         string                `json:"format"`
	SeedUID        string                `json:"seedUID"`
	InstallationID string                `json:"installationID"`
	RequestID      string                `json:"requestID"`
	ClusterID      string                `json:"clusterID"`
	Projection     WorkerObjectReference `json:"projection"`
	History        WorkerObjectReference `json:"history"`
	OperationID    string                `json:"operationID"`
}

func DecodeInitialBootstrapPassiveBundle(r io.Reader) (InitialBootstrapPassiveBundle, error) {
	return decodeClosedRPC[InitialBootstrapPassiveBundle](r, InitialBootstrapPassiveBundleMaxBytes)
}
func DecodeInitialBootstrapPassiveLocator(r io.Reader) (InitialBootstrapPassiveLocator, error) {
	return decodeClosedRPC[InitialBootstrapPassiveLocator](r, InitialBootstrapPassiveLocatorMaxBytes)
}
func (InitialBootstrapPassiveBundle) String() string   { return "protected initial passive history" }
func (InitialBootstrapPassiveBundle) GoString() string { return "protected initial passive history" }
