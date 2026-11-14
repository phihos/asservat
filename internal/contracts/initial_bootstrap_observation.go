package contracts

// InitialBootstrapObservation is generated from the retained producer seed.
// It contains only original public prelude/projection identities. It does not
// confer SQL, provider, collection, recovery or target activation authority.
type InitialBootstrapObservation struct {
	Format           string                  `json:"format"`
	Desired          InitialBootstrap        `json:"desired"`
	Prelude          InitialBootstrapPrelude `json:"prelude"`
	InstallationID   string                  `json:"installationID"`
	RequestID        string                  `json:"requestID"`
	ClusterID        string                  `json:"clusterID"`
	Projection       WorkerObjectReference   `json:"projection"`
	ResourceVersion  string                  `json:"resourceVersion"`
	OperationID      string                  `json:"operationID"`
	PlanDigest       string                  `json:"planDigest"`
	ProjectionDigest string                  `json:"projectionDigest"`
}
