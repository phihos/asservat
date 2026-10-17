package contracts

// Fixed A-HWORK provenance, generated from the existing completed resource and
// configuration journals. It carries no credentials or current authorization.
// Comparable value fields preserve exact role-root input equality. A zero value
// is omitted from the old input encoding and cannot authorize worker roles.
type PublicRuntimeWorkerBinding struct {
	Provider             PublicRuntimeWorkerProviderBinding `json:"provider,omitzero"`
	Resources            WorkerObjectReference              `json:"resources"`
	ResourceSetupID      string                             `json:"resourceSetupID"`
	FleetGuardName       string                             `json:"fleetGuardName"`
	ResourceBinding      string                             `json:"resourceBinding"`
	WorkerLayout         string                             `json:"workerLayout"`
	Deployment           PublicRuntimeWorkerObject          `json:"deployment"`
	Account              PublicRuntimeWorkerObject          `json:"account"`
	Lease                PublicRuntimeWorkerObject          `json:"lease"`
	ConfigurationRoot    WorkerObjectReference              `json:"configurationRoot"`
	ConfigurationSetupID string                             `json:"configurationSetupID"`
	Configuration        ConfigurationRuntimeRoles          `json:"configuration"`
}

type PublicRuntimeWorkerObject struct {
	Reference      WorkerObjectReference `json:"reference"`
	OperationID    string                `json:"operationID"`
	TemplateDigest string                `json:"templateDigest"`
}
