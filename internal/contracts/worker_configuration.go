package contracts

// WorkerConfiguration is the private worker-profile.json ConfigMap payload.
// Kubernetes names and UIDs are resolved by installation, never a download user.
type WorkerConfiguration struct {
	Format            string                  `json:"format"`
	InstallationID    string                  `json:"installationID"`
	ClusterID         string                  `json:"clusterID"`
	RecoveryEpoch     string                  `json:"recoveryEpoch"`
	Revision          int64                   `json:"revision"`
	Suspended         bool                    `json:"suspended"`
	Namespace         WorkerObjectReference   `json:"namespace"`
	ServiceAccount    WorkerObjectReference   `json:"serviceAccount"`
	PriorityClass     WorkerObjectReference   `json:"priorityClass"`
	ControlConfig     LocalKeySecretReference `json:"controlConfig"`
	Image             string                  `json:"image"`
	ImagePullSecrets  []string                `json:"imagePullSecrets"`
	CPUMillis         int64                   `json:"cpuMillis"`
	MemoryBytes       int64                   `json:"memoryBytes"`
	MaxRuntimeSeconds int64                   `json:"maxRuntimeSeconds"`
	StoreCredentials  *WorkerObjectReference  `json:"storeCredentials,omitempty"`
}
// UnconfiguredWorkerConfiguration is the exact worker-profile.json document of
// an installed source before an administrator configures a worker (ADR-194 D1).
func UnconfiguredWorkerConfiguration(installationID string) string {
	return `{"format":"asservat-worker-configuration/unconfigured","installationID":"` + installationID + `"}`
}

type WorkerObjectReference struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
