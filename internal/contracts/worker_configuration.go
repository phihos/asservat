package contracts

// WorkerConfigurationFormat is the only worker-profile.json format.
const WorkerConfigurationFormat = "asservat-worker-configuration/v3"

// WorkerConfiguration is the Helm-rendered worker-profile.json ConfigMap
// payload in the download-worker namespace. It holds Helm-known values only:
// object names, never UIDs or generated IDs. Readers take the installation,
// cluster and recovery epoch from the `<name>-ids` Secret, the namespace UID
// from their own namespace reference and each object's UID by a GET by name.
// StoreCredentials names the worker namespace's download-read Secret; empty
// means a worker without native transfer.
type WorkerConfiguration struct {
	Format            string   `json:"format"`
	Revision          int64    `json:"revision"`
	Suspended         bool     `json:"suspended"`
	Namespace         string   `json:"namespace"`
	ServiceAccount    string   `json:"serviceAccount"`
	PriorityClass     string   `json:"priorityClass"`
	ControlConfig     string   `json:"controlConfig"`
	Image             string   `json:"image"`
	ImagePullSecrets  []string `json:"imagePullSecrets"`
	CPUMillis         int64    `json:"cpuMillis"`
	MemoryBytes       int64    `json:"memoryBytes"`
	MaxRuntimeSeconds int64    `json:"maxRuntimeSeconds"`
	StoreCredentials  string   `json:"storeCredentials,omitempty"`
}

type WorkerObjectReference struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
