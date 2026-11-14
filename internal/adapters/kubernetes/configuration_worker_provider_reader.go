package kubernetes

// ConfigurationWorkerProviderReader verifies the fixed worker process and its
// actual protected sources before provider credential control. It requires no
// accepted owner SQL row: producing that row is this worker's later job.
// The native clients and their transports remain owned by the deployment.
type ConfigurationWorkerProviderReader struct {
	worker *InstalledWorkerProjectionReader
	fleet  *ProtectedFleetSettings
	owner  *OwnerConfigurationSource
	podUID string
}
