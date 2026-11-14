package contracts

const CapacityDeploymentFile = "capacity-deployment.json"
const CapacityDeploymentRoot = "/run/asservat/capacity"
const CapacityWorkerProjectionDirectory = "capacity"
const CapacityCredentialManifestFile = "capacity-roles.json"

func CapacityRuntimePurposes() []string {
	return []string{"capacity", "capacity-capture"}
}
