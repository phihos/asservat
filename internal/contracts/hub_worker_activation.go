package contracts

import (
	"strings"
	"time"
)

// This fixed installed profile starts configuration reconciliation first. Its
// optional projections have no authority until the original resource journal
// records their exact completed dispositions. Legacy omission remains separate.
const HubWorkerInstalledLayout = "asservat-hub-worker-installed/v1"
const HubWorkerCleanupProjectionDirectory = "cleanup"
const HubWorkerCleanupManifestFile = "cleanup-roles.json"
const HubWorkerCleanupDeploymentFile = "cleanup-deployment.json"

func HubWorkerCleanupProjectionName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-cleanup"
}

// Original public provenance for the one installation continuation. The input
// deliberately cannot name a SQL role root that does not exist yet, supply
// credentials, extend the journal interval or select a subsystem by filename.
type HubWorkerRuntimeActivation struct {
	Resources           WorkerObjectReference         `json:"resources"`
	SetupID             string                        `json:"setupID"`
	BindingDigest       string                        `json:"bindingDigest"`
	WorkerLayout        string                        `json:"workerLayout"`
	CreatedAt           time.Time                     `json:"createdAt"`
	Until               time.Time                     `json:"until"`
	Deployment          WorkerObjectReference         `json:"deployment"`
	ServiceAccount      WorkerObjectReference         `json:"serviceAccount"`
	OwnerDeployment     WorkerObjectReference         `json:"ownerDeployment"`
	WorkloadGuard       OwnerDeploymentGuard          `json:"workloadGuard"`
	ConfigurationProbes []OwnerConfigurationProbe     `json:"configurationProbes"`
	SchedulingLeases    []OwnerSchedulingLease        `json:"schedulingLeases"`
	CapacityProbe       *OwnerDeploymentCapacityProbe `json:"capacityProbe,omitempty"`
	InitialHistoryProbe *OwnerInitialHistoryProbe     `json:"initialHistoryProbe,omitempty"`
}
