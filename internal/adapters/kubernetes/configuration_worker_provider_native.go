package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

// Complete actual values within one worker-provider native bracket. These
// private fields never implement a reader or establish a replacement interval.
type configurationProviderNative struct {
	until           time.Time
	guards          [3]string
	resources       contracts.InitialRuntimeResourceState
	fleet           fleet.Administration
	owner           fleet.OwnerConfiguration
	fleetRef        cfg.Resource
	ownerRef        cfg.Resource
	deployment      apps.Deployment
	ownerDeployment apps.Deployment
	account         core.ServiceAccount
	process         configurationProviderProcess
	podName         string
}
