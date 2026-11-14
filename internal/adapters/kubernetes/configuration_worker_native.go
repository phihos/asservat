package kubernetes

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
)

// One actual native bracket, retained only by the private worker advancement.
// These complete responses do not implement a general current-reader port.
// Direct reads can compare them but cannot renew this interval or enforcement.
type configurationWorkerNative struct {
	proof           configurationRoleObserved
	fleet           fleet.Administration
	owner           fleet.OwnerConfiguration
	deployment      apps.Deployment
	ownerDeployment apps.Deployment
	account         core.ServiceAccount
	administrator   auth.UserInfo
	fleetRef        cfg.Resource
	ownerRef        cfg.Resource
}
