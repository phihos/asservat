package kubernetes

import (
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
)

// Projection-only incomplete source responses. No proof marker, accepted-reader
// interface or effect method exists on this type. Its enclosing original call
// owns every response and date through completion under the SQL bridge.
type ownerProjectionSourcePrefix struct {
	source                      *ConfigurationRoleSource
	started, until              time.Time
	guards                      [3]string
	fleet                       fleet.Administration
	owner                       fleet.OwnerConfiguration
	fleetRef, ownerRef          cfg.Resource
	deployment, ownerDeployment apps.Deployment
	account                     core.ServiceAccount
	administrator               auth.UserInfo
	actors                      [3]auth.UserInfo
}
