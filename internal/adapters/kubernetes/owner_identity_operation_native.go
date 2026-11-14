package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
)

// Actual original responses belonging to one admitted owner operation. This is
// neither a current-reader implementation nor a value supplied by an installer
// input. The SQL seam consumes the separately admitted opaque operation only.
type ownerIdentityOperationNative struct {
	retained initialRuntimeRetainedResources
	source   configurationWorkerNative
	input    contracts.OwnerIdentityRoles
	accepted fleet.OwnerConfigurationObservation
	account  core.ServiceAccount
	service  core.Service
	roles    contracts.OwnerIdentityRoleSnapshot
	object   *core.Secret
	missing  bool
	until    time.Time
}
