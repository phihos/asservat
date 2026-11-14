package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/domain/fleet"
)

type ownerIdentityProviderObservation struct {
	configuration fleet.OwnerConfiguration
	check         providerconfig.OwnerSetupCheck
	until         time.Time
}
