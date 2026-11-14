package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
)

// Pure derivation from the actual initial operation responses. This value is
// not authority: only a positively acknowledged original launch claim followed
// by actual post-lock SQL/native checks may admit its one Deployment UPDATE.
type configurationWorkerLaunchPlan struct {
	claim   contracts.ConfigurationRuntimeLaunch
	running apps.Deployment
}
