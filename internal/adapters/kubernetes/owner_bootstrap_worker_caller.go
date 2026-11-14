package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// OwnerBootstrapWorkerCaller is public installation provenance, not runtime
// authorization. The observation backend must persist this exact pin with its
// own original receipt and independently verify every current caller. No Pod or
// ReplicaSet identity exists here: the original Deployment is their controller
// anchor, and their actual identities belong to online runtime observation.
type OwnerBootstrapWorkerCaller struct {
	Pin                                                    fleet.ClusterObservationCallerPin
	Resources, Selection, ConfigurationRoot                contracts.WorkerObjectReference
	ResourceSetupID, ResourceBinding                       string
	SelectionOperationID, SelectionPublicDigest            string
	ConfigurationSetupID, WorkerInputID, LaunchOperationID string
	ObservedAt, FreshUntil                                 time.Time
}
