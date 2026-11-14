package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InitialRuntimeResourceInventory is original CREATE provenance for the fixed
// input generators. It is not a current-source observation. Every consumer must
// construct the native guard/source reader and check its actual current values.
// A journal receipt can never stand in for that reader or SQL acceptance.
type InitialRuntimeResourceInventory struct {
	Namespace, FleetSource, OwnerSource                        contracts.WorkerObjectReference
	OwnerDeployment, OwnerAccount, OwnerService                contracts.WorkerObjectReference
	WorkerDeployment, WorkerAccount, LeaderLease               contracts.WorkerObjectReference
	OwnerInputs, WorkerInputs, OwnerProviders, WorkerProviders string
	FleetGuard, OwnerSourceGuard, WorkloadGuard                contracts.OwnerDeploymentGuard
	BridgeAdministration                                       cfg.InitialRuntimeBridgeAdministration
}
