package kubernetes

import "asservat.local/asservat/internal/contracts"

// Only the capacity compartment may change here. Full closed state validation,
// original UID/RV CAS and current native/SQL checks surround this transition.
func capacityProjectionTransition(old, next contracts.InitialRuntimeResourceState) bool {
	a, b := old.CapacityProjection, next.CapacityProjection
	old.CapacityProjection = b
	if !equalJSON(old, next) || b == nil {
		return false
	}
	if a == nil {
		return b.Receipt == nil
	}
	return a.Receipt == nil && b.Receipt != nil && capacityProjectionSameClaim(a, b)
}
