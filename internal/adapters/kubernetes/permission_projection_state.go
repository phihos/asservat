package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Shape/provenance validation of the ADR-189 permission claim only, like the
// capacity claim. It neither renews a pending claim nor grants the stream.
func permissionProjectionStateValid(installation string, state contracts.InitialRuntimeResourceState, now time.Time) bool {
	p := state.PermissionProjection
	if p == nil {
		return true
	}
	if !authorization.UUID(installation) || state.WorkerLayout == "" || !initialRuntimeLayoutStateValid(state) ||
		!authorization.UUID(state.SetupID) || len(state.Objects) != contracts.InitialRuntimeResourceCount || state.CreatedAt.Year() < 2020 ||
		state.CreatedAt.After(now) || !capacityProjectionMicrotime(state.CreatedAt) || state.Until.Sub(state.CreatedAt) != 30*time.Minute {
		return false
	}
	ids := map[string]bool{state.SetupID: true}
	uids := map[string]bool{}
	for _, object := range state.Objects {
		if object.Receipt == nil || !authorization.UUID(object.OperationID) || ids[object.OperationID] ||
			!authorization.UUID(object.Receipt.UID) || uids[object.Receipt.UID] {
			return false
		}
		ids[object.OperationID], uids[object.Receipt.UID] = true, true
	}
	if !authorization.UUID(p.OperationID) || ids[p.OperationID] || !authorization.UUID(p.RootID) || !capacitySetupDigest(p.PublicDigest) ||
		p.ClaimedAt.Before(state.CreatedAt) || p.ClaimedAt.After(now) || !capacityProjectionMicrotime(p.ClaimedAt) || !capacityProjectionMicrotime(p.Until) ||
		!p.Until.After(p.ClaimedAt) || p.Until.Sub(p.ClaimedAt) > 5*time.Second || p.Until.After(state.Until) {
		return false
	}
	if r := p.Receipt; r != nil {
		if r.Secret.Name != contracts.PermissionRuntimeProjectionName(installation) || !authorization.UUID(r.Secret.UID) || uids[r.Secret.UID] ||
			!identity.Text(r.ResourceVersion, 128) || !capacityProjectionMicrotime(r.ObservedAt) || r.ObservedAt.Before(p.ClaimedAt) ||
			r.ObservedAt.After(now) || !r.ObservedAt.Before(state.Until) {
			return false
		}
	}
	return true
}

// Only the permission compartment may change: claim, then its receipt.
func permissionProjectionTransition(old, next contracts.InitialRuntimeResourceState) bool {
	a, b := old.PermissionProjection, next.PermissionProjection
	old.PermissionProjection = b
	if !equalJSON(old, next) || b == nil {
		return false
	}
	if a == nil {
		return b.Receipt == nil
	}
	x, y := *a, *b
	x.Receipt, y.Receipt = nil, nil
	return a.Receipt == nil && b.Receipt != nil && equalJSON(x, y)
}
