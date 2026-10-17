package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Shape/provenance validation only. Both producer and runtime reader must
// independently prove the original journal's protection and current workload.
// A completed historical receipt may outlive the installation interval; this
// function neither renews a pending claim nor grants a runtime operation.
func capacityProjectionStateValid(installation string, state contracts.InitialRuntimeResourceState, now time.Time) bool {
	p := state.CapacityProjection
	if p == nil {
		return true
	}
	if !authorization.UUID(installation) || state.WorkerLayout == "" || !initialRuntimeLayoutStateValid(state) ||
		len(state.Objects) != contracts.InitialRuntimeResourceCount || state.CreatedAt.Year() < 2020 ||
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
	if !authorization.UUID(p.OperationID) || p.OperationID == p.Setup.OperationID || ids[p.OperationID] || !capacitySetupDigest(p.PublicDigest) ||
		p.ClaimedAt.Before(state.CreatedAt) || p.ClaimedAt.After(now) || !capacityProjectionMicrotime(p.ClaimedAt) || !capacityProjectionMicrotime(p.Until) ||
		!p.Until.After(p.ClaimedAt) || p.Until.Sub(p.ClaimedAt) > 5*time.Second || p.Until.After(state.Until) ||
		!capacityProjectionSetupValid(installation, p.Setup, state.CreatedAt, p.ClaimedAt) {
		return false
	}
	if r := p.Receipt; r != nil {
		if r.Secret.Name != contracts.CapacityRuntimeProjectionName(installation) || !authorization.UUID(r.Secret.UID) || r.Secret.UID == p.Setup.RoleRootUID || uids[r.Secret.UID] ||
			!identity.Text(r.ResourceVersion, 128) || !capacityProjectionMicrotime(r.ObservedAt) || r.ObservedAt.Before(p.ClaimedAt) ||
			r.ObservedAt.After(now) || !r.ObservedAt.Before(state.Until) {
			return false
		}
	}
	return true
}

func capacityProjectionSetupValid(installation string, s contracts.CapacityRootSetupReceipt, earliest, claimed time.Time) bool {
	if s.Format != contracts.CapacityRootSetupFormat || s.InstallationID != installation || s.DatabaseOID == 0 ||
		!capacitySetupDigest(s.InputDigest) || s.PostmasterAt.Year() < 2020 || s.PostmasterAt.After(s.ClaimedAt) ||
		!capacityProjectionMicrotime(s.PostmasterAt) || s.ClaimedAt.Before(earliest) || s.ClaimedAt.After(claimed) ||
		!capacityProjectionMicrotime(s.ClaimedAt) || !capacityProjectionMicrotime(s.Until) || !s.Until.After(s.ClaimedAt) || s.Until.Sub(s.ClaimedAt) > 5*time.Second {
		return false
	}
	for _, v := range []string{s.OperationID, s.InstallationID, s.InitialClaimID, s.PermissionRootID, s.RoleRootUID, s.RoleSetupID} {
		if !authorization.UUID(v) {
			return false
		}
	}
	return true
}

func capacityProjectionMicrotime(v time.Time) bool { return v.Equal(v.Truncate(time.Microsecond)) }
