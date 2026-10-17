package kubernetes

import (
	"context"
	"encoding/hex"
	"reflect"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/google/uuid"
)

func capacitySetupDigest(v string) bool {
	b, err := hex.DecodeString(v)
	var nonzero byte
	for _, x := range b {
		nonzero |= x
	}
	return err == nil && len(b) == 32 && nonzero != 0 && hex.EncodeToString(b) == v
}

func capacitySetupRolesReady(v contracts.PublicRuntimeRoleState) bool {
	for _, purpose := range contracts.CapacitySetupRolePurposes() {
		found := false
		for _, role := range v.Roles {
			if role.Purpose == purpose {
				if found || role.Claim == nil || role.Receipt == nil {
					return false
				}
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func capacitySetupStateValid(v contracts.PublicRuntimeRoleState, now time.Time) bool {
	c := v.CapacitySetup
	if c == nil {
		return true
	} // Omission preserves the previous protocol bytes.
	if !authorization.UUID(c.OperationID) || c.OperationID == v.OperationID || !authorization.UUID(c.PermissionRootID) || !capacitySetupDigest(c.InputDigest) || c.DatabaseOID == 0 || c.PostmasterAt.Year() < 2020 || c.PostmasterAt.After(c.ClaimedAt) || c.ClaimedAt.Before(v.CreatedAt) || c.ClaimedAt.After(now) || c.ClaimedAt.Nanosecond()%1000 != 0 || c.PostmasterAt.Nanosecond()%1000 != 0 || c.Until.Nanosecond()%1000 != 0 || !c.Until.After(c.ClaimedAt) || c.Until.Sub(c.ClaimedAt) > 5*time.Second || c.Until.After(v.Until) || !capacitySetupRolesReady(v) {
		return false
	}
	if v.Projection != nil && c.OperationID == v.Projection.OperationID {
		return false
	}
	for _, role := range v.Roles {
		if role.Claim != nil && c.OperationID == role.Claim.OperationID {
			return false
		}
	}
	if r := c.Receipt; r != nil {
		if r.Format != contracts.CapacityRootSetupFormat || r.OperationID != c.OperationID || r.InstallationID != v.Input.InstallationID || r.InitialClaimID != v.Input.InitialClaimID || r.PermissionRootID != c.PermissionRootID || !authorization.UUID(r.RoleRootUID) || r.RoleSetupID != v.OperationID || r.InputDigest != c.InputDigest || r.DatabaseOID != c.DatabaseOID || !r.PostmasterAt.Equal(c.PostmasterAt) || !r.ClaimedAt.Equal(c.ClaimedAt) || !r.Until.Equal(c.Until) {
			return false
		}
	}
	return true
}

// No root creation/adoption here: the original role root, all original role
// receipts and the exact independently mounted setup identity must preexist.
func (s *PublicRuntimeRoleRoot) ClaimCapacityRootSetup(ctx context.Context, rootUID, setupID, permissionRoot, inputDigest string, database uint32, postmaster time.Time) (contracts.PublicRuntimeRoleSnapshot, bool, error) {
	var zero contracts.PublicRuntimeRoleSnapshot
	ctx, end, err := s.enter(ctx)
	if err != nil {
		return zero, false, err
	}
	defer end()
	old, object, err := s.read(ctx)
	if err != nil {
		return zero, false, err
	}
	if old.UID != rootUID || old.State.OperationID != setupID || !authorization.UUID(permissionRoot) || !capacitySetupDigest(inputDigest) || database == 0 || postmaster.Year() < 2020 || !capacitySetupRolesReady(old.State) {
		return zero, false, cfg.ErrChanged
	}
	if c := old.State.CapacitySetup; c != nil {
		if c.PermissionRootID != permissionRoot || c.InputDigest != inputDigest || c.DatabaseOID != database || !c.PostmasterAt.Equal(postmaster) {
			return zero, false, cfg.ErrChanged
		}
		return old, false, nil
	}
	now := s.client.now().UTC().Truncate(time.Microsecond)
	until := old.ValidUntil
	if old.State.Until.Before(until) {
		until = old.State.Until
	}
	until = until.UTC().Truncate(time.Microsecond)
	if !now.Before(until) || postmaster.After(now) {
		return zero, false, cfg.ErrUnavailable
	}
	next := old.State
	next.CapacitySetup = &contracts.CapacityRootSetupClaim{OperationID: uuid.NewString(), PermissionRootID: permissionRoot, InputDigest: inputDigest, DatabaseOID: database, PostmasterAt: postmaster.UTC(), ClaimedAt: now, Until: until}
	if !runtimeRoleStateValid(s.input, next, s.client.now()) {
		return zero, false, cfg.ErrInvalid
	}
	out, err := s.update(ctx, old, object, next, until)
	if err != nil {
		return zero, false, err
	}
	return out, true, nil
}

// A current exact SQL read may recover an acknowledged paired-root receipt
// after the effect interval expired. It cannot permit another SQL effect.
func (s *PublicRuntimeRoleRoot) CompleteCapacityRootSetup(ctx context.Context, original contracts.PublicRuntimeRoleSnapshot, receipt contracts.CapacityRootSetupReceipt) (err error) {
	ctx, end, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer end()
	// ADR-186 inside a role operation: the setup transaction intervened, so
	// prove again before the completing write and bracket it afterwards.
	if publicRoleOperationOf(ctx) != nil {
		until, e := s.current(ctx)
		if e != nil {
			return e
		}
		var narrow context.CancelFunc
		ctx, narrow = context.WithDeadline(ctx, until)
		defer narrow()
		defer func() {
			if err == nil {
				if _, e := s.current(ctx); e != nil {
					err = cfg.ErrUnavailable
				}
			}
		}()
	}
	old, object, err := s.read(ctx)
	if err != nil {
		return err
	}
	if old.UID != original.UID || old.State.Input != original.State.Input || old.State.OperationID != original.State.OperationID || old.State.CapacitySetup == nil || original.State.CapacitySetup == nil {
		return cfg.ErrChanged
	}
	a, b := *old.State.CapacitySetup, *original.State.CapacitySetup
	a.Receipt = nil
	b.Receipt = nil
	if !reflect.DeepEqual(a, b) || receipt.RoleRootUID != old.UID {
		return cfg.ErrChanged
	}
	if current := old.State.CapacitySetup.Receipt; current != nil {
		if reflect.DeepEqual(*current, receipt) {
			return nil
		}
		return cfg.ErrChanged
	}
	next := old.State
	claim := *old.State.CapacitySetup
	claim.Receipt = &receipt
	next.CapacitySetup = &claim
	if !runtimeRoleStateValid(s.input, next, s.client.now()) {
		return cfg.ErrInvalid
	}
	_, err = s.update(ctx, old, object, next, old.ValidUntil)
	return err
}
