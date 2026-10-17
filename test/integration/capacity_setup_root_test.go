package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The SQL matrix's only private-root substitute. Its original role creation
// claims still drive the real SQL role producer; no synthetic SQL receipt is
// accepted. Actual Kubernetes claim/guard qualification is separate.
type capacitySQLRoot struct {
	*publicRoleSQLRoot
	setupClaims, setupReceipts       int
	lostSetupClaim, lostSetupReceipt bool
}

func newCapacitySQLRoot(t *testing.T, in contracts.PublicRuntimeRoles) *capacitySQLRoot {
	t.Helper()
	r := &capacitySQLRoot{publicRoleSQLRoot: newPublicRoleSQLRoot(t, in)}
	r.value.State.MAC = contracts.PublicAuditKeyMaterial{
		InputVersion:   r.value.State.OperationID + "-input/v1",
		AccountVersion: r.value.State.OperationID + "-account/v1",
		InputKey:       make([]byte, 32), AccountKey: make([]byte, 32),
	}
	for _, key := range [][]byte{r.value.State.MAC.InputKey, r.value.State.MAC.AccountKey} {
		if _, err := rand.Read(key); err != nil {
			t.Fatal("synthetic original key generation unavailable")
		}
	}
	t.Cleanup(func() { clear(r.value.State.MAC.InputKey); clear(r.value.State.MAC.AccountKey) })
	return r
}

func (r *capacitySQLRoot) ClaimCapacityRootSetup(ctx context.Context, root, setup, permission, digest string, db uint32, postmaster time.Time) (contracts.PublicRuntimeRoleSnapshot, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || root != r.value.UID || setup != r.value.State.OperationID {
		return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
	}
	if old := r.value.State.CapacitySetup; old != nil {
		if old.PermissionRootID != permission || old.InputDigest != digest || old.DatabaseOID != db || !old.PostmasterAt.Equal(postmaster) {
			return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrChanged
		}
		return r.snapshot(ctx), false, nil
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	if r.value.State.Until.Before(until) {
		until = r.value.State.Until
	}
	until = until.Truncate(time.Microsecond)
	if !n.Before(until) {
		return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
	}
	r.value.State.CapacitySetup = asStored(&contracts.CapacityRootSetupClaim{OperationID: custodyID(), PermissionRootID: permission, InputDigest: digest, DatabaseOID: db, PostmasterAt: postmaster, ClaimedAt: n, Until: until})
	r.setupClaims++
	if r.lostSetupClaim {
		r.lostSetupClaim = false
		return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
	}
	return r.snapshot(ctx), true, nil
}

func (r *capacitySQLRoot) CompleteCapacityRootSetup(ctx context.Context, original contracts.PublicRuntimeRoleSnapshot, receipt contracts.CapacityRootSetupReceipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || original.UID != r.value.UID || original.State.CapacitySetup == nil || r.value.State.CapacitySetup == nil {
		return cfg.ErrUnavailable
	}
	a, b := *original.State.CapacitySetup, *r.value.State.CapacitySetup
	a.Receipt, b.Receipt = nil, nil
	if !reflect.DeepEqual(a, b) || receipt.OperationID != a.OperationID || receipt.InputDigest != a.InputDigest || !receipt.ClaimedAt.Equal(a.ClaimedAt) || !receipt.Until.Equal(a.Until) {
		return cfg.ErrChanged
	}
	if r.lostSetupReceipt {
		r.lostSetupReceipt = false
		return cfg.ErrUnavailable
	}
	if old := r.value.State.CapacitySetup.Receipt; old != nil {
		if *old != receipt {
			return cfg.ErrChanged
		}
		return nil
	}
	r.setupReceipts++
	r.value.State.CapacitySetup.Receipt = &receipt
	return nil
}

type capacitySyntheticProtection struct {
	cluster, namespace string
	digest             artifact.Digest
}

func (s capacitySyntheticProtection) CapacityProtection(ctx context.Context) (capacity.CapacitySourceProtection, error) {
	if ctx.Err() != nil {
		return capacity.CapacitySourceProtection{}, ctx.Err()
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	return capacity.CapacitySourceProtection{ClusterID: s.cluster, ControlNamespaceUID: s.namespace, Digest: s.digest, ObservedAt: n, FreshUntil: until}, nil
}

func capacityGuardHex(v artifact.Digest) string { return hex.EncodeToString(v[:]) }
