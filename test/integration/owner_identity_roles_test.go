package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Explicit synthetic Secret/CAS side for the real SQL matrix. The actual native
// protected Secret adapter needs separate qualification; this fixture is never an
// installed producer, namespace guard or grant of current recovery authority.
type ownerIdentitySQLRoot struct {
	mu                     sync.Mutex
	value                  contracts.OwnerIdentityRoleSnapshot
	lostClaim, lostReceipt bool
	claims, receipts       int
	beforeClaim            func()
	afterRead              func()
}

func (r *ownerIdentitySQLRoot) snapshot(ctx context.Context) contracts.OwnerIdentityRoleSnapshot {
	b, _ := json.Marshal(r.value)
	defer clear(b)
	var v contracts.OwnerIdentityRoleSnapshot
	_ = json.Unmarshal(b, &v)
	n := time.Now().UTC().Truncate(time.Microsecond)
	v.ValidUntil = n.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(v.ValidUntil) {
		v.ValidUntil = d
	}
	return v
}
func (r *ownerIdentitySQLRoot) OpenOwnerIdentityRoles(ctx context.Context) (contracts.OwnerIdentityRoleSnapshot, error) {
	return r.ReadOwnerIdentityRoles(ctx)
}
func (r *ownerIdentitySQLRoot) ReadOwnerIdentityRoles(ctx context.Context) (contracts.OwnerIdentityRoleSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.OwnerIdentityRoleSnapshot{}, ctx.Err()
	}
	value := r.snapshot(ctx)
	if r.afterRead != nil {
		run := r.afterRead
		r.afterRead = nil
		run()
	}
	return value, nil
}
func (r *ownerIdentitySQLRoot) ClaimOwnerIdentityRole(ctx context.Context, purpose string, db uint32, postmaster time.Time) (contracts.OwnerIdentityRoleSnapshot, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.OwnerIdentityRoleSnapshot{}, false, ctx.Err()
	}
	for i := range r.value.State.Roles {
		role := &r.value.State.Roles[i]
		if role.Purpose != purpose {
			continue
		}
		if role.Claim != nil {
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
			return contracts.OwnerIdentityRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		role.Claim = &contracts.PublicRuntimeRoleClaim{OperationID: custodyID(), ClaimedAt: n, Until: until, DatabaseOID: db, PostmasterAt: postmaster}
		r.claims++
		if r.beforeClaim != nil {
			r.beforeClaim()
			r.beforeClaim = nil
		}
		if r.lostClaim {
			r.lostClaim = false
			return contracts.OwnerIdentityRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		return r.snapshot(ctx), true, nil
	}
	return contracts.OwnerIdentityRoleSnapshot{}, false, cfg.ErrInvalid
}
func (r *ownerIdentitySQLRoot) CompleteOwnerIdentityRole(ctx context.Context, original contracts.OwnerIdentityRoleSnapshot, purpose string, receipt contracts.PublicRuntimeRoleReceipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.lostReceipt {
		r.lostReceipt = false
		return cfg.ErrUnavailable
	}
	for i := range r.value.State.Roles {
		role := &r.value.State.Roles[i]
		if role.Purpose != purpose {
			continue
		}
		if role.Claim == nil || original.State.Roles[i].Claim == nil || !ownerIdentityFixtureClaimEqual(*role.Claim, *original.State.Roles[i].Claim) {
			return cfg.ErrChanged
		}
		if role.Receipt != nil {
			if *role.Receipt != receipt {
				return cfg.ErrChanged
			}
			return nil
		}
		r.receipts++
		role.Receipt = &receipt
		return nil
	}
	return cfg.ErrInvalid
}
func newOwnerIdentitySQLRoot(t *testing.T, input contracts.OwnerIdentityRoles) *ownerIdentitySQLRoot {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	r := &ownerIdentitySQLRoot{value: contracts.OwnerIdentityRoleSnapshot{State: contracts.OwnerIdentityRoleState{Format: contracts.OwnerIdentityRoleStateFormat, Input: input, OperationID: custodyID(), CreatedAt: n, Until: n.Add(30 * time.Minute)}, UID: custodyID(), ResourceVersion: "1"}}
	for _, p := range contracts.OwnerIdentityRolePurposes() {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		r.value.State.Roles = append(r.value.State.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: base64.RawURLEncoding.EncodeToString(b)})
		clear(b)
	}
	return r
}

func ownerIdentityFixtureClaimEqual(a, b contracts.PublicRuntimeRoleClaim) bool {
	return a.OperationID == b.OperationID && a.DatabaseOID == b.DatabaseOID && a.ClaimedAt.Equal(b.ClaimedAt) && a.Until.Equal(b.Until) && a.PostmasterAt.Equal(b.PostmasterAt)
}
