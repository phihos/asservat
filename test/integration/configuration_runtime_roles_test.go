package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Explicit synthetic Secret/CAS side for the real SQL matrix. The actual native
// protected Secret adapter needs separate qualification; this fixture is never an
// installed producer, namespace guard or grant of current recovery authority.
type configurationRoleSQLRoot struct {
	mu                     sync.Mutex
	value                  contracts.ConfigurationRuntimeRoleSnapshot
	lostClaim, lostReceipt bool
	claims, receipts       int
	beforeClaim            func()
}

func (r *configurationRoleSQLRoot) snapshot(ctx context.Context) contracts.ConfigurationRuntimeRoleSnapshot {
	b, _ := json.Marshal(r.value)
	defer clear(b)
	var v contracts.ConfigurationRuntimeRoleSnapshot
	_ = json.Unmarshal(b, &v)
	n := time.Now().UTC().Truncate(time.Microsecond)
	v.ObservedAt, v.ValidUntil = n, n.Add(5*time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(v.ValidUntil) {
		v.ValidUntil = d
	}
	v.Sources.ObservedAt, v.Sources.FreshUntil = v.ObservedAt, v.ValidUntil
	v.Sources.Fleet.ObservedAt, v.Sources.Fleet.FreshUntil = v.ObservedAt, v.ValidUntil
	v.Sources.Owner.ObservedAt, v.Sources.Owner.FreshUntil = v.ObservedAt, v.ValidUntil
	return v
}
func (r *configurationRoleSQLRoot) OpenConfigurationRuntimeRoles(ctx context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	return r.ReadConfigurationRuntimeRoles(ctx)
}
func (r *configurationRoleSQLRoot) WithConfigurationRoleOperation(ctx context.Context, run func(context.Context) error) error {
	// Synthetic proof side only; the real scoped SQL effects still consume the
	// exact original operation deadline and original immutable claim.
	live, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	return run(live)
}
func (r *configurationRoleSQLRoot) ReadConfigurationRuntimeRoles(ctx context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.ConfigurationRuntimeRoleSnapshot{}, ctx.Err()
	}
	return r.snapshot(ctx), nil
}
func (r *configurationRoleSQLRoot) ClaimConfigurationRuntimeRole(ctx context.Context, purpose string, db uint32, postmaster time.Time) (contracts.ConfigurationRuntimeRoleSnapshot, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.ConfigurationRuntimeRoleSnapshot{}, false, ctx.Err()
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
		// UTC like the product root: the snapshot copy round-trips through JSON,
		// and == on time.Time includes the location (fails under TZ=UTC).
		until = until.UTC().Truncate(time.Microsecond)
		if !n.Before(until) {
			return contracts.ConfigurationRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		sources := r.snapshot(ctx).Sources
		sources.ObservedAt, sources.Fleet.ObservedAt, sources.Owner.ObservedAt = n, n, n
		sources.FreshUntil, sources.Fleet.FreshUntil, sources.Owner.FreshUntil = until, until, until
		role.Claim = &contracts.ConfigurationRuntimeRoleClaim{OperationID: custodyID(), ClaimedAt: n, Until: until, DatabaseOID: db, PostmasterAt: postmaster.UTC(), Sources: sources}
		r.claims++
		if r.beforeClaim != nil {
			r.beforeClaim()
			r.beforeClaim = nil
		}
		if r.lostClaim {
			r.lostClaim = false
			return contracts.ConfigurationRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		return r.snapshot(ctx), true, nil
	}
	return contracts.ConfigurationRuntimeRoleSnapshot{}, false, cfg.ErrInvalid
}
func (r *configurationRoleSQLRoot) CompleteConfigurationRuntimeRole(ctx context.Context, original contracts.ConfigurationRuntimeRoleSnapshot, purpose string, receipt contracts.PublicRuntimeRoleReceipt) error {
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
		if role.Claim == nil || original.State.Roles[i].Claim == nil || *role.Claim != *original.State.Roles[i].Claim {
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
func newConfigurationRoleSQLRoot(t *testing.T, input contracts.ConfigurationRuntimeRoles, issuer string) *configurationRoleSQLRoot {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	r := &configurationRoleSQLRoot{value: contracts.ConfigurationRuntimeRoleSnapshot{State: contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: input, OperationID: custodyID(), CreatedAt: n, Until: n.Add(30 * time.Minute)}, UID: custodyID(), ResourceVersion: "1"}}
	r.value.Sources = contracts.ConfigurationRoleObservation{InstallationID: input.InstallationID, ClusterID: input.ClusterID, IssuerEpoch: issuer, NamespaceUID: input.Namespace.UID, DeploymentUID: input.Deployment.UID, AccountUID: input.ServiceAccount.UID, WorkloadDigest: strings.Repeat("1", 64), GuardDigest: strings.Repeat("2", 64), Fleet: contracts.ConfigurationRoleSourceRevision{UID: input.FleetSource.UID, Generation: 1, Digest: strings.Repeat("3", 64)}, Owner: contracts.ConfigurationRoleSourceRevision{UID: input.OwnerSource.UID, Generation: 1, Digest: strings.Repeat("4", 64)}}
	for _, p := range contracts.ConfigurationRuntimeRolePurposes() {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		r.value.State.Roles = append(r.value.State.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: p, Password: base64.RawURLEncoding.EncodeToString(b)})
		clear(b)
	}
	return r
}
