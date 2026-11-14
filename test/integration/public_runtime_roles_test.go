package integration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Explicit synthetic Secret/CAS side for the real SQL matrix. The actual native
// protected Secret adapter needs separate qualification; this fixture is never an
// installed producer, namespace guard or grant of current recovery authority.
type publicRoleSQLRoot struct {
	mu                     sync.Mutex
	value                  contracts.PublicRuntimeRoleSnapshot
	lostClaim, lostReceipt bool
	claims, receipts       int
	beforeClaim            func()
}

func (r *publicRoleSQLRoot) snapshot(ctx context.Context) contracts.PublicRuntimeRoleSnapshot {
	b, _ := json.Marshal(r.value)
	defer clear(b)
	var v contracts.PublicRuntimeRoleSnapshot
	_ = json.Unmarshal(b, &v)
	n := time.Now().UTC().Truncate(time.Microsecond)
	v.ObservedAt, v.ValidUntil = n, n.Add(5*time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(v.ValidUntil) {
		v.ValidUntil = d
	}
	return v
}
func (r *publicRoleSQLRoot) OpenPublicRuntimeRoles(ctx context.Context) (contracts.PublicRuntimeRoleSnapshot, error) {
	return r.ReadPublicRuntimeRoles(ctx)
}
func (r *publicRoleSQLRoot) ReadPublicRuntimeRoles(ctx context.Context) (contracts.PublicRuntimeRoleSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.PublicRuntimeRoleSnapshot{}, ctx.Err()
	}
	return r.snapshot(ctx), nil
}
func (r *publicRoleSQLRoot) ClaimPublicRuntimeRole(ctx context.Context, purpose string, db uint32, postmaster time.Time) (contracts.PublicRuntimeRoleSnapshot, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.PublicRuntimeRoleSnapshot{}, false, ctx.Err()
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
			return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		role.Claim = asStored(&contracts.PublicRuntimeRoleClaim{OperationID: custodyID(), ClaimedAt: n, Until: until, DatabaseOID: db, PostmasterAt: postmaster})
		r.claims++
		if r.beforeClaim != nil {
			r.beforeClaim()
			r.beforeClaim = nil
		}
		if r.lostClaim {
			r.lostClaim = false
			return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		return r.snapshot(ctx), true, nil
	}
	return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrInvalid
}
func (r *publicRoleSQLRoot) CompletePublicRuntimeRole(ctx context.Context, original contracts.PublicRuntimeRoleSnapshot, purpose string, receipt contracts.PublicRuntimeRoleReceipt) error {
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
func newPublicRoleSQLRoot(t *testing.T, input contracts.PublicRuntimeRoles) *publicRoleSQLRoot {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	r := &publicRoleSQLRoot{value: contracts.PublicRuntimeRoleSnapshot{State: contracts.PublicRuntimeRoleState{Format: contracts.PublicRuntimeRoleStateFormat, Input: input, OperationID: custodyID(), CreatedAt: n, Until: n.Add(30 * time.Minute)}, UID: custodyID(), ResourceVersion: "1"}}
	for _, p := range contracts.PublicRuntimeRolePurposes() {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		r.value.State.Roles = append(r.value.State.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: base64.RawURLEncoding.EncodeToString(b)})
		clear(b)
	}
	return r
}
func publicRoleTLSConfig(t *testing.T, admin *pgxpool.Pool, address string, tlsConfig *tls.Config) *pgx.ConnConfig {
	t.Helper()
	c := admin.Config().ConnConfig.Copy()
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	number, e := strconv.Atoi(port)
	if e != nil {
		t.Fatal(e)
	}
	c.Host, c.Port = host, uint16(number)
	c.TLSConfig = tlsConfig.Clone()
	c.TLSConfig.MinVersion = tls.VersionTLS13
	c.Fallbacks = nil
	c.ValidateConnect = nil
	c.AfterConnect = nil
	c.Tracer = nil
	return c
}

// asStored returns v as the protected Secret holds it, through the same JSON
// the snapshots use, so the root compares one time representation on every
// host. pgx and ctx.Deadline() return local-zone times, and on a UTC runner
// the JSON round trip turns those into time.UTC, which != and DeepEqual see
// as a changed claim (the first CI fleet runs).
func asStored[T any](v *T) *T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	out := new(T)
	if err = json.Unmarshal(b, out); err != nil {
		panic(err)
	}
	return out
}
