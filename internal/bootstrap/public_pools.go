package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The ordinary shared login has one main pool and two existing reserved
// resolution pools. Pinned capture writes keep their slots. These 23 hot slots
// plus the owner's six leave three for independently acquired cold readers.
const hubAPIHotConnections = contracts.PublicRuntimeHubConnections + 3

func publicPoolPlan(duty string) (role, key string, limit int, hot, ok bool) {
	if slices.Contains(contracts.PublicRuntimeHubSharedDuties(), duty) || duty == "hub-runtime" {
		if duty == "audit-resolution-journal" || duty == "audit-resolution-ack" {
			return "hub-runtime", duty, 1, true, true
		}
		return "hub-runtime", "hub-runtime", contracts.PublicRuntimeHubOrdinaryConnections, true, true
	}
	switch duty {
	case "capture-admit", "capture-journal", "capture-ack":
		return duty, duty, 1, true, true
	case "capture-intent-read", "capacity-profile-read", "worker-config-read":
		return duty, duty, 1, false, true
	default:
		return "", "", 0, false, false
	}
}

// publicPools opens the fixed hub pools on first use and verifies their actual
// credential against the immutable installer manifest. Typed adapter duties
// share a pool unless they have an explicit reservation above.
type publicPools struct {
	in       *providerInputs
	manifest contracts.PublicRuntimeCredentialManifest
	governor *postgres.SQLConnectionGovernor
	mu       sync.Mutex
	closed   bool
	pools    map[string]*pgxpool.Pool
}

// files is the public root: the owner root in the legacy layout, the public
// projection in the installed layout (ADR-182).
func readPublicRuntimeManifest(ctx context.Context, in *ownerInputs, files *providerInputs) (contracts.PublicRuntimeCredentialManifest, error) {
	var zero contracts.PublicRuntimeCredentialManifest
	b, e := mounts.Read(ctx, files.files, contracts.PublicRuntimeCredentialManifestFile, contracts.PublicRuntimeCredentialManifestMaxBytes)
	if e != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	m, e := contracts.DecodePublicRuntimeCredentialManifest(bytes.NewReader(b))
	c := in.config
	if e != nil || m.Format != contracts.PublicRuntimeCredentialManifestFormat || m.Input.InstallationID != c.InstallationID || m.Input.ClusterID != c.ClusterID || m.Input.Namespace != c.Namespace || m.Input.OwnerConfigurationUID != c.ConfigurationUID {
		return zero, mounts.ErrUnavailable
	}
	if m.Input.LayoutDigest != postgres.PublicRuntimeRoleLayoutDigest() {
		return zero, errors.Join(mounts.ErrUnavailable, contracts.ErrPublicRuntimeLayout)
	}
	return m, nil
}

func (p *publicPools) open(ctx context.Context, purpose string) (*pgxpool.Pool, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, mounts.ErrUnavailable
	}
	role, key, limit, hot, ok := publicPoolPlan(purpose)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	if pool := p.pools[key]; pool != nil {
		return pool, nil
	}
	name, known := postgres.PublicRuntimeRoleName(p.manifest.Input.InstallationID, role)
	if !known {
		return nil, mounts.ErrUnavailable
	}
	c, e := p.in.sqlConfig(ctx, "sql-public-"+role+".json")
	if e != nil || c == nil || c.ConnConfig.User != name {
		return nil, mounts.ErrUnavailable
	}
	c.MaxConns, c.MinConns = int32(limit), 0
	if p.governor.Govern(c, hot) != nil {
		return nil, mounts.ErrUnavailable
	}
	pool, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	if postgres.VerifyPublicRuntimeCredential(ctx, pool, p.manifest, role) != nil {
		pool.Close()
		return nil, mounts.ErrUnavailable
	}
	if p.pools == nil {
		p.pools = map[string]*pgxpool.Pool{}
	}
	p.pools[key] = pool
	return pool, nil
}

func (p *publicPools) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	pools := p.pools
	p.pools = nil
	p.mu.Unlock()
	for _, pool := range pools {
		pool.Close()
	}
}
