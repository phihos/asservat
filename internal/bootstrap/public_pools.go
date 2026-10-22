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

// hubAPIHotPurposes keep one dedicated governed connection (ADR-177): the
// browser session and refresh lanes, both audit lanes, capture admission and
// its journal, downloads and native owners. Every other purpose is cold.
var hubAPIHotPurposes = []string{"browser-session", "refresh-admit", "refresh-owner", "audit-normal-journal", "audit-normal-ack", "audit-resolution-journal", "audit-resolution-ack", "capture-admit", "capture-journal", "capture-ack", "download-session", "native-owner"}

// publicPools opens hub-api's public purpose pools on first use. Each pool is
// governed and verified against the installer's immutable role manifest. The
// metadata pool retains the former seven readers' aggregate concurrency; every
// other credential has MaxConns=1. No runtime role is adopted or migrated.
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
	if pool := p.pools[purpose]; pool != nil {
		return pool, nil
	}
	name, known := postgres.PublicRuntimeRoleName(p.manifest.Input.InstallationID, purpose)
	// The browser settings observer and cleanup belong to the hub-worker.
	if !known || !slices.Contains(contracts.PublicRuntimeHubRolePurposes(), purpose) || purpose == "browser-settings" || purpose == "browser-cleanup" {
		return nil, mounts.ErrUnavailable
	}
	c, e := p.in.sqlConfig(ctx, "sql-public-"+purpose+".json")
	if e != nil || c == nil || c.ConnConfig.User != name {
		return nil, mounts.ErrUnavailable
	}
	limit, ok := contracts.PublicRuntimeRolePoolLimit(purpose)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	c.MaxConns, c.MinConns = int32(limit), 0
	if p.governor.Govern(c, slices.Contains(hubAPIHotPurposes, purpose)) != nil {
		return nil, mounts.ErrUnavailable
	}
	pool, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	if postgres.VerifyPublicRuntimeCredential(ctx, pool, p.manifest, purpose) != nil {
		pool.Close()
		return nil, mounts.ErrUnavailable
	}
	if p.pools == nil {
		p.pools = map[string]*pgxpool.Pool{}
	}
	p.pools[purpose] = pool
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
