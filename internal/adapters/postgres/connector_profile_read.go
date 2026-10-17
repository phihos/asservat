package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectorIdentityProfiles reads one peer's staged connector identity
// (ADR-193). The federation composes a peer's duties from these rows instead
// of an installation-pinned peer list. Staging stays the only writer; the read
// grants nothing, and every duty still checks current source and recovery.
type ConnectorIdentityProfiles struct{ ledger *Ledger }

func NewConnectorIdentityProfiles(ctx context.Context, pool *pgxpool.Pool) (*ConnectorIdentityProfiles, error) {
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ConnectorIdentityProfiles{l}, nil
}

// ReadStagedConnector returns the staged profile (with the regional guard's
// protection digest) and the root's current backing for exactly the
// presented peer. A suspended, blocked or never staged peer is unavailable.
func (s *ConnectorIdentityProfiles) ReadStagedConnector(ctx context.Context, p value.ClusterCredentialProfile) (value.ConnectorCredentialProfile, app.ConnectorIdentityBacking, error) {
	var profile value.ConnectorCredentialProfile
	var backing app.ConnectorIdentityBacking
	if s == nil || ctx == nil || ctx.Err() != nil || !p.Valid() {
		return profile, backing, value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var rawProfile, rawBacking string
	var suspended, blocked bool
	err := s.ledger.pool.QueryRow(call, `SELECT p.configuration::text, r.backing::text, p.suspended, p.blocked
		FROM public.connector_identity_profile p JOIN public.connector_identity_root r ON r.root_id=p.root_id
		WHERE p.root_id=$1 AND p.peer_id=$2 AND p.installation_id=$3 AND p.cluster_id=$4`, p.RootID, p.PeerID, p.InstallationID, p.ClusterID).Scan(&rawProfile, &rawBacking, &suspended, &blocked)
	if err != nil || suspended || blocked || strictJSON(rawProfile, &profile) != nil || strictJSON(rawBacking, &backing) != nil {
		return value.ConnectorCredentialProfile{}, app.ConnectorIdentityBacking{}, value.ErrUnavailable
	}
	b := profile.Binding
	if profile.RootID != p.RootID || b.PeerID != p.PeerID || b.InstallationID != p.InstallationID || b.ClusterID != p.ClusterID || b.Role != value.ConnectorPeer ||
		!profile.Valid() || profile.Suspended || !backing.Valid() || backing.Policy.RootID != p.RootID || backing.Policy.InstallationID != p.InstallationID {
		return value.ConnectorCredentialProfile{}, app.ConnectorIdentityBacking{}, value.ErrUnavailable
	}
	return profile, backing, nil
}

// ReadConnectorProfile returns exactly the presented peer's staged profile,
// without the root backing, for the key service's peer resolver (ADR-198).
// A suspended, blocked or never staged peer is unavailable.
func (s *ConnectorIdentityProfiles) ReadConnectorProfile(ctx context.Context, p value.ClusterCredentialProfile) (value.ConnectorCredentialProfile, error) {
	var profile value.ConnectorCredentialProfile
	if s == nil || ctx == nil || ctx.Err() != nil || !p.Valid() {
		return profile, value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var raw string
	var suspended, blocked bool
	err := s.ledger.pool.QueryRow(call, `SELECT configuration::text, suspended, blocked FROM public.connector_identity_profile
		WHERE root_id=$1 AND peer_id=$2 AND installation_id=$3 AND cluster_id=$4`, p.RootID, p.PeerID, p.InstallationID, p.ClusterID).Scan(&raw, &suspended, &blocked)
	if err != nil || suspended || blocked || strictJSON(raw, &profile) != nil {
		return value.ConnectorCredentialProfile{}, value.ErrUnavailable
	}
	b := profile.Binding
	if profile.RootID != p.RootID || b.PeerID != p.PeerID || b.InstallationID != p.InstallationID || b.ClusterID != p.ClusterID || b.Role != value.ConnectorPeer || !profile.Valid() || profile.Suspended {
		return value.ConnectorCredentialProfile{}, value.ErrUnavailable
	}
	return profile, nil
}

// ReadRootBacking returns the connector root's stored backing; found is
// false before the first staging created the root.
func (s *ConnectorIdentityProfiles) ReadRootBacking(ctx context.Context, root string) (app.ConnectorIdentityBacking, bool, error) {
	var backing app.ConnectorIdentityBacking
	if s == nil || ctx == nil || ctx.Err() != nil {
		return backing, false, value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var raw string
	err := s.ledger.pool.QueryRow(call, `SELECT backing::text FROM public.connector_identity_root WHERE root_id=$1`, root).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return backing, false, nil
	}
	if err != nil || strictJSON(raw, &backing) != nil || !backing.Valid() || backing.Policy.RootID != root {
		return app.ConnectorIdentityBacking{}, false, value.ErrUnavailable
	}
	return backing, true, nil
}

func strictJSON(s string, v any) error {
	d := json.NewDecoder(bytes.NewReader([]byte(s)))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
