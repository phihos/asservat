package postgres

import (
	"context"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectorObservationRegistry owns one original scoped registry ledger and
// installed profile. Only a source reader is bound per conversation; no pool,
// role, accepted source or deadline can be selected by a remote request.
type ConnectorObservationRegistry struct {
	ledger  *Ledger
	profile value.ConnectorCredentialProfile
}

var _ app.ConnectorObservationRegistry = (*ConnectorObservationRegistry)(nil)

func NewConnectorObservationRegistry(ctx context.Context, pool *pgxpool.Pool, profile value.ConnectorCredentialProfile) (*ConnectorObservationRegistry, error) {
	if ctx == nil || ctx.Err() != nil || !profile.Valid() || profile.Suspended || profile.Retiring {
		return nil, value.ErrUnavailable
	}
	ledger, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &ConnectorObservationRegistry{ledger: ledger, profile: profile.Clone()}, nil
}

func (s *ConnectorObservationRegistry) ReadConnectorObservationRegistration(ctx context.Context, original value.ConnectorCredentialProfile, source app.ConnectorIdentitySourceReader, leaf value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || source == nil || !s.profile.Equal(original) || !leaf.Valid(time.Now()) || leaf.Usage != "client" || leaf.Binding != s.profile.Binding {
		return app.ConnectorLeafRegistration{}, value.ErrUnavailable
	}
	// Reuse the existing exact current SQL49 read, including both fresh source
	// reads, original caller/source intersection and post-lock database checks.
	// The original profile is installation provenance, not a requirement that a
	// later compatible, independently accepted revision equal its first revision.
	bound := ConnectorRegistry{ledger: s.ledger, source: source, profile: s.profile}
	return bound.ConnectorLeafRegistration(ctx, leaf)
}
