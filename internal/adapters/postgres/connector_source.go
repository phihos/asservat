package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The installation gives this producer only the two private source RPCs. SQL
// resolves every pinned login's real catalog identity under the current database
// incarnation. No caller-supplied OID, credential or accepted-source status exists.
type ConnectorIdentitySources struct {
	ledger        *Ledger
	root          string
	binding       value.PeerBinding
	qualification app.ConnectorQualificationPin
}

var _ app.ConnectorIdentitySourceJournal = (*ConnectorIdentitySources)(nil)

func NewConnectorIdentitySources(ctx context.Context, pool *pgxpool.Pool, root string, binding value.PeerBinding, qualification app.ConnectorQualificationPin) (*ConnectorIdentitySources, error) {
	if !authorization.UUID(root) || !binding.Valid() || binding.Role != value.ConnectorPeer || qualification.InstallationID != binding.InstallationID || !qualification.Qualification.Valid() {
		return nil, value.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ConnectorIdentitySources{ledger: l, root: root, binding: binding, qualification: qualification}, nil
}
func (s *ConnectorIdentitySources) StageConnectorIdentity(ctx context.Context, c app.ConnectorIdentityConfiguration) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !c.Valid(time.Now()) || c.Source.Observation.Profile.RootID != s.root || c.Source.Observation.Profile.Binding != s.binding || !s.qualification.Matches(c) {
		return value.ErrUnavailable
	}
	c = c.Clone()
	live, end := context.WithDeadline(ctx, c.Source.Observation.FreshUntil)
	defer end()
	b, e := json.Marshal(c)
	if e != nil || len(b) > 192<<10 {
		return value.ErrInvalid
	}
	q, e := json.Marshal(s.qualification.Qualification)
	if e != nil {
		return value.ErrInvalid
	}
	accepted := false
	e = s.ledger.transaction(live, func(db *custodydb.Queries) error {
		var err error
		accepted, err = db.StageConnectorIdentity(live, custodydb.StageConnectorIdentityParams{RootID: id(s.root), ConfigurationValue: b, QualificationValue: q})
		return err
	})
	if e != nil {
		return value.ErrUnavailable
	}
	if !accepted {
		return value.ErrConflict
	}
	if live.Err() != nil || !c.Valid(time.Now()) {
		return value.ErrUnavailable
	}
	return nil
}
func (s *ConnectorIdentitySources) FenceConnectorIdentity(ctx context.Context, b value.PeerBinding, at time.Time) error {
	if s == nil || ctx == nil || ctx.Err() != nil || b != s.binding || at.IsZero() || at.After(time.Now()) {
		return value.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return q.FenceConnectorIdentity(ctx, custodydb.FenceConnectorIdentityParams{RootID: id(s.root), PeerID: id(b.PeerID), ObservedAt: ts(at.UTC().Truncate(time.Microsecond))})
	})
}
