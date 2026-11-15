package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This port is composed with the fixed capacity credential, not admission or
// user-facing read credentials. SQL binds its session user to the installed
// root and returns no subjects, groups, or immutable audit payload.
type CapacityPermissions struct {
	ledger             *Ledger
	root, installation string
}

var _ app.CapacityPermissionReader = (*CapacityPermissions)(nil)

func NewCapacityPermissions(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*CapacityPermissions, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) {
		return nil, cfg.ErrInvalid
	}
	ledger, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &CapacityPermissions{ledger: ledger, root: root, installation: installation}, nil
}
func decodeCapacityPermissions(raw []byte) (app.AcceptedCapacityPermissions, error) {
	var out app.AcceptedCapacityPermissions
	if len(raw) < 2 || len(raw) > 1<<20 {
		return out, cfg.ErrUnavailable
	}
	validated := jsontext.Value(bytes.Clone(raw))
	if validated.Canonicalize() != nil {
		return out, cfg.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil {
		return app.AcceptedCapacityPermissions{}, cfg.ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return app.AcceptedCapacityPermissions{}, cfg.ErrUnavailable
	}
	canonical, e := json.Marshal(out)
	if e != nil || !capacitySameJSONFields(raw, canonical) {
		return app.AcceptedCapacityPermissions{}, cfg.ErrUnavailable
	}
	return out, nil
}
func (s *CapacityPermissions) ReadCapacityPermissions(ctx context.Context) (app.AcceptedCapacityPermissions, error) {
	var out app.AcceptedCapacityPermissions
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil {
		return out, cfg.ErrUnavailable
	}
	until := time.Now().Add(app.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	e := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, err := capacityTrustJSON(live, q, s.installation)
		if err != nil {
			return err
		}
		raw, err := q.ReadCapacityPermissionScopes(live, custodydb.ReadCapacityPermissionScopesParams{RootID: id(s.root), RecoveryValue: b})
		if err != nil {
			return err
		}
		out, err = decodeCapacityPermissions(raw)
		if err != nil {
			return err
		}
		out.FreshUntil = identity.Earlier(out.FreshUntil, until)
		if out.RootID != s.root || !out.Valid(time.Now()) || live.Err() != nil {
			return cfg.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !out.Valid(time.Now()) {
		return app.AcceptedCapacityPermissions{}, cfg.ErrUnavailable
	}
	return out, nil
}
