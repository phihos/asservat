package postgres

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BrowserSettingsProjection has separate SQL credentials from browser ingress.
// Only the protected Kubernetes observer supplies settings to this facet.
type BrowserSettingsProjection struct {
	ledger *Ledger
	root   string
}

var _ app.BrowserSettingsProjection = (*BrowserSettingsProjection)(nil)

func NewBrowserSettingsProjection(ctx context.Context, pool *pgxpool.Pool, root string) (*BrowserSettingsProjection, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &BrowserSettingsProjection{l, root}, nil
}
func (s *BrowserSettingsProjection) ObserveBrowserSettings(ctx context.Context, a value.BrowserSettings) error {
	if a.RootID != s.root || !a.Valid(a.ObservedAt) {
		return value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if e := q.InsertBlockedBrowserRoot(ctx, custodydb.InsertBlockedBrowserRootParams{ID: id(s.root), Epoch: id(a.Epoch), MaxLogins: int32(a.MaxLogins), MaxSessions: int32(a.MaxSessions), MaxLogoutEvents: int32(a.MaxLogoutEvents)}); e != nil {
			return e
		}
		r, e := q.LockBrowserRoot(ctx, id(s.root))
		if e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !a.Valid(now.Time) {
			return value.ErrDenied
		}
		if r.SourceUid.Valid {
			if r.SourceUid.String != a.Revision.UID || a.Revision.Generation < r.SourceGeneration.Int64 || a.Revision.Generation == r.SourceGeneration.Int64 && !bytes.Equal(r.SourceDigest, a.Revision.Digest[:]) || a.ObservedAt.Before(r.ObservedAt.Time) {
				return value.ErrDenied
			}
			// Changes to the browser authority binding require a new epoch. Stable
			// settings updates may narrow ceilings without logging everyone out.
			bindingChanged := r.Issuer.String != a.Issuer || r.ClientID.String != a.ClientID || r.Origin.String != a.Origin
			if bindingChanged && uid(r.Epoch) == a.Epoch {
				return value.ErrDenied
			}
			if uid(r.Epoch) != a.Epoch {
				seen, e := q.BrowserEpochSeen(ctx, custodydb.BrowserEpochSeenParams{RootID: id(s.root), Epoch: id(a.Epoch)})
				if e != nil {
					return e
				}
				if seen {
					return value.ErrDenied
				}
			}
		} else {
			// Migration from private unqualified fixtures cannot turn their old
			// cookies/challenges into production credentials.
			if e = q.RevokeUnqualifiedBrowserLogins(ctx, id(s.root)); e != nil {
				return e
			}
			if e = q.RevokeUnqualifiedBrowserSessions(ctx, id(s.root)); e != nil {
				return e
			}
		}
		if e = q.RecordBrowserEpoch(ctx, custodydb.RecordBrowserEpochParams{RootID: id(s.root), Epoch: id(a.Epoch), SourceGeneration: a.Revision.Generation}); e != nil {
			return e
		}
		text := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
		if e = q.ObserveBrowserSettings(ctx, custodydb.ObserveBrowserSettingsParams{ID: id(s.root), Epoch: id(a.Epoch), Enabled: !a.Suspended, MaxLogins: int32(a.MaxLogins), MaxSessions: int32(a.MaxSessions), MaxLogoutEvents: int32(a.MaxLogoutEvents), SourceUid: text(a.Revision.UID), SourceGeneration: pgtype.Int8{Int64: a.Revision.Generation, Valid: true}, SourceDigest: a.Revision.Digest[:], ObservedAt: ts(a.ObservedAt), FreshUntil: ts(a.FreshUntil), Issuer: text(a.Issuer), ClientID: text(a.ClientID), Origin: text(a.Origin), MaxLifetimeSeconds: pgtype.Int4{Int32: int32(a.MaxLifetimeSeconds), Valid: true}}); e != nil {
			return e
		}
		if e = q.ClampBrowserSessionLifetimes(ctx, custodydb.ClampBrowserSessionLifetimesParams{RootID: id(s.root), MaxLifetimeSeconds: int32(a.MaxLifetimeSeconds)}); e != nil {
			return e
		}
		now, e = q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !a.Valid(now.Time) {
			return value.ErrDenied
		}
		return nil
	})
	if err != nil {
		return value.ErrUnavailable
	}
	return nil
}
func (s *BrowserSettingsProjection) FenceBrowserSettings(ctx context.Context, started time.Time) error {
	if started.IsZero() {
		return value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, e := q.LockBrowserRoot(ctx, id(s.root)); e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if started.After(now.Time) {
			return value.ErrInvalid
		}
		return q.FenceBrowserSettings(ctx, custodydb.FenceBrowserSettingsParams{ID: id(s.root), ObservedAt: ts(started)})
	})
	if err != nil {
		return value.ErrUnavailable
	}
	return nil
}
func browserSettingsCurrent(r custodydb.BrowserSessionRoot, now time.Time) bool {
	return r.Enabled && r.SourceUid.Valid && r.SourceGeneration.Valid && len(r.SourceDigest) == 32 && r.Issuer.Valid && r.ClientID.Valid && r.Origin.Valid && r.MaxLifetimeSeconds.Valid && value.Fresh(r.ObservedAt.Time, r.FreshUntil.Time, now, 5*time.Second)
}
