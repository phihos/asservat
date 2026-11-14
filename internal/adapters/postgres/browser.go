package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BrowserSessions stores browser logins, sessions and back-channel logouts.
// The process reads browser.json once at start (a change rolls hub-api);
// NewBrowserSessions shortens existing sessions to its maximum lifetime.
type BrowserSessions struct {
	ledger   *Ledger
	settings value.BrowserSettings
}

var _ app.BrowserSessionStore = (*BrowserSessions)(nil)

func NewBrowserSessions(ctx context.Context, pool *pgxpool.Pool, settings value.BrowserSettings) (*BrowserSessions, error) {
	if !settings.Valid() {
		return nil, value.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	s := &BrowserSessions{ledger: l, settings: settings}
	if e = s.transaction(ctx, func(q *custodydb.Queries) error {
		return q.ClampBrowserSessionLifetimes(ctx, int64(settings.MaxLifetime/time.Second))
	}); e != nil {
		return nil, e
	}
	return s, nil
}

func (s *BrowserSessions) inactivity() int64 { return int64(s.settings.InactivityTimeout / time.Second) }

func (s *BrowserSessions) transaction(ctx context.Context, f func(*custodydb.Queries) error) error {
	err := s.ledger.transaction(ctx, f)
	for _, e := range []error{value.ErrDenied, value.ErrInvalid, value.ErrSessionBusy} {
		if errors.Is(err, e) {
			return e
		}
	}
	if err != nil {
		return value.ErrUnavailable
	}
	return nil
}

func (s *BrowserSessions) PutLogin(ctx context.Context, l value.BrowserLogin) error {
	return s.transaction(ctx, func(q *custodydb.Queries) error {
		if e := q.PruneBrowserLogins(ctx); e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !l.Valid(now.Time) {
			return value.ErrDenied
		}
		return q.InsertBrowserLogin(ctx, custodydb.InsertBrowserLoginParams{ID: l.ID[:], Browser: l.Browser[:], Ciphertext: l.Ciphertext, CreatedAt: ts(l.CreatedAt), ExpiresAt: ts(l.ExpiresAt)})
	})
}

func (s *BrowserSessions) TakeLogin(ctx context.Context, key, browser [32]byte) (value.BrowserLogin, error) {
	var out value.BrowserLogin
	err := s.transaction(ctx, func(q *custodydb.Queries) error {
		r, e := q.ConsumeBrowserLogin(ctx, custodydb.ConsumeBrowserLoginParams{ID: key[:], Browser: browser[:]})
		if errors.Is(e, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if e != nil {
			return e
		}
		// Consumption commits even when expired; the caller checks validity.
		out = value.BrowserLogin{ID: key, Browser: browser, Ciphertext: r.Ciphertext, CreatedAt: r.CreatedAt.Time.UTC(), ExpiresAt: r.ExpiresAt.Time.UTC()}
		return nil
	})
	if err != nil {
		return value.BrowserLogin{}, err
	}
	return out, nil
}

func browserRecord(r custodydb.BrowserSession) value.BrowserSession {
	out := value.BrowserSession{Principal: value.Principal{Issuer: r.Issuer, Subject: r.Subject, ClientID: r.ClientID, Kind: value.Human}, ProviderSession: r.ProviderSession, Ciphertext: r.Ciphertext, CreatedAt: r.CreatedAt.Time.UTC(), AuthenticatedAt: r.AuthenticatedAt.Time.UTC(), ExpiresAt: r.ExpiresAt.Time.UTC(), RefreshAt: r.RefreshAt.Time.UTC(), Version: r.Version}
	copy(out.ID[:], r.ID)
	return out
}

func (s *BrowserSessions) CreateSession(ctx context.Context, r value.BrowserSession) (value.BrowserSession, error) {
	err := s.transaction(ctx, func(q *custodydb.Queries) error {
		if r.Principal.Issuer != s.settings.Issuer || r.Principal.ClientID != s.settings.ClientID {
			return value.ErrDenied
		}
		r.ExpiresAt = value.Earlier(r.ExpiresAt, r.CreatedAt.Add(s.settings.MaxLifetime))
		r.RefreshAt = value.Earlier(r.RefreshAt, r.ExpiresAt)
		if e := q.PruneBrowserSessions(ctx, s.inactivity()); e != nil {
			return e
		}
		blocked, e := q.BrowserSessionLoggedOut(ctx, custodydb.BrowserSessionLoggedOutParams{Issuer: r.Principal.Issuer, ClientID: r.Principal.ClientID, ProviderSession: r.ProviderSession, Subject: r.Principal.Subject, IssuedAt: ts(r.AuthenticatedAt)})
		if e != nil {
			return e
		}
		if blocked {
			return value.ErrDenied
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if r.Version != 1 || !r.Valid(now.Time) {
			return value.ErrDenied
		}
		return q.InsertBrowserSession(ctx, custodydb.InsertBrowserSessionParams{ID: r.ID[:], Issuer: r.Principal.Issuer, ClientID: r.Principal.ClientID, Subject: r.Principal.Subject, ProviderSession: r.ProviderSession, Ciphertext: r.Ciphertext, CreatedAt: ts(r.CreatedAt), AuthenticatedAt: ts(r.AuthenticatedAt), ExpiresAt: ts(r.ExpiresAt), RefreshAt: ts(r.RefreshAt)})
	})
	if err != nil {
		return value.BrowserSession{}, err
	}
	return r, nil
}

// ReadSession reads an active session and records the request for the
// inactivity timeout (at most one write per session and minute).
func (s *BrowserSessions) ReadSession(ctx context.Context, key [32]byte) (value.BrowserSession, error) {
	return s.readSession(ctx, key, true)
}

// ReadSessionForCSRF reads without counting as activity.
func (s *BrowserSessions) ReadSessionForCSRF(ctx context.Context, key [32]byte) (value.BrowserSession, error) {
	return s.readSession(ctx, key, false)
}

func (s *BrowserSessions) readSession(ctx context.Context, key [32]byte, active bool) (value.BrowserSession, error) {
	var out value.BrowserSession
	err := s.transaction(ctx, func(q *custodydb.Queries) error {
		r, e := q.ReadBrowserSession(ctx, custodydb.ReadBrowserSessionParams{ID: key[:], InactivitySeconds: s.inactivity()})
		if errors.Is(e, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		out = browserRecord(r)
		if !out.Valid(now.Time) || out.Principal.Issuer != s.settings.Issuer || out.Principal.ClientID != s.settings.ClientID {
			return value.ErrDenied
		}
		if !active {
			return nil
		}
		if len(r.RefreshClaim) > 0 {
			if !now.Time.Before(r.ClaimUntil.Time) {
				return value.ErrDenied
			}
			return value.ErrSessionBusy
		}
		return q.TouchBrowserSession(ctx, key[:])
	})
	if err != nil {
		return value.BrowserSession{}, err
	}
	return out, nil
}

func (s *BrowserSessions) ClaimRefresh(ctx context.Context, key [32]byte, version int64, claim [32]byte) error {
	if claim == ([32]byte{}) {
		return value.ErrInvalid
	}
	return s.transaction(ctx, func(q *custodydb.Queries) error {
		r, e := q.LockBrowserSession(ctx, key[:])
		if errors.Is(e, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !browserRecord(r).Valid(now.Time) {
			return value.ErrDenied
		}
		if len(r.RefreshClaim) > 0 {
			if !now.Time.Before(r.ClaimUntil.Time) {
				return value.ErrDenied
			}
			return value.ErrSessionBusy
		}
		if r.Version != version {
			return value.ErrSessionBusy
		}
		return q.ClaimBrowserRefresh(ctx, custodydb.ClaimBrowserRefreshParams{ID: key[:], RefreshClaim: claim[:], ClaimUntil: ts(value.Earlier(r.ExpiresAt.Time, now.Time.Add(10*time.Second)))})
	})
}

func (s *BrowserSessions) FinishRefresh(ctx context.Context, key [32]byte, version int64, claim [32]byte, blob []byte, refreshAt time.Time) error {
	return s.transaction(ctx, func(q *custodydb.Queries) error {
		r, e := q.LockBrowserSession(ctx, key[:])
		if errors.Is(e, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !r.ClaimUntil.Valid || !browserRefreshDatesCurrent(browserRecord(r), r.ClaimUntil.Time, refreshAt, now.Time) || !bytes.Equal(r.RefreshClaim, claim[:]) || r.Version != version || len(blob) == 0 || len(blob) > value.MaxSessionCiphertext {
			return value.ErrDenied
		}
		return q.FinishBrowserRefresh(ctx, custodydb.FinishBrowserRefreshParams{ID: key[:], Ciphertext: blob, RefreshAt: ts(refreshAt)})
	})
}

func (s *BrowserSessions) RevokeSession(ctx context.Context, key [32]byte) error {
	return s.transaction(ctx, func(q *custodydb.Queries) error {
		return q.DeleteBrowserSession(ctx, key[:])
	})
}

// LogoutSessions records a verified back-channel logout and revokes the
// matching sessions. A receipt outlives every session it can block.
func (s *BrowserSessions) LogoutSessions(ctx context.Context, event app.LogoutEvent) error {
	if !value.Text(event.Issuer, 2048) || !value.Text(event.ClientID, 256) || !value.Text(event.ID, 256) || event.Subject == "" && event.SessionID == "" || event.Subject != "" && !value.Text(event.Subject, 256) || event.SessionID != "" && !value.Text(event.SessionID, 256) {
		return value.ErrInvalid
	}
	if event.Issuer != s.settings.Issuer || event.ClientID != s.settings.ClientID {
		return value.ErrDenied
	}
	b, _ := json.Marshal([]string{event.Issuer, event.ClientID, event.ID})
	key := sha256.Sum256(b)
	return s.transaction(ctx, func(q *custodydb.Queries) error {
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !value.Fresh(event.IssuedAt, event.IssuedAt.Add(5*time.Minute), now.Time, 5*time.Minute) {
			return value.ErrDenied
		}
		old, e := q.ReadBrowserLogout(ctx, key[:])
		if e == nil {
			if old.Issuer == event.Issuer && old.ClientID == event.ClientID && old.Subject == event.Subject && old.ProviderSession == event.SessionID && old.IssuedAt.Time.Equal(event.IssuedAt) {
				return nil
			}
			return value.ErrDenied
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e = q.PruneBrowserLogout(ctx); e != nil {
			return e
		}
		if e = q.InsertBrowserLogout(ctx, custodydb.InsertBrowserLogoutParams{ID: key[:], Issuer: event.Issuer, ClientID: event.ClientID, Subject: event.Subject, ProviderSession: event.SessionID, IssuedAt: ts(event.IssuedAt), ExpiresAt: ts(event.IssuedAt.Add(s.settings.MaxLifetime + time.Hour))}); e != nil {
			return e
		}
		return q.RevokeBrowserProviderSessions(ctx, custodydb.RevokeBrowserProviderSessionsParams{Issuer: event.Issuer, ClientID: event.ClientID, Subject: event.Subject, ProviderSession: event.SessionID, IssuedAt: ts(event.IssuedAt)})
	})
}

// A refresh schedule is work due time, not an authority lease. This predicate
// still checks the actual session and one-use claim after database locks.
func browserRefreshDatesCurrent(r value.BrowserSession, claimUntil, refreshAt, now time.Time) bool {
	return r.Valid(now) && now.Before(claimUntil) && refreshAt.After(r.CreatedAt) && !refreshAt.After(r.ExpiresAt)
}
