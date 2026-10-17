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

type BrowserSessions struct {
	ledger      *Ledger
	root, epoch string
	binding     value.BrowserBinding
}

var _ app.BrowserSessionStore = (*BrowserSessions)(nil)
var _ app.SessionCleanup = (*BrowserSessions)(nil)

func (s *BrowserSessions) Cleanup(ctx context.Context) error {
	// Cleanup is allowed while the root is disabled, but only under the exact
	// current epoch. Restoration cannot restart an old cleanup authority.
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		root, e := q.LockBrowserRoot(ctx, id(s.root))
		if e != nil || uid(root.Epoch) != s.epoch {
			return value.ErrDenied
		}
		if e = q.PruneBrowserLogins(ctx, custodydb.PruneBrowserLoginsParams{RootID: id(s.root), Epoch: id(s.epoch)}); e != nil {
			return e
		}
		if e = q.PruneBrowserSessions(ctx, custodydb.PruneBrowserSessionsParams{RootID: id(s.root), Epoch: id(s.epoch)}); e != nil {
			return e
		}
		if e = q.PruneJoinedBrowserRefreshOwners(ctx, id(s.root)); e != nil {
			return e
		}
		return q.PruneBrowserLogout(ctx, custodydb.PruneBrowserLogoutParams{RootID: id(s.root), Epoch: id(s.epoch)})
	})
	if err != nil {
		return value.ErrUnavailable
	}
	return nil
}

func NewBrowserSessions(ctx context.Context, pool *pgxpool.Pool, binding value.BrowserBinding) (*BrowserSessions, error) {
	if !binding.Valid() {
		return nil, value.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &BrowserSessions{ledger: l, root: binding.RootID, epoch: binding.Epoch, binding: binding}, nil
}
func (s *BrowserSessions) transaction(ctx context.Context, exclusive bool, f func(*custodydb.Queries, custodydb.BrowserSessionRoot) error) error {
	return s.withRoot(ctx, exclusive, true, f)
}
func (s *BrowserSessions) withRoot(ctx context.Context, exclusive, current bool, f func(*custodydb.Queries, custodydb.BrowserSessionRoot) error) error {
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var root custodydb.BrowserSessionRoot
		var e error
		if exclusive {
			root, e = q.LockBrowserRoot(ctx, id(s.root))
		} else {
			root, e = q.ShareBrowserRoot(ctx, id(s.root))
		}
		if e != nil || uid(root.Epoch) != s.epoch {
			return value.ErrDenied
		}
		if current {
			now, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			if !browserSettingsCurrent(root, now.Time) {
				return value.ErrUnavailable
			}
		}
		if root.Issuer.String != s.binding.Issuer || root.ClientID.String != s.binding.ClientID || root.Origin.String != s.binding.Origin {
			return value.ErrDenied
		}
		if e = f(q, root); e != nil {
			return e
		}
		if current {
			now, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			if !browserSettingsCurrent(root, now.Time) {
				return value.ErrUnavailable
			}
		}
		return nil
	})
	for _, e := range []error{value.ErrDenied, value.ErrInvalid, value.ErrSessionBusy, value.ErrSessionCapacity} {
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
	return s.transaction(ctx, true, func(q *custodydb.Queries, r custodydb.BrowserSessionRoot) error {
		if e := q.PruneBrowserLogins(ctx, custodydb.PruneBrowserLoginsParams{RootID: id(s.root), Epoch: id(s.epoch)}); e != nil {
			return e
		}
		n, e := q.CountBrowserLogins(ctx, id(s.root))
		if e != nil {
			return e
		}
		if n >= int64(r.MaxLogins) {
			return value.ErrSessionCapacity
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !l.Valid(now.Time) {
			return value.ErrDenied
		}
		return q.InsertBrowserLogin(ctx, custodydb.InsertBrowserLoginParams{RootID: id(s.root), Epoch: id(s.epoch), ID: l.ID[:], Browser: l.Browser[:], Ciphertext: l.Ciphertext, CreatedAt: ts(l.CreatedAt), ExpiresAt: ts(l.ExpiresAt)})
	})
}
func (s *BrowserSessions) TakeLogin(ctx context.Context, key, browser [32]byte) (value.BrowserLogin, error) {
	var out value.BrowserLogin
	err := s.transaction(ctx, false, func(q *custodydb.Queries, _ custodydb.BrowserSessionRoot) error {
		r, e := q.ConsumeBrowserLogin(ctx, custodydb.ConsumeBrowserLoginParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:], Browser: browser[:]})
		if errors.Is(e, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if e != nil {
			return e
		}
		out = value.BrowserLogin{ID: key, Browser: browser, Ciphertext: r.Ciphertext, CreatedAt: r.CreatedAt.Time.UTC(), ExpiresAt: r.ExpiresAt.Time.UTC()}
		// Commit consumption even when expired. Return denial after commit.
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
func sessionObservation(r custodydb.BrowserSessionRoot, expires time.Time) value.SessionObservation {
	out := value.SessionObservation{Settings: value.Revision{UID: r.SourceUid.String, Generation: r.SourceGeneration.Int64}, ObservedAt: r.ObservedAt.Time.UTC(), FreshUntil: value.Earlier(r.FreshUntil.Time.UTC(), expires)}
	copy(out.Settings.Digest[:], r.SourceDigest)
	return out
}
func (s *BrowserSessions) CreateSession(ctx context.Context, r value.BrowserSession) (value.BrowserSession, error) {
	err := s.transaction(ctx, true, func(q *custodydb.Queries, root custodydb.BrowserSessionRoot) error {
		if r.Principal.Issuer != root.Issuer.String || r.Principal.ClientID != root.ClientID.String {
			return value.ErrDenied
		}
		r.ExpiresAt = value.Earlier(r.ExpiresAt, r.CreatedAt.Add(time.Duration(root.MaxLifetimeSeconds.Int32)*time.Second))
		r.RefreshAt = value.Earlier(r.RefreshAt, r.ExpiresAt)
		if e := q.PruneBrowserSessions(ctx, custodydb.PruneBrowserSessionsParams{RootID: id(s.root), Epoch: id(s.epoch)}); e != nil {
			return e
		}
		n, e := q.CountBrowserSessions(ctx, id(s.root))
		if e != nil {
			return e
		}
		if n >= int64(root.MaxSessions) {
			return value.ErrSessionCapacity
		}
		n, e = q.CountBrowserSubject(ctx, custodydb.CountBrowserSubjectParams{RootID: id(s.root), Issuer: r.Principal.Issuer, ClientID: r.Principal.ClientID, Subject: r.Principal.Subject, ActorKey: digest(r.Principal)})
		if e != nil {
			return e
		}
		if n >= 10 {
			return value.ErrSessionCapacity
		}
		blocked, e := q.BrowserSessionLoggedOut(ctx, custodydb.BrowserSessionLoggedOutParams{RootID: id(s.root), Epoch: id(s.epoch), Issuer: r.Principal.Issuer, ClientID: r.Principal.ClientID, ProviderSession: r.ProviderSession, Subject: r.Principal.Subject, IssuedAt: ts(r.AuthenticatedAt)})
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
		// A caller cannot bring its own observation. Preserve the current
		// configuration's original deadline through application handoff.
		r.Observation = sessionObservation(root, r.ExpiresAt)
		return q.InsertBrowserSession(ctx, custodydb.InsertBrowserSessionParams{RootID: id(s.root), Epoch: id(s.epoch), ID: r.ID[:], Issuer: r.Principal.Issuer, ClientID: r.Principal.ClientID, Subject: r.Principal.Subject, ProviderSession: r.ProviderSession, Ciphertext: r.Ciphertext, CreatedAt: ts(r.CreatedAt), AuthenticatedAt: ts(r.AuthenticatedAt), ExpiresAt: ts(r.ExpiresAt), RefreshAt: ts(r.RefreshAt)})
	})
	if err != nil {
		return value.BrowserSession{}, err
	}
	return r, nil
}
func (s *BrowserSessions) ReadSession(ctx context.Context, key [32]byte) (value.BrowserSession, error) {
	return s.readSession(ctx, key, true)
}
func (s *BrowserSessions) ReadSessionForCSRF(ctx context.Context, key [32]byte) (value.BrowserSession, error) {
	return s.readSession(ctx, key, false)
}
func (s *BrowserSessions) readSession(ctx context.Context, key [32]byte, current bool) (value.BrowserSession, error) {
	var out value.BrowserSession
	err := s.withRoot(ctx, false, current, func(q *custodydb.Queries, root custodydb.BrowserSessionRoot) error {
		r, e := q.ReadBrowserSession(ctx, custodydb.ReadBrowserSessionParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:]})
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
		if !out.Valid(now.Time) || out.Principal.Issuer != root.Issuer.String || out.Principal.ClientID != root.ClientID.String {
			return value.ErrDenied
		}
		if current && len(r.RefreshClaim) > 0 {
			if !now.Time.Before(r.ClaimUntil.Time) {
				return value.ErrDenied
			}
			return value.ErrSessionBusy
		}
		if current {
			out.Observation = sessionObservation(root, out.ExpiresAt)
		}
		return nil
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
	busy := false
	err := s.transaction(ctx, true, func(q *custodydb.Queries, _ custodydb.BrowserSessionRoot) error {
		r, e := q.LockBrowserSession(ctx, custodydb.LockBrowserSessionParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:]})
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
		owned, e := q.BrowserOwnedRefreshBusy(ctx, custodydb.BrowserOwnedRefreshBusyParams{RootID: id(s.root), SessionID: key[:]})
		if e != nil {
			return e
		}
		if owned {
			// This POST may have seen a stricter current group policy than the
			// persisted due time. Wake the already admitted loop; do not claim a
			// competing provider rotation or extend ownership/attachment grace.
			if _, e = q.WakeBrowserOwnedRefresh(ctx, custodydb.WakeBrowserOwnedRefreshParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:], Version: version}); e != nil {
				return e
			}
			busy = true
			return nil // Commit the shortening before reporting temporary Busy.
		}
		return q.ClaimBrowserRefresh(ctx, custodydb.ClaimBrowserRefreshParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:], RefreshClaim: claim[:], ClaimUntil: ts(value.Earlier(r.ExpiresAt.Time, now.Time.Add(10*time.Second)))})
	})
	if err != nil {
		return err
	}
	if busy {
		return value.ErrSessionBusy
	}
	return nil
}
func (s *BrowserSessions) FinishRefresh(ctx context.Context, key [32]byte, version int64, claim [32]byte, blob []byte, refreshAt time.Time) error {
	return s.transaction(ctx, false, func(q *custodydb.Queries, _ custodydb.BrowserSessionRoot) error {
		r, e := q.LockBrowserSession(ctx, custodydb.LockBrowserSessionParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:]})
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
		return q.FinishBrowserRefresh(ctx, custodydb.FinishBrowserRefreshParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:], Ciphertext: blob, RefreshAt: ts(refreshAt)})
	})
}
func (s *BrowserSessions) RevokeSession(ctx context.Context, key [32]byte) error {
	return s.withRoot(ctx, false, false, func(q *custodydb.Queries, _ custodydb.BrowserSessionRoot) error {
		return q.DeleteBrowserSession(ctx, custodydb.DeleteBrowserSessionParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:]})
	})
}
func (s *BrowserSessions) LogoutSessions(ctx context.Context, event app.LogoutEvent) error {
	if !value.Text(event.Issuer, 2048) || !value.Text(event.ClientID, 256) || !value.Text(event.ID, 256) || event.Subject == "" && event.SessionID == "" || event.Subject != "" && !value.Text(event.Subject, 256) || event.SessionID != "" && !value.Text(event.SessionID, 256) {
		return value.ErrInvalid
	}
	b, _ := json.Marshal([]string{event.Issuer, event.ClientID, event.ID})
	key := sha256.Sum256(b)
	return s.withRoot(ctx, true, false, func(q *custodydb.Queries, r custodydb.BrowserSessionRoot) error {
		if r.Issuer.String != event.Issuer || r.ClientID.String != event.ClientID {
			return value.ErrDenied
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !value.Fresh(event.IssuedAt, event.IssuedAt.Add(5*time.Minute), now.Time, 5*time.Minute) {
			return value.ErrDenied
		}
		old, e := q.ReadBrowserLogout(ctx, custodydb.ReadBrowserLogoutParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:]})
		if e == nil {
			if old.Issuer == event.Issuer && old.ClientID == event.ClientID && old.Subject == event.Subject && old.ProviderSession == event.SessionID && old.IssuedAt.Time.Equal(event.IssuedAt) {
				return nil
			}
			return value.ErrDenied
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e = q.PruneBrowserLogout(ctx, custodydb.PruneBrowserLogoutParams{RootID: id(s.root), Epoch: id(s.epoch)}); e != nil {
			return e
		}
		n, e := q.CountBrowserLogout(ctx, id(s.root))
		if e != nil {
			return e
		}
		if n >= int64(r.MaxLogoutEvents) {
			return value.ErrSessionCapacity
		}
		now, e = q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !value.Fresh(event.IssuedAt, event.IssuedAt.Add(5*time.Minute), now.Time, 5*time.Minute) {
			return value.ErrDenied
		}
		if e = q.InsertBrowserLogout(ctx, custodydb.InsertBrowserLogoutParams{RootID: id(s.root), Epoch: id(s.epoch), ID: key[:], Issuer: event.Issuer, ClientID: event.ClientID, Subject: event.Subject, ProviderSession: event.SessionID, IssuedAt: ts(event.IssuedAt), ExpiresAt: ts(event.IssuedAt.Add(25 * time.Hour))}); e != nil {
			return e
		}
		return q.RevokeBrowserProviderSessions(ctx, custodydb.RevokeBrowserProviderSessionsParams{RootID: id(s.root), Epoch: id(s.epoch), Issuer: event.Issuer, ClientID: event.ClientID, Subject: event.Subject, ProviderSession: event.SessionID, IssuedAt: ts(event.IssuedAt)})
	})
}

// A refresh schedule is work due time, not an authority lease. This predicate
// still checks the actual session and one-use claim after database locks.
func browserRefreshDatesCurrent(r value.BrowserSession, claimUntil, refreshAt, now time.Time) bool {
	return r.Valid(now) && now.Before(claimUntil) && refreshAt.After(r.CreatedAt) && !refreshAt.After(r.ExpiresAt)
}
