package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

type BrowserSessionStore interface {
	PutLogin(context.Context, value.BrowserLogin) error
	TakeLogin(context.Context, [32]byte, [32]byte) (value.BrowserLogin, error)
	CreateSession(context.Context, value.BrowserSession) (value.BrowserSession, error)
	ReadSession(context.Context, [32]byte) (value.BrowserSession, error)
	ReadSessionForCSRF(context.Context, [32]byte) (value.BrowserSession, error)
	ClaimRefresh(context.Context, [32]byte, int64, [32]byte) error
	FinishRefresh(context.Context, [32]byte, int64, [32]byte, []byte, time.Time) error
	RevokeSession(context.Context, [32]byte) error
	LogoutSessions(context.Context, LogoutEvent) error
}
type CredentialCipher interface {
	Encrypt(context.Context, []byte, []byte) ([]byte, error)
	Decrypt(context.Context, []byte, []byte) ([]byte, error)
}

// SessionCleanup has no OIDC credentials and cannot create or renew a session.
// Bootstrap runs the loop independently of HTTP traffic and observes its health.
type SessionCleanup interface{ Cleanup(context.Context) error }

func RunSessionCleanup(ctx context.Context, store SessionCleanup, report func(error)) error {
	if store == nil || report == nil {
		return value.ErrInvalid
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := store.Cleanup(attempt)
		cancel()
		report(err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

type BrowserSessions struct {
	Store                   BrowserSessionStore
	Cipher                  CredentialCipher
	Provider                BrowserProvider
	Identities              Resolver
	Logout                  LogoutVerifier
	Issuer, ClientID, Epoch string
	Lifetime                time.Duration
	Now                     func() time.Time
}
type LoginRedirect struct {
	URL, State, Browser string
	ExpiresAt           time.Time
}
type SessionView struct {
	Identity  value.Identity
	CSRF      string
	ExpiresAt time.Time
}
type LoginResult struct {
	Cookie, ReturnTo string
	Session          SessionView
}
type loginSecrets struct{ Nonce, Verifier, ReturnTo string }
type sessionSecrets struct{ Access, Refresh, CSRF, Nonce string }

func randomSessionSecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func sessionKey(s string) ([32]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, value.ErrDenied
	}
	return sha256.Sum256([]byte(s)), nil
}
func (s BrowserSessions) configured() bool {
	return s.Store != nil && s.Cipher != nil && s.Provider != nil && s.Identities != nil && s.Now != nil && value.Text(s.Issuer, 2048) && value.Text(s.ClientID, 256) && value.Text(s.Epoch, 64) && s.Lifetime >= time.Minute && s.Lifetime <= 24*time.Hour
}
func (s BrowserSessions) binding(purpose string, key [32]byte, version int64) []byte {
	b, _ := json.Marshal([]any{"asservat-browser/v1", s.Epoch, s.Issuer, s.ClientID, purpose, base64.RawURLEncoding.EncodeToString(key[:]), version})
	digest := sha256.Sum256(b)
	return []byte("asservat-browser/v1:" + base64.RawURLEncoding.EncodeToString(digest[:]))
}
func (s BrowserSessions) seal(ctx context.Context, v any, ad []byte) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	defer clear(b)
	c, e := s.Cipher.Encrypt(ctx, b, ad)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return c, nil
}
func (s BrowserSessions) open(ctx context.Context, c, ad []byte, v any) error {
	b, e := s.Cipher.Decrypt(ctx, c, ad)
	if e != nil {
		return value.ErrUnavailable
	}
	defer clear(b)
	if len(b) > 128<<10 || json.Unmarshal(b, v) != nil {
		return value.ErrUnavailable
	}
	return nil
}
func (s BrowserSessions) Begin(ctx context.Context, returnTo string) (LoginRedirect, error) {
	var out LoginRedirect
	if !s.configured() {
		return out, value.ErrUnavailable
	}
	if !LocalReturnPath(returnTo) {
		return out, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	now := s.Now()
	out = LoginRedirect{State: randomSessionSecret(), Browser: randomSessionSecret(), ExpiresAt: now.Add(5 * time.Minute)}
	secrets := loginSecrets{randomSessionSecret(), randomSessionSecret(), returnTo}
	key, _ := sessionKey(out.State)
	browser, _ := sessionKey(out.Browser)
	c, err := s.seal(ctx, secrets, s.binding("login", key, 1))
	if err != nil {
		return LoginRedirect{}, err
	}
	out.URL, err = s.Provider.AuthorizationURL(out.State, secrets.Nonce, secrets.Verifier)
	if err != nil {
		return LoginRedirect{}, value.ErrUnavailable
	}
	if s.Now().Before(now) || !s.Now().Before(out.ExpiresAt) {
		return LoginRedirect{}, value.ErrDenied
	}
	err = s.Store.PutLogin(ctx, value.BrowserLogin{ID: key, Browser: browser, Ciphertext: c, CreatedAt: now, ExpiresAt: out.ExpiresAt})
	if err != nil {
		return LoginRedirect{}, err
	}
	return out, nil
}
func (s BrowserSessions) Complete(ctx context.Context, state, browser, code string) (LoginResult, error) {
	var out LoginResult
	if !s.configured() {
		return out, value.ErrUnavailable
	}
	key, err := sessionKey(state)
	if err != nil {
		return out, err
	}
	browserKey, err := sessionKey(browser)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l, err := s.Store.TakeLogin(ctx, key, browserKey)
	if err != nil {
		return out, err
	}
	var secrets loginSecrets
	if !l.Valid(s.Now()) || s.open(ctx, l.Ciphertext, s.binding("login", key, 1), &secrets) != nil || !LocalReturnPath(secrets.ReturnTo) {
		return out, value.ErrDenied
	}
	t, err := s.Provider.Exchange(ctx, code, secrets.Verifier, secrets.Nonce)
	if err != nil {
		return out, value.ErrDenied
	}
	i, window, err := resolveBrowserCredential(ctx, s.Identities, t.Access, s.Now)
	if err != nil {
		return out, err
	}
	now := s.Now()
	if !l.Valid(now) || !i.Valid(now) || i.Principal.Kind != value.Human || i.Principal.Issuer != s.Issuer || i.Principal.ClientID != s.ClientID || i.Principal.Subject != t.Subject {
		return out, value.ErrDenied
	}
	cookie := randomSessionSecret()
	id, _ := sessionKey(cookie)
	credentials := sessionSecrets{t.Access, t.Refresh, randomSessionSecret(), secrets.Nonce}
	sealed, err := s.seal(ctx, credentials, s.binding("session", id, 1))
	if err != nil {
		return out, err
	}
	record := value.BrowserSession{ID: id, Principal: i.Principal, ProviderSession: t.SessionID, Ciphertext: sealed, CreatedAt: now, AuthenticatedAt: t.AuthenticatedAt, ExpiresAt: now.Add(s.Lifetime), RefreshAt: credentialRefreshAt(now, t.ExpiresAt, now.Add(s.Lifetime), window), Version: 1}
	if !l.Valid(s.Now()) || !i.Valid(s.Now()) || !record.Valid(s.Now()) {
		return out, value.ErrDenied
	}
	discard := func() {
		// A known failed callback should not occupy a user's session quota.
		// The exact locally generated ID is safe to revoke even after an
		// unknown COMMIT. Bound this attempt independently of client cancel;
		// a storage outage leaves only the original finite session deadline.
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = s.Store.RevokeSession(cleanup, id)
	}
	if record, err = s.Store.CreateSession(ctx, record); err != nil {
		if errors.Is(err, value.ErrUnavailable) {
			discard()
		}
		return out, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			discard()
		}
	}()
	if ctx.Err() != nil || !record.Current(s.Now()) || record.ID != id || record.Principal != i.Principal {
		return out, value.ErrDenied
	}
	i.ValidUntil = value.Earlier(i.ValidUntil, record.Observation.FreshUntil)
	if !i.Valid(s.Now()) {
		return out, value.ErrDenied
	}
	handedOff = true
	return LoginResult{Cookie: cookie, ReturnTo: secrets.ReturnTo, Session: SessionView{i, credentials.CSRF, record.ExpiresAt}}, nil
}
func refreshTime(now, expiry, end time.Time) time.Time {
	return value.Earlier(end, value.Earlier(now.Add(time.Minute), expiry.Add(-15*time.Second)))
}

func (s BrowserSessions) Resolve(ctx context.Context, cookie string, allowRefresh bool) (SessionView, error) {
	var out SessionView
	if !s.configured() {
		return out, value.ErrUnavailable
	}
	key, err := sessionKey(cookie)
	if err != nil {
		return out, err
	}
	return s.resolveKey(ctx, key, allowRefresh, nil)
}

// resolveKey is private to C02. An explicit POST-admitted refresh owner keeps
// only the original hashed session locator; it does not fabricate a cookie.
func (s BrowserSessions) resolveKey(ctx context.Context, key [32]byte, allowRefresh bool, schedule *refreshSessionSchedule) (SessionView, error) {
	var out SessionView
	if !s.configured() || ctx == nil || ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r, err := s.Store.ReadSession(ctx, key)
	if err != nil {
		return out, err
	}
	if !r.Current(s.Now()) || r.ID != key || r.Principal.Issuer != s.Issuer || r.Principal.ClientID != s.ClientID {
		return out, value.ErrDenied
	}
	var secrets sessionSecrets
	if err = s.open(ctx, r.Ciphertext, s.binding("session", key, r.Version), &secrets); err != nil {
		return out, err
	}
	i, window, resolveErr := resolveBrowserCredential(ctx, s.Identities, secrets.Access, s.Now)
	if resolveErr != nil && !errors.Is(resolveErr, value.ErrDenied) {
		return out, resolveErr
	}
	// GET session never rotates credentials. Explicit POST refresh and command
	// middleware may refresh; policy/key-service outages never trigger rotation.
	due := r.RefreshAt
	if window.Valid(s.Now()) {
		due = value.Earlier(due, window.RefreshAt(r.ExpiresAt))
	}
	refresh := !s.Now().Before(due) || errors.Is(resolveErr, value.ErrDenied)
	if refresh && allowRefresh {
		claimSecret := randomSessionSecret()
		claim, _ := sessionKey(claimSecret)
		if owned, ok := s.Store.(currentRefreshClaimStore); ok {
			err = owned.ClaimCurrentRefresh(ctx, key, r.Version, claim, i)
		} else {
			err = s.Store.ClaimRefresh(ctx, key, r.Version, claim)
		}
		if err != nil {
			return out, err
		}
		// A failed or ambiguous provider call leaves the durable claim consumed.
		// No process may retry its old token or take over an expired claim.
		t, e := s.Provider.Refresh(ctx, secrets.Refresh, r.Principal.Subject, r.ProviderSession, secrets.Nonce)
		if e != nil {
			return out, value.ErrDenied
		}
		i, window, resolveErr = resolveBrowserCredential(ctx, s.Identities, t.Access, s.Now)
		if resolveErr != nil || i.Principal != r.Principal || !i.Valid(s.Now()) || !t.AuthenticatedAt.Equal(r.AuthenticatedAt) {
			return out, value.ErrDenied
		}
		secrets.Access, secrets.Refresh = t.Access, t.Refresh
		sealed, e := s.seal(ctx, secrets, s.binding("session", key, r.Version+1))
		if e != nil {
			return out, e
		}
		if !i.Valid(s.Now()) || !r.Valid(s.Now()) {
			return out, value.ErrDenied
		}
		if e = s.Store.FinishRefresh(ctx, key, r.Version, claim, sealed, credentialRefreshAt(s.Now(), t.ExpiresAt, r.ExpiresAt, window)); e != nil {
			return out, e
		}
		r.Version++
	}
	// Logout/revocation during crypto/provider/policy I/O must win. The final
	// SQL read proves the same current version; cached identity never revives it.
	current, e := s.Store.ReadSession(ctx, key)
	if e != nil {
		return out, e
	}
	now := s.Now()
	if ctx.Err() != nil || current.ID != key || !current.Current(now) {
		return out, value.ErrDenied
	}
	if current.Version != r.Version {
		// A separate, successful POST may have replaced the exact credentials
		// while this read-only request verified the old token. It is safe to
		// request a fresh read, never to return the old token's identity. This
		// also handles an old expired token racing that committed replacement.
		if current.Version > r.Version && r.Current(now) && current.ID == r.ID && current.Principal == r.Principal && current.ProviderSession == r.ProviderSession && current.CreatedAt.Equal(r.CreatedAt) && current.AuthenticatedAt.Equal(r.AuthenticatedAt) && !current.ExpiresAt.After(r.ExpiresAt) && current.Observation.Settings == r.Observation.Settings && (errors.Is(resolveErr, value.ErrDenied) || resolveErr == nil && i.Principal == r.Principal) {
			return out, value.ErrSessionBusy
		}
		return out, value.ErrDenied
	}
	if resolveErr != nil {
		return out, resolveErr
	}
	if i.Principal != current.Principal {
		return out, value.ErrDenied
	}
	i.ValidUntil = value.Earlier(i.ValidUntil, current.Observation.FreshUntil)
	if !i.Valid(s.Now()) {
		return out, value.ErrDenied
	}
	if schedule != nil {
		*schedule = refreshSessionSchedule{Pin: value.RefreshSessionPin{ID: current.ID, Principal: current.Principal, ProviderSession: current.ProviderSession, CreatedAt: current.CreatedAt, AuthenticatedAt: current.AuthenticatedAt, ExpiresAt: current.ExpiresAt}, Version: current.Version, RefreshAt: current.RefreshAt, Window: window}
		if window.Valid(s.Now()) {
			schedule.RefreshAt = value.Earlier(schedule.RefreshAt, window.RefreshAt(current.ExpiresAt))
		}
	}
	return SessionView{i, secrets.CSRF, current.ExpiresAt}, nil
}

// CSRF exposes no identity or evidence. It lets a returning tab refresh an
// expired access token without weakening the CSRF check or mutating a GET.
func (s BrowserSessions) CSRF(ctx context.Context, cookie string) (string, error) {
	if !s.configured() {
		return "", value.ErrUnavailable
	}
	key, err := sessionKey(cookie)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := s.Store.ReadSessionForCSRF(ctx, key)
	if err != nil {
		return "", err
	}
	var credentials sessionSecrets
	if !r.Valid(s.Now()) || r.Principal.Issuer != s.Issuer || r.Principal.ClientID != s.ClientID {
		return "", value.ErrDenied
	}
	if err = s.open(ctx, r.Ciphertext, s.binding("session", key, r.Version), &credentials); err != nil {
		return "", err
	}
	if _, err = sessionKey(credentials.CSRF); err != nil {
		return "", value.ErrDenied
	}
	current, err := s.Store.ReadSessionForCSRF(ctx, key)
	if err != nil {
		return "", err
	}
	if ctx.Err() != nil || current.ID != r.ID || current.Principal != r.Principal || current.ProviderSession != r.ProviderSession || !current.CreatedAt.Equal(r.CreatedAt) || !current.AuthenticatedAt.Equal(r.AuthenticatedAt) || current.ExpiresAt.After(r.ExpiresAt) {
		return "", value.ErrDenied
	}
	if current.Version != r.Version || !current.Valid(s.Now()) {
		now := s.Now()
		if ctx.Err() == nil && current.Version > r.Version && r.Valid(now) && current.Valid(now) && current.ID == r.ID && current.Principal == r.Principal && current.ProviderSession == r.ProviderSession && current.CreatedAt.Equal(r.CreatedAt) && current.AuthenticatedAt.Equal(r.AuthenticatedAt) && !current.ExpiresAt.After(r.ExpiresAt) {
			return "", value.ErrSessionBusy
		}
		return "", value.ErrDenied
	}
	return credentials.CSRF, nil
}
func (s BrowserSessions) CheckCSRF(ctx context.Context, cookie, token string) error {
	if _, e := sessionKey(token); e != nil {
		return value.ErrDenied
	}
	want, e := s.CSRF(ctx, cookie)
	if e != nil {
		return e
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(token)) != 1 {
		return value.ErrDenied
	}
	return nil
}
func (s BrowserSessions) End(ctx context.Context, cookie string) error {
	if !s.configured() {
		return value.ErrUnavailable
	}
	key, err := sessionKey(cookie)
	if err != nil {
		return err
	}
	return s.Store.RevokeSession(ctx, key)
}
func (s BrowserSessions) BackchannelLogout(ctx context.Context, token string) error {
	if !s.configured() || s.Logout == nil {
		return value.ErrUnavailable
	}
	e, err := s.Logout.VerifyLogout(ctx, token)
	if err != nil {
		return value.ErrDenied
	}
	if e.Issuer != s.Issuer || e.ClientID != s.ClientID {
		return value.ErrDenied
	}
	return s.Store.LogoutSessions(ctx, e)
}

// LocalReturnPath cannot become a scheme-relative or backslash redirect after
// URL decoding. Callback destinations carry no tokens or external URLs.
func LocalReturnPath(s string) bool {
	if !value.Text(s, 2048) || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\#") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" {
		return false
	}
	decoded, err := url.PathUnescape(s)
	return err == nil && value.Text(decoded, 2048) && !strings.HasPrefix(decoded, "//") && !strings.ContainsAny(decoded, "\\%")
}
