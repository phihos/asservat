package identity

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// These purpose-specific doubles exercise lifetime propagation only. They are
// not encryption adapters, persisted sessions or production identity sources.
type handoffStore struct {
	BrowserSessionStore
	record           value.BrowserSession
	login            value.BrowserLogin
	onCreate         func()
	onRead           func(int)
	reads            int
	createErr        error
	readErr          error
	created, revoked [32]byte
	revocations      int
	cleanupValid     bool
}

func (s *handoffStore) ReadSession(context.Context, [32]byte) (value.BrowserSession, error) {
	s.reads++
	if s.onRead != nil {
		s.onRead(s.reads)
	}
	if s.readErr != nil {
		return value.BrowserSession{}, s.readErr
	}
	return s.record, nil
}
func (s *handoffStore) TakeLogin(context.Context, [32]byte, [32]byte) (value.BrowserLogin, error) {
	return s.login, nil
}
func (s *handoffStore) CreateSession(_ context.Context, r value.BrowserSession) (value.BrowserSession, error) {
	s.created = r.ID
	if s.onCreate != nil {
		s.onCreate()
	}
	return r, s.createErr
}
func (s *handoffStore) RevokeSession(ctx context.Context, key [32]byte) error {
	s.revocations++
	s.revoked = key
	d, ok := ctx.Deadline()
	s.cleanupValid = ctx.Err() == nil && ok && time.Now().Before(d) && !d.After(time.Now().Add(time.Second))
	return nil
}

type handoffCipher struct{ CredentialCipher }

func (handoffCipher) Decrypt(context.Context, []byte, []byte) ([]byte, error) {
	return json.Marshal(map[string]string{"Access": "synthetic-access", "Refresh": "synthetic-refresh", "CSRF": "synthetic-csrf", "Nonce": "synthetic-nonce", "Verifier": "synthetic-verifier", "ReturnTo": "/"})
}
func (handoffCipher) Encrypt(context.Context, []byte, []byte) ([]byte, error) {
	return []byte("synthetic-credential-placeholder"), nil
}

type handoffIdentity struct{ identity value.Identity }

func (i handoffIdentity) Resolve(context.Context, string) (value.Identity, error) {
	return i.identity, nil
}

type handoffProvider struct {
	BrowserProvider
	tokens BrowserTokens
}

func (p handoffProvider) Exchange(context.Context, string, string, string) (BrowserTokens, error) {
	return p.tokens, nil
}

func handoffFixture(t *testing.T) (*time.Time, *handoffStore, BrowserSessions, string) {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cookie := randomSessionSecret()
	key, _ := sessionKey(cookie)
	p := value.Principal{Issuer: "https://id.invalid", ClientID: "console", Subject: "synthetic-developer", Kind: value.Human}
	i := value.Identity{Principal: p, Scopes: []string{"asservat:capture"}, Policy: value.Revision{UID: "identity-policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}
	store := &handoffStore{record: value.BrowserSession{ID: key, Principal: p, ProviderSession: "provider-session", Ciphertext: []byte("placeholder"), CreatedAt: now.Add(-time.Minute), AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Second), RefreshAt: now.Add(time.Second), Version: 1}, login: value.BrowserLogin{ID: key, Browser: key, Ciphertext: []byte("placeholder"), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}}
	provider := handoffProvider{tokens: BrowserTokens{Access: "synthetic-access", Refresh: "synthetic-refresh", Subject: p.Subject, SessionID: "provider-session", IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthenticatedAt: now}}
	s := BrowserSessions{Store: store, Cipher: handoffCipher{}, Provider: provider, Identities: handoffIdentity{i}, Issuer: p.Issuer, ClientID: p.ClientID, Lifetime: time.Hour, Now: func() time.Time { return now }}
	return &now, store, s, cookie
}

func TestBrowserIdentityCannotOutliveSession(t *testing.T) {
	now, store, service, cookie := handoffFixture(t)
	view, e := service.Resolve(context.Background(), cookie, false)
	if e != nil {
		t.Fatal(e)
	}
	if view.Identity.ValidUntil.After(store.record.ExpiresAt) || view.Identity.Valid(store.record.ExpiresAt) || !view.Identity.Valid(*now) {
		t.Fatal("returned identity outlives its browser session")
	}
}

func TestBrowserCallbackRechecksIdentityAfterSessionCreation(t *testing.T) {
	now, store, service, cookie := handoffFixture(t)
	store.onCreate = func() {
		*now = now.Add(61 * time.Second)
	}
	if _, e := service.Complete(context.Background(), cookie, cookie, "synthetic-code"); e == nil {
		t.Fatal("callback returned identity that expired during session creation")
	}
}

func TestFailedBrowserCallbackDiscardsOnlyItsNewSession(t *testing.T) {
	for _, kind := range []string{"expired", "cancelled", "unknown-commit"} {
		t.Run(kind, func(t *testing.T) {
			now, store, service, cookie := handoffFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "expired":
				store.onCreate = func() { *now = now.Add(61 * time.Second) }
			case "cancelled":
				store.onCreate = cancel
			case "unknown-commit":
				store.createErr = value.ErrUnavailable
			}
			if _, e := service.Complete(ctx, cookie, cookie, "synthetic-code"); e == nil {
				t.Fatal("failed callback accepted")
			}
			if store.revocations != 1 || store.revoked != store.created || store.revoked == store.record.ID || !store.cleanupValid {
				t.Fatal("failed callback kept its unreachable session or revoked another session")
			}
		})
	}
}
