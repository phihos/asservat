package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type csrfRotationStore struct{ *handoffStore }

func (s csrfRotationStore) ReadSessionForCSRF(ctx context.Context, key [32]byte) (value.BrowserSession, error) {
	return s.ReadSession(ctx, key)
}

type csrfRotationCipher struct {
	CredentialCipher
	entered, release chan struct{}
	csrf             string
}

func (c csrfRotationCipher) Decrypt(context.Context, []byte, []byte) ([]byte, error) {
	close(c.entered)
	<-c.release
	return json.Marshal(sessionSecrets{CSRF: c.csrf})
}
func TestCSRFConcurrentCommittedRefreshIsBusyOnlyForSameOriginalSession(t *testing.T) {
	for _, kind := range []string{"same", "principal", "provider", "created", "authenticated", "expiry-extension", "expired", "same-version-identity-change", "decreased-version", "revoked", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			now, store, service, cookie := handoffFixture(t)
			store.record.ExpiresAt = now.Add(time.Hour)
			service.Store = csrfRotationStore{store}
			entered, release := make(chan struct{}), make(chan struct{})
			service.Cipher = csrfRotationCipher{entered: entered, release: release, csrf: randomSessionSecret()}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type response struct {
				token string
				err   error
			}
			result := make(chan response, 1)
			go func() { csrf, e := service.CSRF(ctx, cookie); result <- response{csrf, e} }()
			<-entered
			store.record.Version++
			switch kind {
			case "principal":
				store.record.Principal.Subject = "other"
			case "provider":
				store.record.ProviderSession = "other"
			case "created":
				store.record.CreatedAt = store.record.CreatedAt.Add(-time.Second)
			case "authenticated":
				store.record.AuthenticatedAt = store.record.AuthenticatedAt.Add(-time.Second)
			case "expiry-extension":
				store.record.ExpiresAt = store.record.ExpiresAt.Add(time.Second)
			case "expired":
				*now = now.Add(2 * time.Hour)
			case "same-version-identity-change":
				store.record.Version--
				store.record.Principal.Subject = "other"
			case "decreased-version":
				store.record.Version = 0
			case "revoked":
				store.readErr = value.ErrDenied
			case "cancelled":
				cancel()
			}
			close(release)
			got := <-result
			if got.token != "" {
				t.Fatal("stale CSRF escaped")
			}
			e := got.err
			if kind == "same" {
				if !errors.Is(e, value.ErrSessionBusy) {
					t.Fatal("committed rotation forced sign-in", e)
				}
			} else if e == nil || errors.Is(e, value.ErrSessionBusy) {
				t.Fatal("contradictory session treated as busy or disclosed CSRF", kind, e)
			}
		})
	}
}
