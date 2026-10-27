package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"reflect"
	"testing"
	"time"
)

type stepupStore struct {
	BrowserSessionStore
	writes int
}

func (s *stepupStore) PutLogin(context.Context, value.BrowserLogin) error { s.writes++; return nil }

type stepupProvider struct {
	BrowserProvider
	acr   []string
	onURL func()
}

func (p *stepupProvider) StepUpAuthorizationURL(_, _, _ string, acr []string) (string, error) {
	p.acr = append([]string(nil), acr...)
	if p.onURL != nil {
		p.onURL()
	}
	return "https://issuer.invalid/auth", nil
}

func TestStepUpLoginUsesCurrentProtectedPolicy(t *testing.T) {
	for _, name := range []string{"configured", "missing", "stale", "wrong issuer", "removed client", "expires during work", "canceled", "unsafe return"} {
		t.Run(name, func(t *testing.T) {
			f, _ := newFixture()
			f.p.StepUp = value.StepUpPolicy{ACRValues: []string{"gold"}, MaxAge: 5 * time.Minute}
			store := &stepupStore{}
			provider := &stepupProvider{}
			service := BrowserSessions{Store: store, Cipher: handoffCipher{}, Provider: provider, Identities: handoffIdentity{}, Policies: f, Issuer: f.p.Issuer, ClientID: "console", Epoch: "epoch", Lifetime: time.Hour, Now: func() time.Time { return f.now }}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "missing":
				f.p.StepUp = value.StepUpPolicy{}
			case "stale":
				f.now = f.p.FreshUntil
			case "wrong issuer":
				f.p.Issuer = "https://another.invalid"
			case "removed client":
				f.p.Clients[0].ID = "other"
			case "expires during work":
				provider.onURL = func() { f.now = f.p.FreshUntil }
			case "canceled":
				cancel()
			}
			path := "/approvals/request"
			if name == "unsafe return" {
				path = "//outside.invalid"
			}
			out, err := service.BeginStepUp(ctx, path)
			if name == "configured" {
				if err != nil || store.writes != 1 || out.URL == "" || !reflect.DeepEqual(provider.acr, []string{"gold"}) {
					t.Fatal("configured step-up refused", err)
				}
			} else if err == nil || store.writes != 0 {
				t.Fatal("unqualified step-up persisted a login", err)
			}
		})
	}
}
