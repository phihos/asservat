package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSmallServicesPersistIdentityBeforeDatabaseInitialization(t *testing.T) {
	var identityPersisted bool
	if err := prepareSmallServices(t.Context(), func(context.Context) error {
		identityPersisted = true
		return nil
	}, func(context.Context) error {
		if !identityPersisted {
			t.Fatal("database can initialize before original realm/client identity is persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"identity-failure", "cancellation-after-identity"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failed := errors.New("retained identity unavailable")
			var initialized bool
			err := prepareSmallServices(ctx, func(context.Context) error {
				if mode == "identity-failure" {
					return failed
				}
				cancel()
				return nil
			}, func(context.Context) error { initialized = true; return nil })
			if err == nil || initialized {
				t.Fatal("database initialized after identity failure/cancellation", err)
			}
		})
	}
}

// Values shared by actual chart regressions. Public placeholders are render
// fixtures only; they are not admitted provider roots or runtime authority.
// External provider coordinates are filled in for services left external.
func smallServicesHelmValues(services map[string]any) map[string]any {
	external := map[string]map[string]any{
		"postgres":    {"host": "external.example", "database": "asservat", "rootsPEM": "PUBLIC-CA", "adminSecret": "operator-postgres-admin"},
		"objectStore": {"endpoint": "https://s3.example", "region": "test", "bucket": "audit", "rootsPEM": "PUBLIC-CA"},
		"keyService":  {"endpoint": "https://bao.example", "rootsPEM": "PUBLIC-CA"},
	}
	for name, coordinates := range external {
		selected, _ := services[name].(map[string]any)
		if selected == nil {
			selected = map[string]any{}
			services[name] = selected
		}
		if _, ok := selected["external"]; !ok {
			selected["external"] = coordinates
		}
	}
	return map[string]any{
		"mode":         "hub",
		"installation": map[string]any{"name": "trial"},
		"image":        map[string]any{"repository": "registry.example/asservat", "digest": "sha256:" + strings.Repeat("a", 64)},
		"origin":       "https://console.example",
		"identity":     map[string]any{"issuer": "https://identity.example/realms/asservat", "clientID": "asservat-console"},
		"services":     services,
	}
}
