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
func smallServicesHelmBootstrap() map[string]any {
	return map[string]any{
		"enabled": true, "name": "trial",
		"image":        "registry.example/asservat@sha256:" + strings.Repeat("a", 64),
		"secrets":      map[string]any{"producer": "provider-material", "schema": "sql-ddl", "retirement": "sql-retire"},
		"postgres":     map[string]any{"host": "external.example", "rootsPEM": "PUBLIC-CA"},
		"auditStore":   map[string]any{"endpoint": "https://s3.example", "region": "test", "bucket": "audit", "rootsPEM": "PUBLIC-CA"},
		"keyService":   map[string]any{"endpoint": "https://bao.example", "rootsPEM": "PUBLIC-CA"},
		"fleet":        map[string]any{"issuer": "https://identity.example/realms/asservat", "clients": []string{"asservat-console"}},
		"continuation": map[string]any{"public": map[string]any{"origin": "https://console.example"}},
	}
}
