package oidc

import (
	"context"
	"testing"
)

func TestKeycloakAccessTokenProfile(t *testing.T) {
	f := newFixture(t)
	f.v.trust.Profile = Keycloak
	claims := func() map[string]any {
		c := f.claims()
		delete(c, "client_id")
		c["azp"], c["typ"] = "console", "Bearer"
		c["groups"] = []string{"mutable-name-must-not-confer-access"}
		c["asservat_groups"] = []string{"stable-team-id"}
		return c
	}
	c, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "JWT", claims()))
	if err != nil || c.ClientID != "console" || len(c.Groups) != 1 || c.Groups[0] != "stable-team-id" {
		t.Fatalf("provider normalization failed: %v", err)
	}
	t.Run("absent-stable-membership-is-empty", func(t *testing.T) {
		input := claims()
		delete(input, "asservat_groups")
		out, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "JWT", input))
		if err != nil || len(out.Groups) != 0 {
			t.Fatal("mutable groups became membership")
		}
	})
	for name, change := range map[string]func(map[string]any){
		"id-token":           func(c map[string]any) { c["typ"] = "ID" },
		"refresh-token":      func(c map[string]any) { c["typ"] = "Refresh" },
		"missing-type":       func(c map[string]any) { delete(c, "typ") },
		"missing-client":     func(c map[string]any) { delete(c, "azp") },
		"conflicting-client": func(c map[string]any) { c["client_id"] = "other" },
		"empty-client-alias": func(c map[string]any) { c["client_id"] = "" },
		"group-alias":        func(c map[string]any) { c["Asservat_groups"] = []string{"admin"} },
		"type-alias":         func(c map[string]any) { c["TYP"] = "Bearer" },
		"null-groups":        func(c map[string]any) { c["asservat_groups"] = nil },
		"duplicate-groups":   func(c map[string]any) { c["asservat_groups"] = []string{"same", "same"} },
		"wrong-audience":     func(c map[string]any) { c["aud"] = "console" },
		"delegated":          func(c map[string]any) { c["act"] = map[string]any{"sub": "admin"} },
	} {
		t.Run(name, func(t *testing.T) {
			input := claims()
			change(input)
			if _, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "JWT", input)); err == nil {
				t.Fatal("invalid provider token accepted")
			}
		})
	}
	f.v.trust.Profile = RFC9068
	if _, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "JWT", claims())); err == nil {
		t.Fatal("unconfigured provider profile guessed from token")
	}
	f.v.trust.Profile = Keycloak
	if _, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", f.claims())); err == nil {
		t.Fatal("RFC profile guessed for Keycloak")
	}
}
