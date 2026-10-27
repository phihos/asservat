package oidc

import (
	"context"
	"testing"
	"time"
)

// ADR-249: the signed acr/auth_time pass through as assurance facts; a
// malformed value means no assurance, never a rejected token.
func TestAccessTokenAssuranceClaims(t *testing.T) {
	f := newFixture(t)
	claims := f.claims()
	authTime := f.now().Add(-2 * time.Minute).Unix()
	claims["acr"], claims["auth_time"] = "gold", authTime
	c, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", claims))
	if err != nil || c.ACR != "gold" || c.AuthTime.Unix() != authTime {
		t.Fatalf("assurance: %+v %v", c, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"numeric acr":           func(m map[string]any) { m["acr"] = 2 },
		"string auth_time":      func(m map[string]any) { m["auth_time"] = "now" },
		"auth_time after iat":   func(m map[string]any) { m["auth_time"] = f.now().Unix() },
		"absent":                func(m map[string]any) { delete(m, "acr"); delete(m, "auth_time") },
		"acr without auth_time": func(m map[string]any) { delete(m, "auth_time") },
	} {
		t.Run(name, func(t *testing.T) {
			m := f.claims()
			m["acr"], m["auth_time"] = "gold", authTime
			mutate(m)
			c, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", m))
			if err != nil {
				t.Fatal("assurance shape rejected an otherwise valid token", err)
			}
			if !c.AuthTime.IsZero() && name != "numeric acr" {
				t.Fatal("malformed assurance accepted", c.AuthTime)
			}
			if name == "numeric acr" && (c.ACR != "" || !c.AuthTime.IsZero()) {
				t.Fatal("numeric acr accepted")
			}
		})
	}
	m := f.claims()
	m["ACR"] = "gold"
	if _, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", m)); err == nil {
		t.Fatal("case alias of acr accepted")
	}
}
