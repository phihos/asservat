package kms

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTransitExplicitCredentialsAndBounds(t *testing.T) {
	t.Setenv("BAO_TOKEN", "ambient-secret")
	t.Setenv("BAO_NAMESPACE", "wrong-namespace")
	t.Setenv("BAO_ADDR", "https://unused.invalid")
	t.Setenv("BAO_AGENT_ADDR", "https://unused.invalid")
	for _, mode := range []string{"ok", "oversized", "denied", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Vault-Token") != "selected-token" || r.Header.Get("X-Vault-Namespace") != "" || r.URL.Path != "/v1/transit/encrypt/evidence" {
					t.Error("ambient credentials/path used")
				}
				switch mode {
				case "ok":
					w.Write([]byte(`{"data":{"ciphertext":"synthetic-wrapped"}}`))
				case "oversized":
					w.Write([]byte(`{"data":{"ciphertext":"` + strings.Repeat("x", 40000) + `"}}`))
				case "denied":
					w.WriteHeader(403)
					w.Write([]byte(`{"errors":["MUST-NOT-LEAK"]}`))
				case "redirect":
					w.Header().Set("Location", "https://unused.invalid")
					w.WriteHeader(307)
				}
			}))
			defer s.Close()
			sealer, err := NewSealer(s.URL, "selected-token", "transit", "evidence", s.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = sealer.Seal(context.Background(), []byte("synthetic-keyset"), []byte("binding"))
			if mode == "ok" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrKeyService) || strings.Contains(err.Error(), "MUST-NOT-LEAK") {
				t.Fatalf("unsafe KMS error: %v", err)
			}
		})
	}
}
