package kms

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSigningKeyPinsVersionPurposeAndProviderOutput(t *testing.T) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"valid", "wrong-version", "wrong-signature", "bad-base64", "denied", "redirect", "oversized", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/v1/submission/sign/policy" || r.Method != "POST" || r.Header.Get("X-Vault-Token") != "selected-signing-token" {
					t.Error("unexpected signing authority")
				}
				var body struct {
					Input     string `json:"input"`
					Version   int    `json:"key_version"`
					Prehashed bool   `json:"prehashed"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Version != 2 || body.Prehashed {
					t.Error("signing request changed")
				}
				input, e := base64.StdEncoding.DecodeString(body.Input)
				if e != nil {
					t.Error(e)
				}
				if mode == "cancel" {
					<-r.Context().Done()
					return
				}
				if mode == "denied" {
					w.WriteHeader(403)
					w.Write([]byte("MUST-NOT-LEAK"))
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", "https://unused.invalid")
					w.WriteHeader(307)
					return
				}
				value := "vault:v2:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, input))
				switch mode {
				case "wrong-version":
					value = strings.Replace(value, "v2:", "v1:", 1)
				case "wrong-signature":
					value = "vault:v2:" + base64.StdEncoding.EncodeToString(make([]byte, 64))
				case "bad-base64":
					value += "="
				case "oversized":
					value = strings.Repeat("x", 40000)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": value}})
			}))
			defer server.Close()
			s, e := NewSigningKey(server.URL, "selected-signing-token", "submission", "policy", 2, pub, server.Client())
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if mode == "cancel" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
			}
			defer cancel()
			signer := s.ForContext(ctx)
			var nilOptions *ed25519.Options
			if _, e := signer.Sign(rand.Reader, []byte("input"), nilOptions); e == nil || calls.Load() != 0 {
				t.Fatal("nil signing options reached provider")
			}
			if _, e := signer.Sign(rand.Reader, []byte("input"), crypto.SHA256); e == nil || calls.Load() != 0 {
				t.Fatal("prehashed operation reached provider")
			}
			sig, e := signer.Sign(rand.Reader, []byte("input"), crypto.Hash(0))
			if mode == "valid" {
				if e != nil || !ed25519.Verify(pub, []byte("input"), sig) {
					t.Fatal("provider signature rejected", e)
				}
			} else if !errors.Is(e, ErrKeyService) || strings.Contains(e.Error(), "MUST-NOT-LEAK") {
				t.Fatal("unsafe provider result", e)
			}
			if calls.Load() != 1 {
				t.Fatal("signing call retried or missing")
			}
		})
	}
}
