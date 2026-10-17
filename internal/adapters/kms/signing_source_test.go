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
	"sync/atomic"
	"testing"
)

func TestSigningTokenSourceReadsEveryOriginalRequest(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	var token atomic.Value
	token.Store("first-synthetic-token")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1/retirement/sign/certificate" || r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != token.Load().(string) {
			t.Error("wrong provider path or retained credential")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var input struct {
			Input     string `json:"input"`
			Version   int    `json:"key_version"`
			Prehashed bool   `json:"prehashed"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&input) != nil || input.Version != 2 || input.Prehashed {
			t.Error("provider signing scope changed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plain, e := base64.StdEncoding.Strict().DecodeString(input.Input)
		if e != nil {
			t.Error(e)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "vault:v2:" + base64.StdEncoding.EncodeToString(ed25519.Sign(private, plain))}})
	}))
	defer server.Close()
	signer, err := NewSigningKeyWithTokenSource(server.URL, "retirement", "certificate", 2, pub, func(ctx context.Context) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s := token.Load().(string)
		if s == "" {
			return nil, errors.New("projection unavailable")
		}
		return []byte(s), nil
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	for _, next := range []string{"first-synthetic-token", "rotated-synthetic-token"} {
		token.Store(next)
		got, e := signer.ForContext(context.Background()).Sign(rand.Reader, []byte("bounded-retirement-record"), crypto.Hash(0))
		if e != nil || !ed25519.Verify(pub, []byte("bounded-retirement-record"), got) {
			t.Fatal("current exact provider request failed", e)
		}
	}
	token.Store("")
	if out, e := signer.ForContext(context.Background()).Sign(rand.Reader, []byte("bounded-retirement-record"), crypto.Hash(0)); e == nil || out != nil {
		t.Fatal("missing projection reused old token")
	}
	if requests.Load() != 2 {
		t.Fatal("missing projection made a request or a provider call retried", requests.Load())
	}
}
