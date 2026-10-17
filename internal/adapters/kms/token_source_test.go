package kms

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTransitCurrentTokenSource(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "ambient-not-selected")
	var expected atomic.Value
	expected.Store("synthetic-first")
	var requests atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Vault-Token") != expected.Load().(string) {
			t.Error("provider used another token")
		}
		w.Write([]byte(`{"data":{"ciphertext":"synthetic-wrapped"}}`))
	}))
	defer s.Close()
	var unavailable atomic.Bool
	var buffer []byte
	source := func(context.Context) ([]byte, error) {
		if unavailable.Load() {
			return nil, errors.New("must-not-leak")
		}
		buffer = []byte(expected.Load().(string))
		return buffer, nil
	}
	c, err := NewSealerWithTokenSource(s.URL, "transit", "keys", source, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, token := range []string{"synthetic-first", "synthetic-second"} {
		expected.Store(token)
		if _, err = c.Seal(context.Background(), []byte("keyset"), []byte("binding")); err != nil {
			t.Fatal(err)
		}
		for _, b := range buffer {
			if b != 0 {
				t.Fatal("owned token buffer retained")
			}
		}
	}
	unavailable.Store(true)
	if _, err = c.Seal(context.Background(), []byte("keyset"), []byte("binding")); !errors.Is(err, ErrKeyService) {
		t.Fatal("missing token not sanitized", err)
	}
	if requests.Load() != 2 {
		t.Fatal("failed source reused cached/ambient token")
	}
	unavailable.Store(false)
	expected.Store("synthetic\ninvalid")
	if _, err = c.Seal(context.Background(), []byte("keyset"), []byte("binding")); !errors.Is(err, ErrKeyService) {
		t.Fatal("invalid token accepted", err)
	}
	if requests.Load() != 2 {
		t.Fatal("invalid token transmitted")
	}
}
