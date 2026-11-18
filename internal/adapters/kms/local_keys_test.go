package kms

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

var localScope = LocalKeyScope{"00000000-0000-4000-8000-000000000001", "artifact", "evidence"}

func localSecret(t testing.TB, scope LocalKeyScope, active int, versions ...int) []byte {
	t.Helper()
	s := localKeySecret{Format: localSecretFormat, InstallationID: scope.InstallationID, Purpose: scope.Purpose, KeyID: scope.KeyID, ActiveVersion: active}
	for _, version := range versions {
		material := make([]byte, 32)
		if _, err := rand.Read(material); err != nil {
			t.Fatal(err)
		}
		s.Keys = append(s.Keys, localKeyVersion{version, material})
	}
	defer s.clear()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(b) })
	return b
}

func backend(t testing.TB, scope LocalKeyScope, raw []byte) *LocalKeyBackend {
	t.Helper()
	b, err := NewLocalKeyBackend(scope, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLocalKeyRestartRotationAndBinding(t *testing.T) {
	ctx := context.Background()
	raw := localSecret(t, localScope, 1, 1, math.MaxInt32)
	first := backend(t, localScope, raw)
	plain, ad := []byte("synthetic keyset"), []byte("exact artifact binding")
	sealed, err := first.Seal(ctx, plain, ad)
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.Seal(ctx, plain, ad)
	if err != nil || sealed.Ciphertext == second.Ciphertext {
		t.Fatal("wrapping did not use fresh library nonces")
	}
	// Construct a fresh backend from the original persisted Secret. No in-memory
	// generated replacement key or original backend is used for readback.
	restored := backend(t, localScope, bytes.Clone(raw))
	got, err := restored.Open(ctx, sealed, ad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("persisted key did not recover ciphertext", err)
	}
	clear(got)
	var doc localKeySecret
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	defer doc.clear()
	doc.ActiveVersion = math.MaxInt32
	rotatedSecret, _ := json.Marshal(doc)
	defer clear(rotatedSecret)
	rotated := backend(t, localScope, rotatedSecret)
	newKey, err := rotated.Seal(ctx, plain, ad)
	if err != nil || !strings.HasSuffix(newKey.Reference, "/2147483647") {
		t.Fatal("new wrapping ignored active version", err)
	}
	got, err = rotated.Open(ctx, sealed, ad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("rotation lost retained key", err)
	}
	clear(got)
	doc.Keys = doc.Keys[1:]
	retiredSecret, _ := json.Marshal(doc)
	defer clear(retiredSecret)
	retired := backend(t, localScope, retiredSecret)
	if b, err := retired.Open(ctx, sealed, ad); err == nil || b != nil {
		t.Fatal("missing old key was silently regenerated")
	}
	for _, change := range []func(*artifact.SealedKey){
		func(k *artifact.SealedKey) { k.Reference = strings.Replace(k.Reference, "/artifact/", "/audit/", 1) },
		func(k *artifact.SealedKey) {
			k.Reference = strings.Replace(k.Reference, localScope.InstallationID, "00000000-0000-4000-8000-000000000002", 1)
		},
		func(k *artifact.SealedKey) { k.Reference = newKey.Reference },
		func(k *artifact.SealedKey) { k.Reference = strings.TrimSuffix(k.Reference, "/1") + "/01" },
		func(k *artifact.SealedKey) { k.Ciphertext += "\n" },
		func(k *artifact.SealedKey) {
			b, _ := base64.StdEncoding.DecodeString(k.Ciphertext)
			b[len(b)-1] ^= 1
			k.Ciphertext = base64.StdEncoding.EncodeToString(b)
		},
	} {
		changed := sealed
		change(&changed)
		if b, err := rotated.Open(ctx, changed, ad); err == nil || b != nil {
			t.Fatal("tampered key returned plaintext")
		}
	}
	if b, err := rotated.Open(ctx, sealed, []byte("different artifact")); err == nil || b != nil {
		t.Fatal("foreign binding returned plaintext")
	}
	// Even accidental reuse of identical root material across named scopes does
	// not let an attacker relabel a ciphertext into another purpose/installation.
	for _, purpose := range []string{"audit", "browser-credentials"} {
		var other localKeySecret
		json.Unmarshal(raw, &other)
		other.Purpose = purpose
		b, _ := json.Marshal(other)
		other.clear()
		scope := localScope
		scope.Purpose = purpose
		reader := backend(t, scope, b)
		clear(b)
		changed := sealed
		changed.Reference = reader.active
		if b, err := reader.Open(ctx, changed, ad); err == nil || b != nil {
			t.Fatal("ciphertext accepted under substituted key scope")
		}
	}
}

func TestLocalKeySecretRejectsAmbiguousOrInvalidConfiguration(t *testing.T) {
	raw := localSecret(t, localScope, 1, 1, 2)
	// A valid projected file at the Kubernetes Secret size boundary parses.
	padded := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), maxLocalSecret-len(raw))...)
	defer clear(padded)
	if _, err := NewLocalKeyBackend(localScope, bytes.NewReader(padded)); err != nil {
		t.Fatal("valid Secret at upstream size boundary", err)
	}
	changes := map[string]func(*localKeySecret){
		"format":             func(s *localKeySecret) { s.Format = "unknown" },
		"installation":       func(s *localKeySecret) { s.InstallationID = "00000000-0000-4000-8000-000000000002" },
		"purpose":            func(s *localKeySecret) { s.Purpose = "browser-credentials" },
		"key":                func(s *localKeySecret) { s.KeyID = "another" },
		"missing-primary":    func(s *localKeySecret) { s.ActiveVersion = 3 },
		"no-keys":            func(s *localKeySecret) { s.Keys = nil },
		"zero-version":       func(s *localKeySecret) { s.Keys[0].Version = 0 },
		"large-version":      func(s *localKeySecret) { s.Keys[0].Version = 2147483648 },
		"duplicate-version":  func(s *localKeySecret) { s.Keys[1].Version = 1 },
		"duplicate-material": func(s *localKeySecret) { copy(s.Keys[1].Material, s.Keys[0].Material) },
		"short-key":          func(s *localKeySecret) { s.Keys[0].Material = s.Keys[0].Material[:31] },
		"zero-key":           func(s *localKeySecret) { clear(s.Keys[0].Material) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			var s localKeySecret
			json.Unmarshal(raw, &s)
			defer s.clear()
			change(&s)
			b, _ := json.Marshal(s)
			defer clear(b)
			if k, err := NewLocalKeyBackend(localScope, bytes.NewReader(b)); err == nil || k != nil {
				t.Fatal("invalid secret accepted")
			}
		})
	}
	for _, b := range [][]byte{
		nil, []byte("null"), append(bytes.Clone(raw), []byte("{}")...), bytes.Repeat([]byte("x"), maxLocalSecret+1),
		bytes.Replace(raw, []byte(`"purpose":`), []byte(`"purpose":"audit","purpose":`), 1),
		bytes.Replace(raw, []byte(`"purpose":`), []byte(`"Purpose":`), 1),
		bytes.Replace(raw, []byte(`"format":`), []byte(`"unexpected":true,"format":`), 1),
	} {
		if k, err := NewLocalKeyBackend(localScope, bytes.NewReader(b)); err == nil || k != nil {
			t.Fatal("ambiguous secret accepted")
		}
	}
	if _, err := NewLocalKeyBackend(localScope, failureReader{}); !errors.Is(err, ErrKeyService) || strings.Contains(err.Error(), "secret material") {
		t.Fatal("unsafe loader error", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	backend(t, localScope, pretty.Bytes())
	clear(pretty.Bytes())
}

type failureReader struct{}

func (failureReader) Read([]byte) (int, error) {
	return 0, errors.New("secret material in upstream failure")
}

func TestLocalKeyBoundsCancellationAndConcurrency(t *testing.T) {
	k := backend(t, localScope, localSecret(t, localScope, 1, 1))
	ctx := context.Background()
	ad, plain := bytes.Repeat([]byte("b"), 2048), bytes.Repeat([]byte("k"), 4096)
	sealed, err := k.Seal(ctx, plain, ad)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, make([]byte, 4097)} {
		if _, err := k.Seal(ctx, bad, ad); err == nil {
			t.Fatal("invalid keyset length accepted")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 2049)} {
		if _, err := k.Seal(ctx, plain, bad); err == nil {
			t.Fatal("invalid binding length accepted")
		}
		if b, err := k.Open(ctx, sealed, bad); err == nil || b != nil {
			t.Fatal("invalid binding returned plaintext")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, c := range []context.Context{nil, canceled} {
		if _, err := k.Seal(c, plain, ad); err == nil {
			t.Fatal("invalid context accepted")
		}
		if b, err := k.Open(c, sealed, ad); err == nil || b != nil {
			t.Fatal("canceled context returned plaintext")
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 25 {
				v, err := k.Seal(ctx, plain, ad)
				if err != nil {
					t.Error(err)
					return
				}
				b, err := k.Open(ctx, v, ad)
				if err != nil || !bytes.Equal(b, plain) {
					t.Error("concurrent readback failed", err)
				}
				clear(b)
			}
		})
	}
	wg.Wait()
}
