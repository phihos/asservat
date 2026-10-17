package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	raw := localSecret(t, localScope, 1, 1, 2)
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
	doc.ActiveVersion = 2
	rotatedSecret, _ := json.Marshal(doc)
	defer clear(rotatedSecret)
	rotated := backend(t, localScope, rotatedSecret)
	newKey, err := rotated.Seal(ctx, plain, ad)
	if err != nil || !strings.HasSuffix(newKey.Reference, "/2") {
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
		func(k *artifact.SealedKey) { k.Reference = strings.TrimSuffix(k.Reference, "/1") + "/2" },
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
		"too-many": func(s *localKeySecret) {
			for len(s.Keys) <= maxLocalVersions {
				s.Keys = append(s.Keys, s.Keys[0])
			}
		},
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

func TestLocalSigningPurposeVersionAndPublicPin(t *testing.T) {
	scope := localScope
	scope.Purpose, scope.KeyID = "policy-submission", "submission"
	raw := localSecret(t, scope, 2, 1, 2)
	var doc localKeySecret
	json.Unmarshal(raw, &doc)
	defer doc.clear()
	private := ed25519.NewKeyFromSeed(doc.Keys[1].Material)
	defer clear(private)
	public := private.Public().(ed25519.PublicKey)
	k, err := NewLocalSigningKey(scope, 2, public, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("synthetic purpose-bound JWS input")
	s := k.ForContext(context.Background())
	sig, err := s.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil || !ed25519.Verify(public, message, sig) {
		t.Fatal("invalid local signature", err)
	}
	copyPublic := s.Public().(ed25519.PublicKey)
	clear(copyPublic)
	if !bytes.Equal(s.Public().(ed25519.PublicKey), public) {
		t.Fatal("caller mutated public pin")
	}
	wrong := bytes.Clone(public)
	wrong[0] ^= 1
	for _, args := range []struct {
		scope   LocalKeyScope
		version int
		public  ed25519.PublicKey
	}{
		{scope, 1, public}, {scope, 2, wrong}, {localScope, 2, public},
	} {
		if _, err := NewLocalSigningKey(args.scope, args.version, args.public, bytes.NewReader(raw)); err == nil {
			t.Fatal("untrusted signer configuration accepted")
		}
	}
	for _, option := range []crypto.SignerOpts{nil, (*ed25519.Options)(nil), crypto.SHA256, &ed25519.Options{Context: "other-purpose"}, &ed25519.Options{Hash: crypto.SHA512}} {
		if b, err := s.Sign(rand.Reader, message, option); err == nil || b != nil {
			t.Fatal("unsupported signing mode accepted")
		}
	}
	for _, message := range [][]byte{nil, make([]byte, 16385)} {
		if _, err := s.Sign(rand.Reader, message, crypto.Hash(0)); err == nil {
			t.Fatal("unbounded signing input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := k.ForContext(ctx).Sign(rand.Reader, message, crypto.Hash(0)); err == nil {
		t.Fatal("canceled signature returned")
	}
	if _, err := NewLocalKeyBackend(scope, bytes.NewReader(raw)); err == nil {
		t.Fatal("signing seed loaded as encryption key")
	}
}

func FuzzLocalKeySecret(f *testing.F) {
	f.Add(localSecret(f, localScope, 1, 1))
	f.Add([]byte(`{"keys":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := NewLocalKeyBackend(localScope, bytes.NewReader(b))
		if err != nil {
			return
		}
		ctx := context.Background()
		sealed, err := k.Seal(ctx, []byte("synthetic"), []byte("binding"))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := k.Open(ctx, sealed, []byte("binding"))
		if err != nil || string(plain) != "synthetic" {
			t.Fatal("valid loaded key failed readback")
		}
		clear(plain)
	})
}

var _ io.Reader = failureReader{}
