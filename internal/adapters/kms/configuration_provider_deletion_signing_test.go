package kms

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// configurationSigningFixture is the installed configuration provider with
// ADR-205's context deletion signing key selected. The fixture provider signs
// with a synthetic Ed25519 key at the deletion key's sign path, for the
// audit-wrap token only.
func configurationSigningFixture(t *testing.T, selected bool) (*InstalledConfigurationProviderEffects, contracts.OwnerPublicTransit, ed25519.PublicKey, *int) {
	t.Helper()
	var signing contracts.OwnerPublicTransit
	f, in, profile := configurationControlFixture(t, "audit-wrap", func(in contracts.HubWorkerDeployment, s *contracts.ConfigurationProviderSelection) {
		signing = contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: contracts.ContextDeletionSigningKeyName(in.InstallationID)}
		if selected {
			s.ContextDeletionSigning = signing
		}
	})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signs := new(int)
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/"+signing.Mount+"/sign/"+signing.Key {
			if !strings.HasPrefix(r.URL.Path, "/v1/auth/") {
				t.Error("provider request outside login and the sign path", r.Method, r.URL.Path)
			}
			f.serve(w, r)
			return
		}
		var body struct {
			Input      string `json:"input"`
			KeyVersion int    `json:"key_version"`
			Prehashed  bool   `json:"prehashed"`
		}
		input, err := []byte(nil), json.NewDecoder(r.Body).Decode(&body)
		if err == nil {
			input, err = base64.StdEncoding.DecodeString(body.Input)
		}
		if r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != "exact-service-token" || err != nil || body.KeyVersion != 1 || body.Prehashed {
			t.Error("deletion signing request changed", r.Method, body.KeyVersion)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		*signs++
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(private, input))}})
	})
	root, cancel := context.WithCancel(context.Background())
	effects, err := newConfigurationProviderEffects(root, in, profile,
		func(context.Context) ([]byte, error) {
			return ownerProviderTestJWT(time.Now().Add(600 * time.Second)), nil
		},
		func(context.Context) (time.Time, error) { return time.Now().Add(5 * time.Second), nil }, f.server.Client(), time.Now)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	in.ProviderAuthentication = &profile
	s := &InstalledConfigurationProviderEffects{input: in, effects: effects, root: root, cancel: cancel, closeDone: make(chan struct{})}
	t.Cleanup(func() { _ = s.CloseAndJoin(context.Background()) })
	return s, signing, public, signs
}

// ADR-205 decision 6: the deletion signer borrows audit-wrap's token for the
// selected key's sign path only and checks every signature against the pin.
func TestConfigurationProviderSignsContextDeletionThroughAuditWrap(t *testing.T) {
	s, signing, public, signs := configurationSigningFixture(t, true)
	if err := s.effects.wrap.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	key, err := s.ContextDeletionSigningKey(signing.Mount, signing.Key, 1, public)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	message := []byte(`{"Format":"asservat-context-deletion/v1"}`)
	sig, err := key.ForContext(context.Background()).Sign(nil, message, crypto.Hash(0))
	if err != nil || !ed25519.Verify(public, message, sig) || *signs != 1 {
		t.Fatal("deletion signature through audit-wrap failed", err, *signs)
	}
	// The client reaches no other path: no key read, export or creation.
	for _, path := range []string{signing.Mount + "/keys/" + signing.Key, signing.Mount + "/export/signing-key/" + signing.Key, signing.Mount + "/encrypt/" + signing.Key} {
		if _, err := key.client.Logical().Write(path, map[string]any{}); err == nil {
			t.Fatal("deletion signing client reached", path)
		}
		if _, err := key.client.Logical().Read(path); err == nil {
			t.Fatal("deletion signing client read", path)
		}
	}
	// A provider signature that does not verify under the pin is refused.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	wrong, err := s.ContextDeletionSigningKey(signing.Mount, signing.Key, 1, other)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if sig, err := wrong.ForContext(context.Background()).Sign(nil, message, crypto.Hash(0)); err == nil || sig != nil {
		t.Fatal("signature accepted under another public key")
	}
	for name, c := range map[string]struct {
		mount, key string
		version    int
		public     ed25519.PublicKey
	}{
		"configuration-audit-key": {s.input.KeyService.AuditMount, s.input.KeyService.AuditKey, 1, public},
		"unselected-key":          {signing.Mount, "other", 1, public},
		"other-mount":             {"other", signing.Key, 1, public},
		"path-mount":              {signing.Mount + "/sign", signing.Key, 1, public},
		"wildcard":                {signing.Mount, "*", 1, public},
		"empty":                   {"", "", 1, public},
		"version":                 {signing.Mount, signing.Key, 0, public},
		"public":                  {signing.Mount, signing.Key, 1, public[:16]},
	} {
		if k, err := s.ContextDeletionSigningKey(c.mount, c.key, c.version, c.public); err == nil || k != nil {
			t.Fatal("deletion signing key accepted", name)
		}
	}
	if *signs != 2 {
		t.Fatal("provider signing requests", *signs)
	}
}

// Without the selected key the profile never grants a deletion signer.
func TestConfigurationProviderWithoutDeletionSigningRefusesSigner(t *testing.T) {
	s, signing, public, _ := configurationSigningFixture(t, false)
	if k, err := s.ContextDeletionSigningKey(signing.Mount, signing.Key, 1, public); err == nil || k != nil {
		t.Fatal("deletion signer without a selected key")
	}
	var missing *InstalledConfigurationProviderEffects
	if k, err := missing.ContextDeletionSigningKey(signing.Mount, signing.Key, 1, public); err == nil || k != nil {
		t.Fatal("nil effects produced a signer")
	}
}
