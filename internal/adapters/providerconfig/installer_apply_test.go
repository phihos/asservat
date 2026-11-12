package providerconfig

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bao "github.com/openbao/openbao/api/v2"
)

// ADR-183 applier: only policy/auth-role/PKI-role creates, never an overwrite.
func TestApplySetupArtifactIsCreateOnlyAndConfined(t *testing.T) {
	writes := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && path == "sys/policies/acl/existing":
			_, _ = io.WriteString(w, `{"data":{"name":"existing","policy":"foreign"}}`)
		case r.Method == http.MethodGet:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"errors":[]}`)
		case path == "auth/token/create":
			_, _ = io.WriteString(w, `{"auth":{"client_token":"s.synthetic"}}`)
		default:
			writes[path] = true
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	config := bao.DefaultConfig()
	config.Address = server.URL
	client, err := bao.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("synthetic-admin")
	if _, err = ApplySetupArtifact(context.Background(), client, "inspect", []byte(`{"apply":[{"method":"POST","path":"sys/mounts/evil","body":{}}],"inspect":["a/b"]}`), io.Discard); err == nil || len(writes) != 0 {
		t.Fatal("applied a mount", writes)
	}
	token, err := ApplySetupArtifact(context.Background(), client, "inspect", []byte(`{"apply":[{"method":"POST","path":"sys/policies/acl/existing","body":{"policy":"x"}},{"method":"POST","path":"auth/k8s/role/r","body":{}},{"method":"POST","path":"owner-pki/roles/s","body":{}}],"inspect":["auth/k8s/role/r"]}`), io.Discard)
	if err != nil || string(token) != "s.synthetic" || writes["sys/policies/acl/existing"] || !writes["auth/k8s/role/r"] || !writes["owner-pki/roles/s"] || !writes["sys/policies/acl/inspect"] {
		t.Fatal("create-only apply", err, writes)
	}
}

func TestApplyBundledSetupArtifactUsesFixedInspectionRole(t *testing.T) {
	writes := map[string]int{}
	tokenCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Vault-Token") != "synthetic-installer" || r.Header.Get("X-Vault-Namespace") != "protected" {
			t.Error("lost explicit installer credential or namespace")
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		if r.Method == http.MethodGet {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"errors":[]}`)
			return
		}
		if path == "auth/token/create/"+BundledSetupInspectionRole {
			tokenCalls++
			var request bao.TokenCreateRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil {
				t.Error("invalid inspection request")
			}
			ttl, ttlErr := time.ParseDuration(request.TTL)
			max, maxErr := time.ParseDuration(request.ExplicitMaxTTL)
			if len(request.Policies) != 1 || request.Policies[0] != "inspect-exact" || !request.NoDefaultPolicy || request.Renewable == nil || *request.Renewable || request.Type != "service" || request.NoParent || ttlErr != nil || maxErr != nil || ttl <= 0 || ttl > 600*time.Second || max <= 0 || max > 600*time.Second || request.DisplayName != "inspect-exact" {
				t.Error("inspection role request broadened token")
			}
			_, _ = io.WriteString(w, `{"auth":{"client_token":"s.synthetic-inspection"}}`)
			return
		}
		if path == "auth/token/create" {
			t.Error("bundled path bypassed protected role")
		}
		writes[path]++
		w.WriteHeader(204)
	}))
	defer server.Close()
	config := bao.DefaultConfig()
	config.Address = server.URL
	config.DisableEnvironment = true
	config.MaxRetries = 3
	client, err := bao.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("synthetic-installer")
	client.SetNamespace("protected")
	artifact := []byte(`{"apply":[{"method":"POST","path":"sys/policies/acl/setup-exact","body":{"policy":"path \"exact\" { capabilities = [\"read\"] }"}}],"inspect":["auth/k8s/role/exact"]}`)
	token, err := ApplyBundledSetupArtifact(context.Background(), client, "inspect-exact", artifact, io.Discard)
	if err != nil || string(token) != "s.synthetic-inspection" || tokenCalls != 1 || writes["sys/policies/acl/setup-exact"] != 1 || writes["sys/policies/acl/inspect-exact"] != 1 || len(writes) != 2 {
		t.Fatal("fixed role application failed", err)
	}
	if client.CloneConfig().MaxRetries != 3 || client.CloneConfig().DisableRedirects {
		t.Fatal("bundled wrapper changed caller client")
	}
}

func TestApplyBundledSetupArtifactDeniedOrUnknownRoleNeverReplays(t *testing.T) {
	for _, mode := range []string{"denied", "unknown", "redirect", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			calls, otherTokenCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				path := strings.TrimPrefix(r.URL.Path, "/v1/")
				if r.Method == http.MethodGet {
					w.WriteHeader(404)
					_, _ = io.WriteString(w, `{"errors":[]}`)
					return
				}
				if path == "auth/token/create/"+BundledSetupInspectionRole {
					calls++
					switch mode {
					case "denied":
						w.WriteHeader(403)
						_, _ = io.WriteString(w, `{"errors":["synthetic-secret-marker"]}`)
					case "unknown":
						w.WriteHeader(500)
						_, _ = io.WriteString(w, `{"errors":["synthetic-secret-marker"]}`)
					case "redirect":
						w.Header().Set("Location", "/v1/auth/token/create")
						w.WriteHeader(307)
					case "malformed":
						_, _ = io.WriteString(w, `{"auth":{}}`)
					}
					return
				}
				if strings.HasPrefix(path, "auth/token/") {
					otherTokenCalls++
					t.Error("role refusal fell back or followed redirect")
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			config := bao.DefaultConfig()
			config.Address = server.URL
			config.DisableEnvironment = true
			config.MaxRetries = 3
			client, err := bao.NewClient(config)
			if err != nil {
				t.Fatal(err)
			}
			token, err := ApplyBundledSetupArtifact(context.Background(), client, "inspect", []byte(`{"apply":[{"method":"POST","path":"auth/k8s/role/r","body":{}}],"inspect":["auth/k8s/role/r"]}`), io.Discard)
			if err != ErrSetupUnavailable || len(token) != 0 || calls != 1 || otherTokenCalls != 0 {
				t.Fatalf("role refusal replayed or returned token: calls=%d other=%d err=%v", calls, otherTokenCalls, err)
			}
		})
	}
}

func TestApplyBundledSetupArtifactUnknownCreateNeverReplays(t *testing.T) {
	writes, tokens := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"errors":[]}`)
			return
		}
		if strings.Contains(r.URL.Path, "auth/token/") {
			tokens++
		}
		writes++
		w.WriteHeader(500)
		_, _ = io.WriteString(w, `{"errors":["synthetic-secret-marker"]}`)
	}))
	defer server.Close()
	config := bao.DefaultConfig()
	config.Address = server.URL
	config.DisableEnvironment = true
	config.MaxRetries = 3
	client, err := bao.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ApplyBundledSetupArtifact(context.Background(), client, "inspect", []byte(`{"apply":[{"method":"POST","path":"auth/k8s/role/r","body":{}}],"inspect":["auth/k8s/role/r"]}`), io.Discard)
	if err != ErrSetupUnavailable || len(token) != 0 || writes != 1 || tokens != 0 {
		t.Fatal("unknown create replayed or reached token issuance")
	}
}
