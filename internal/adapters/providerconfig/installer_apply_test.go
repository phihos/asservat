package providerconfig

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
