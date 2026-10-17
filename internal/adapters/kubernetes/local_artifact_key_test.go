package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// ADR-198 decision 2: the root key is generated once as an immutable Secret,
// the guarded configuration names it by UID and digest, and a rerun reopens
// both without generating again; a changed configuration is refused.
func TestLocalArtifactKeyGeneratedOnceAndReopened(t *testing.T) {
	objects := map[string]json.RawMessage{}
	secretPosts := 0
	conflict := func(w http.ResponseWriter) {
		w.WriteHeader(409)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&body)
			name := body["metadata"].(map[string]any)["name"].(string)
			key := r.URL.Path + "/" + name
			if _, ok := objects[key]; ok {
				conflict(w)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/secrets") {
				secretPosts++
			}
			body["metadata"].(map[string]any)["uid"] = ownerID(len(objects) + 10)
			body["metadata"].(map[string]any)["generation"] = 1
			body["metadata"].(map[string]any)["resourceVersion"] = "1"
			objects[key], _ = json.Marshal(body)
			_, _ = w.Write(objects[key])
			return
		}
		if raw, ok := objects[r.URL.Path]; ok {
			_, _ = w.Write(raw)
			return
		}
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: 404})
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	control := cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}
	admins := []cfg.KubernetesActor{{Kind: "Group", Name: "synthetic-admins"}}
	installation := ownerID(1)
	ensure := func() (LocalArtifactKey, error) {
		return EnsureLocalArtifactKey(context.Background(), config, control, installation, "artifact", ownerID(3), admins)
	}
	first, err := ensure()
	if err != nil {
		t.Fatal(err)
	}
	var secret core.Secret
	if json.Unmarshal(objects["/api/v1/namespaces/hub/secrets/"+contracts.LocalArtifactKeySecretName(installation)], &secret) != nil || secret.Immutable == nil || !*secret.Immutable || secret.Type != core.SecretTypeOpaque || len(secret.Data) != 1 {
		t.Fatal("root key Secret", secret)
	}
	var keys struct {
		Format, InstallationID, Purpose, KeyID string
		ActiveVersion                          int
		Keys                                   []struct {
			Version  int
			Material []byte
		}
	}
	if json.Unmarshal(secret.Data["keys.json"], &keys) != nil || keys.Format != "asservat-local-keys/v1" || keys.InstallationID != installation || keys.Purpose != "artifact" || keys.KeyID != "artifact" || keys.ActiveVersion != 1 || len(keys.Keys) != 1 || keys.Keys[0].Version != 1 || len(keys.Keys[0].Material) != 32 {
		t.Fatal("root key payload", keys.Format, len(keys.Keys))
	}
	var c contracts.LocalKeyConfiguration
	sum := sha256.Sum256(secret.Data["keys.json"])
	var configMap core.ConfigMap
	if json.Unmarshal(objects["/api/v1/namespaces/hub/configmaps/"+contracts.LocalArtifactKeyConfigurationName(installation)], &configMap) != nil || json.Unmarshal([]byte(configMap.Data["keys.json"]), &c) != nil ||
		c.Secret.UID != string(secret.UID) || c.Secret.SHA256 != hex.EncodeToString(sum[:]) || c.Revision != 1 || c.RecoveryEpoch != ownerID(3) || c.Suspended || first.Configuration.UID != string(configMap.UID) || first.Guard.PolicyUID == "" {
		t.Fatal("configuration does not pin the generated Secret", c)
	}
	again, err := ensure()
	if err != nil || again.Configuration != first.Configuration || again.Guard.PolicyUID != first.Guard.PolicyUID || secretPosts != 1 {
		t.Fatal("rerun generated again or changed", err, secretPosts)
	}
	configMap.Data["keys.json"] = strings.Replace(configMap.Data["keys.json"], `"revision":1`, `"revision":2`, 1)
	configMap.UID = types.UID(ownerID(9))
	objects["/api/v1/namespaces/hub/configmaps/"+contracts.LocalArtifactKeyConfigurationName(installation)], _ = json.Marshal(configMap)
	if _, err = ensure(); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed configuration accepted", err)
	}
}
