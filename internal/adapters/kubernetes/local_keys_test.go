package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
)

func TestLocalKeySourcePinsAndBounds(t *testing.T) {
	scope := value.KeyScope{InstallationID: "00000000-0000-4000-8000-000000000001", Purpose: "artifact", KeyID: "evidence"}
	for _, mode := range []string{"valid", "suspended", "config-replaced", "secret-replaced", "mutable-secret", "extra-secret-field", "wrong-digest", "wrong-scope", "unknown-config", "alias-config", "config-changed-during-read", "expired-read", "missing-secret", "oversize-secret", "deleting-secret", "namespace-replaced"} {
		t.Run(mode, func(t *testing.T) {
			payload := []byte("synthetic private payload parsed only by kms")
			sum := sha256.Sum256(payload)
			w := contracts.LocalKeyConfiguration{Format: "asservat-local-key-configuration/v1", InstallationID: scope.InstallationID, Purpose: scope.Purpose, KeyID: scope.KeyID, RecoveryEpoch: "00000000-0000-4000-8000-000000000002", Revision: 1, Secret: contracts.LocalKeySecretReference{Name: "root-v1", UID: "secret-uid", SHA256: hex.EncodeToString(sum[:])}}
			if mode == "suspended" {
				w.Suspended = true
			}
			if mode == "wrong-scope" {
				w.Purpose = "audit"
			}
			if mode == "wrong-digest" {
				w.Secret.SHA256 = hex.EncodeToString(make([]byte, 32))
			}
			var clock *atomic.Int64
			reads := 0
			f := newPermissionFixture(t, func(out http.ResponseWriter, r *http.Request) bool {
				if mode == "namespace-replaced" && r.URL.Path == "/api/v1/namespaces/asservat-system" {
					permissionReply(out, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "asservat-system", "uid": "different", "resourceVersion": "x"}})
					return true
				}
				if r.URL.Path == "/api/v1/namespaces/asservat-system/configmaps/local-keys" {
					reads++
					uid := "configuration-uid"
					if mode == "config-replaced" {
						uid = "different"
					}
					if mode == "config-changed-during-read" && reads > 1 {
						w.Revision++
					}
					raw, _ := json.Marshal(w)
					var fields map[string]any
					_ = json.Unmarshal(raw, &fields)
					if mode == "unknown-config" {
						fields["other"] = true
					}
					if mode == "alias-config" {
						fields["Revision"] = fields["revision"]
						delete(fields, "revision")
					}
					raw, _ = json.Marshal(fields)
					permissionReply(out, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "local-keys", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "rv"}, "data": map[string]string{"keys.json": string(raw)}})
					return true
				}
				if r.URL.Path != "/api/v1/namespaces/asservat-system/secrets/root-v1" {
					return false
				}
				if mode == "missing-secret" {
					out.WriteHeader(404)
					return true
				}
				if mode == "expired-read" {
					clock.Add(int64(5 * time.Second))
				}
				uid := "secret-uid"
				if mode == "secret-replaced" {
					uid = "different"
				}
				data := map[string][]byte{"keys.json": payload}
				if mode == "extra-secret-field" {
					data["other"] = payload
				}
				if mode == "oversize-secret" {
					data["keys.json"] = make([]byte, 16385)
				}
				metadata := map[string]any{"name": "root-v1", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "rv"}
				if mode == "deleting-secret" {
					metadata["deletionTimestamp"] = "2026-10-10T00:00:00Z"
				}
				permissionReply(out, map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "immutable": mode != "mutable-secret", "metadata": metadata, "data": data})
				return true
			})
			clock = f.clock
			source, err := NewLocalKeySource(f.client, "local-keys", "configuration-uid", scope)
			if err != nil {
				t.Fatal(err)
			}
			m, err := source.ReadKeyMaterial(context.Background())
			defer clear(m.Payload)
			if mode == "valid" || mode == "suspended" {
				if err != nil || string(m.Payload) != string(payload) || m.Configuration.Revision.Generation != 1 || m.Configuration.FreshUntil.Sub(m.Configuration.ObservedAt) != 5*time.Second {
					t.Fatal("source rejected", err)
				}
			} else if err == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
}
