package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubmissionTrustProtectedConfig(t *testing.T) {
	for _, mode := range []string{"valid", "root", "installation", "epoch", "replacement", "duplicate-key", "unknown", "alias", "key-encoding", "empty", "expired-read"} {
		t.Run(mode, func(t *testing.T) {
			b, e := os.ReadFile("../../../examples/submission-trust.json")
			if e != nil {
				t.Fatal(e)
			}
			var settings map[string]any
			if json.Unmarshal(b, &settings) != nil {
				t.Fatal("fixture")
			}
			root, installation, epoch := settings["rootID"].(string), settings["installationID"].(string), settings["issuerEpoch"].(string)
			key := settings["keys"].([]any)[0].(map[string]any)
			switch mode {
			case "root":
				settings["rootID"] = epoch
			case "installation":
				settings["installationID"] = root
			case "epoch":
				settings["issuerEpoch"] = root
			case "duplicate-key":
				settings["keys"] = []any{key, key}
			case "unknown":
				key["jku"] = "https://untrusted.invalid"
			case "alias":
				key["ID"] = key["id"]
				delete(key, "id")
			case "key-encoding":
				key["publicKey"] = key["publicKey"].(string) + "="
			case "empty":
				settings["keys"] = []any{}
			}
			b, _ = json.Marshal(settings)
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/submission-trust" {
					return false
				}
				uid := "submission-trust-uid"
				if mode == "replacement" {
					uid = "replacement"
				}
				if mode == "expired-read" {
					clock.Add(int64(5 * time.Second))
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "submission-trust", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "opaque"}, "data": map[string]string{"submission.json": string(b)}})
				return true
			})
			clock = f.clock
			reader, e := NewSubmissionTrustClient(f.client, "submission-trust", "submission-trust-uid", root, installation, epoch)
			if e != nil {
				t.Fatal(e)
			}
			got, e := reader.SubmissionTrust(context.Background())
			if mode == "valid" {
				if e != nil || !got.Valid(time.Unix(0, clock.Load())) {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unsafe signing trust accepted")
			}
		})
	}
}
