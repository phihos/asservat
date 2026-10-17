package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

func TestWorkTrustProtectedConfig(t *testing.T) {
	for _, mode := range []string{"valid", "cluster", "epoch", "duplicate-key", "unknown", "case-alias", "padded-key", "offset", "expiry", "replaced", "extra-data", "expired-read", "stale-receiver"} {
		t.Run(mode, func(t *testing.T) {
			b, err := os.ReadFile("../../../examples/work-trust.json")
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if json.Unmarshal(b, &config) != nil {
				t.Fatal("fixture")
			}
			key := config["keys"].([]any)[0].(map[string]any)
			switch mode {
			case "cluster":
				config["clusterID"] = "33333333-3333-4333-8333-333333333333"
			case "epoch":
				config["issuerEpoch"] = "33333333-3333-4333-8333-333333333333"
			case "duplicate-key":
				config["keys"] = []any{key, key}
			case "unknown":
				key["jku"] = "https://attacker.invalid"
			case "case-alias":
				key["ID"] = key["id"]
				delete(key, "id")
			case "padded-key":
				key["publicKey"] = key["publicKey"].(string) + "="
			case "offset":
				key["notBefore"] = "2026-10-10T13:00:00+02:00"
			case "expiry":
				key["notAfter"] = key["notBefore"]
			}
			b, _ = json.Marshal(config)
			uid := "trust-uid"
			if mode == "replaced" {
				uid = "replaced"
			}
			data := map[string]string{"work-trust.json": string(b)}
			if mode == "extra-data" {
				data["other"] = "untrusted"
			}
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/work-trust" {
					return false
				}
				if mode == "expired-read" {
					clock.Add(int64(5 * time.Second))
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "work-trust", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "rv"}, "data": data})
				return true
			})
			clock = f.clock
			now := time.Unix(0, clock.Load()).UTC()
			r := value.Receiver{CollectorEpoch: permissionCluster, PeerID: permissionCluster, ClusterID: permissionCluster, IssuerEpoch: "22222222-2222-4222-8222-222222222222", NodeUID: permissionCluster, NodeBootID: permissionCluster, Region: "fixture", Capabilities: []string{"pod-status/v1"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
			if mode == "stale-receiver" {
				r.VerifiedAt = now.Add(-time.Minute)
				r.ValidUntil = now
			}
			reader, err := NewWorkTrustClient(f.client, "work-trust", "trust-uid")
			if err != nil {
				t.Fatal(err)
			}
			trust, err := reader.WorkTrust(context.Background(), r)
			if mode == "valid" {
				if err != nil || !trust.Valid(now) || len(trust.Keys) != 1 || trust.Revision.Generation != 1 {
					t.Fatal(trust, err)
				}
			} else if err == nil {
				t.Fatal("unsafe signing trust accepted")
			}
		})
	}
}
