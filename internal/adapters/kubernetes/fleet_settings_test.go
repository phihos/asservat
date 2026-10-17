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

func TestFleetAdministrationProtectedConfig(t *testing.T) {
	for _, mode := range []string{"valid", "no-operators", "suspended", "installation", "bad-epoch", "untrusted-issuer", "duplicate-subject", "unbounded", "history", "unknown", "case-alias", "replacement", "extra-data", "expired-read"} {
		t.Run(mode, func(t *testing.T) {
			b, err := os.ReadFile("../../../examples/fleet-settings.json")
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if json.Unmarshal(b, &config) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "no-operators":
				config["groups"] = []any{}
			case "suspended":
				config["suspended"] = true
			case "installation":
				config["installationID"] = "33333333-3333-4333-8333-333333333333"
			case "bad-epoch":
				config["issuerEpoch"] = "00000000-0000-0000-0000-000000000000"
			case "untrusted-issuer":
				config["issuer"] = "http://identity.example.test"
			case "duplicate-subject":
				config["subjects"] = []any{map[string]string{"id": "a", "kind": "human"}, map[string]string{"id": "a", "kind": "human"}}
			case "unbounded":
				config["maxActiveBootstraps"] = 999999
			case "history":
				config["maxBootstrapHistory"] = 1
			case "unknown":
				config["url"] = "https://untrusted.invalid"
			case "case-alias":
				config["Groups"] = config["groups"]
				delete(config, "groups")
			}
			b, _ = json.Marshal(config)
			uid := "fleet-uid"
			if mode == "replacement" {
				uid = "replacement"
			}
			data := map[string]string{"fleet.json": string(b)}
			if mode == "extra-data" {
				data["other"] = "value"
			}
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/fleet" {
					return false
				}
				if mode == "expired-read" {
					clock.Add(int64(5 * time.Second))
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "fleet", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "rv"}, "data": data})
				return true
			})
			clock = f.clock
			reader, err := NewFleetSettingsClient(f.client, "fleet", "fleet-uid", permissionCluster)
			if err != nil {
				t.Fatal(err)
			}
			a, err := reader.FleetAdministration(context.Background())
			if mode == "valid" || mode == "no-operators" || mode == "suspended" {
				if err != nil || !a.Valid(time.Unix(0, clock.Load())) || a.Revision.UID != uid || a.FreshUntil.Sub(a.ObservedAt) != 5*time.Second {
					t.Fatal(a, err)
				}
			} else if err == nil {
				t.Fatal("unsafe fleet administration", mode)
			}
		})
	}
}
