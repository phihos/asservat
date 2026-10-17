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

func TestBrowserSettingsProtectedConfig(t *testing.T) {
	for _, mode := range []string{"valid", "suspended", "replacement", "wrong-root", "zero-epoch", "insecure-issuer", "origin-path", "origin-query", "origin-user", "origin-default-port", "origin-case", "lifetime", "capacity", "unknown", "alias", "extra-data", "expired-read"} {
		t.Run(mode, func(t *testing.T) {
			b, e := os.ReadFile("../../../examples/browser-settings.json")
			if e != nil {
				t.Fatal(e)
			}
			var config map[string]any
			_ = json.Unmarshal(b, &config)
			root := config["rootID"].(string)
			switch mode {
			case "suspended":
				config["suspended"] = true
			case "wrong-root":
				config["rootID"] = "74000000-0000-4000-8000-000000000009"
			case "zero-epoch":
				config["sessionEpoch"] = "00000000-0000-0000-0000-000000000000"
			case "insecure-issuer":
				config["issuer"] = "http://id.example.invalid"
			case "origin-path":
				config["origin"] = "https://console.invalid/path"
			case "origin-query":
				config["origin"] = "https://console.invalid?x=y"
			case "origin-user":
				config["origin"] = "https://user@console.invalid"
			case "origin-default-port":
				config["origin"] = "https://console.invalid:443"
			case "origin-case":
				config["origin"] = "https://Console.invalid"
			case "lifetime":
				config["maxLifetimeSeconds"] = 86401
			case "capacity":
				config["maxSessions"] = 100001
			case "unknown":
				config["clientSecret"] = "must-not-be-accepted"
			case "alias":
				config["ClientID"] = config["clientID"]
				delete(config, "clientID")
			}
			b, _ = json.Marshal(config)
			uid := "browser-config-uid"
			if mode == "replacement" {
				uid = "replacement"
			}
			data := map[string]string{"browser.json": string(b)}
			if mode == "extra-data" {
				data["other"] = "unexpected"
			}
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/browser" {
					return false
				}
				if mode == "expired-read" {
					clock.Add(int64(5 * time.Second))
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "browser", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "rv"}, "data": data})
				return true
			})
			clock = f.clock
			reader, e := NewBrowserSettingsClient(f.client, "browser", "browser-config-uid", root)
			if e != nil {
				t.Fatal(e)
			}
			settings, e := reader.BrowserSettings(context.Background())
			if mode == "valid" || mode == "suspended" {
				if e != nil || !settings.Valid(time.Unix(0, clock.Load())) || settings.Revision.UID != uid || settings.FreshUntil.Sub(settings.ObservedAt) != 5*time.Second {
					t.Fatal("protected settings rejected", e)
				}
			} else if e == nil {
				t.Fatal("unsafe settings accepted")
			}
		})
	}
}
