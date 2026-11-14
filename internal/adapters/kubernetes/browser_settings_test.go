package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestBrowserSettingsProtectedConfig(t *testing.T) {
	for _, mode := range []string{"valid", "defaults", "replacement", "insecure-issuer", "origin-path", "origin-query", "origin-user", "origin-default-port", "origin-case", "zero-lifetime", "unknown", "alias", "extra-data"} {
		t.Run(mode, func(t *testing.T) {
			b, e := readImplementedExample("../../../examples/", "browser-settings.json")
			if e != nil {
				t.Fatal(e)
			}
			var config map[string]any
			_ = json.Unmarshal(b, &config)
			switch mode {
			case "defaults":
				delete(config, "maxLifetimeSeconds")
				delete(config, "inactivityTimeoutSeconds")
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
			case "zero-lifetime":
				config["maxLifetimeSeconds"] = 0
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
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/browser" {
					return false
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "browser", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "rv"}, "data": data})
				return true
			})
			reader, e := NewBrowserSettingsReader(f.client, "browser", "browser-config-uid")
			if e != nil {
				t.Fatal(e)
			}
			settings, e := reader.BrowserSettings(context.Background())
			if mode == "valid" || mode == "defaults" {
				if e != nil || !settings.Valid() || settings.MaxLifetime != 7*24*time.Hour || settings.InactivityTimeout != 24*time.Hour {
					t.Fatal("settings rejected or defaults lost", e, settings)
				}
			} else if e == nil {
				t.Fatal("unsafe settings accepted")
			}
		})
	}
}

// readImplementedExample reads the example this runtime implements:
// examples/implemented/ (pre-ADR-330 contracts) when present, otherwise the
// canonical example.
func readImplementedExample(dir, name string) ([]byte, error) {
	if b, err := os.ReadFile(dir + "implemented/" + name); err == nil {
		return b, nil
	}
	return os.ReadFile(dir + name)
}
