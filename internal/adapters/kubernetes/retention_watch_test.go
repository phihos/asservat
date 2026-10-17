package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

func TestRetentionWatchKeepsIntermediatePolicyLimits(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/asservat-system" {
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
			return
		}
		if r.URL.Query().Get("watch") != "true" || r.URL.Query().Get("resourceVersion") != "opaque:baseline" || r.URL.Query().Has("labelSelector") {
			t.Error("watch lost exact unfiltered cursor")
		}
		for i, maximum := range []int{600, 3600} {
			b := retentionObject("baseline", "retention-uid")
			b["metadata"].(map[string]any)["generation"] = i + 2
			b["metadata"].(map[string]any)["resourceVersion"] = []string{"opaque:b", "opaque:a"}[i]
			b["spec"].(map[string]any)["maxima"].(map[string]any)["evidenceSeconds"] = maximum
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "MODIFIED", "object": b})
			w.(http.Flusher).Flush()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "BOOKMARK", "object": map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceRetentionPolicy", "metadata": map[string]string{"resourceVersion": "opaque:bookmark"}}})
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	c, err := NewPermissionClient(config, permissionCluster, permissionControl, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := NewRetentionClient(c, true)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := retention.WatchRetentionPolicies(context.Background(), "opaque:baseline")
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	for _, maximum := range []int{600, 3600} {
		e, err := watcher.Next(context.Background())
		if err != nil || e.Type != "MODIFIED" || e.Policy == nil || e.Policy.Policy.MaximumSeconds != int64(maximum) {
			t.Fatalf("lost %d transition: %+v %v", maximum, e, err)
		}
	}
	e, err := watcher.Next(context.Background())
	if err != nil || e.Policy != nil || e.Type != "BOOKMARK" || e.ResourceVersion != "opaque:bookmark" {
		t.Fatalf("bookmark %v", err)
	}
	if _, err = watcher.Next(context.Background()); err == nil {
		t.Fatal("closed stream asserted continuity")
	}
}
func TestRetentionWatchRejectsMalformedOrExpiredHistory(t *testing.T) {
	for _, body := range []string{
		`{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","reason":"Expired","code":410}}`,
		`{"type":"BOOKMARK","type":"MODIFIED","object":{}}`,
		`{"type":"BOOKMARK","object":{"apiVersion":"asservat.io/v1alpha1","kind":"EvidenceRetentionPolicy","metadata":{"ResourceVersion":"wrong-case"}}}`,
		`{"type":"MODIFIED","object":{"apiVersion":"asservat.io/v1alpha1","kind":"EvidenceRetentionPolicy","metadata":{},"spec":{}}}`,
	} {
		t.Run(body[:min(35, len(body))], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/v1/namespaces/asservat-system" {
					permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
					return
				}
				_, _ = w.Write([]byte(body + "\n"))
			}))
			defer server.Close()
			c, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, permissionCluster, permissionControl, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			retention, err := NewRetentionClient(c, true)
			if err != nil {
				t.Fatal(err)
			}
			w, err := retention.WatchRetentionPolicies(context.Background(), "opaque:baseline")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if _, err = w.Next(context.Background()); err == nil {
				t.Fatal("invalid watch became continuity")
			}
		})
	}
}
