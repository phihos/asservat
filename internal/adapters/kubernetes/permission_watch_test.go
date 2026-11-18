package kubernetes

import (
	value "asservat.local/asservat/internal/domain/configuration"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

func TestPermissionWatchKeepsIntermediateOwnershipTransitions(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/asservat-system" {
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
			return
		}
		if r.URL.Path == "/api/v1/namespaces/payments" {
			permissionReply(w, permissionNamespace("payments", "payments-uid"))
			return
		}
		if r.URL.Path != "/apis/asservat.io/v1alpha1/accessbindings" || r.URL.Query().Get("watch") != "true" || r.URL.Query().Get("resourceVersion") != "opaque:baseline" || r.URL.Query().Has("labelSelector") {
			t.Error("watch lost exact unfiltered cursor")
		}
		for i, team := range []string{"team-b", "team-a"} {
			b := permissionBinding(1)
			b["metadata"].(map[string]any)["generation"] = i + 2
			b["metadata"].(map[string]any)["resourceVersion"] = []string{"opaque:b", "opaque:a"}[i]
			b["spec"].(map[string]any)["subjects"] = []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": team}}
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "MODIFIED", "object": b})
			w.(http.Flusher).Flush()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "BOOKMARK", "object": map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]string{"resourceVersion": "opaque:bookmark"}}})
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	c, err := NewPermissionClient(config, permissionCluster, permissionControl, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := c.WatchBindings(context.Background(), "opaque:baseline")
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	for _, team := range []string{"team-b", "team-a"} {
		e, err := watcher.Next(context.Background())
		if err != nil || e.Type != "MODIFIED" || e.Binding == nil || e.Binding.Subjects[0].ID != team || e.Binding.Scope.Namespace.UID != "payments-uid" {
			t.Fatalf("lost %s transition: %+v %v", team, e, err)
		}
	}
	e, err := watcher.Next(context.Background())
	if err != nil || e.Binding != nil || e.Type != "BOOKMARK" || e.ResourceVersion != "opaque:bookmark" {
		t.Fatalf("bookmark %v", err)
	}
	if _, err = watcher.Next(context.Background()); err == nil {
		t.Fatal("closed stream asserted continuity")
	}
}
func TestWatchRejectsMalformedOrExpiredHistory(t *testing.T) {
	for _, body := range []string{
		`{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","reason":"Expired","code":410}}`,
		`{"type":"BOOKMARK","type":"MODIFIED","object":{}}`,
		`{"type":"BOOKMARK","object":{"apiVersion":"asservat.io/v1alpha1","kind":"AccessBinding","metadata":{"ResourceVersion":"wrong-case"}}}`,
		`{"type":"MODIFIED","object":{"apiVersion":"asservat.io/v1alpha1","kind":"AccessBinding","metadata":{},"spec":{}}}`,
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
			w, err := c.WatchBindings(context.Background(), "opaque:baseline")
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

func TestIdlePermissionAndRetentionWatches(t *testing.T) {
	// Each stream carries over 2 MiB in separate valid Kubernetes objects.
	const eventCount = 20
	padding := strings.Repeat("a", 120<<10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/asservat-system" {
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5500 * time.Millisecond):
		}
		kind := "AccessBinding"
		if strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies") {
			kind = "EvidenceRetentionPolicy"
		}
		for i := range eventCount {
			err := json.NewEncoder(w).Encode(map[string]any{"type": "BOOKMARK", "object": map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": kind, "metadata": map[string]any{"resourceVersion": strconv.Itoa(i + 1), "annotations": map[string]string{"test": padding}}}})
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	c, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, permissionCluster, permissionControl, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := NewRetentionClient(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	bindings, err := c.WatchBindings(ctx, "before-idle")
	if err != nil {
		t.Fatal(err)
	}
	defer bindings.Close()
	policies, err := retention.WatchRetentionPolicies(ctx, "before-idle")
	if err != nil {
		t.Fatal(err)
	}
	defer policies.Close()
	for i := range eventCount {
		want := strconv.Itoa(i + 1)
		b, err := bindings.Next(ctx)
		if err != nil || b.ResourceVersion != want {
			t.Fatalf("binding stream event %s: %q %v", want, b.ResourceVersion, err)
		}
		p, err := policies.Next(ctx)
		if err != nil || p.ResourceVersion != want {
			t.Fatalf("retention stream event %s: %q %v", want, p.ResourceVersion, err)
		}
	}
	if _, err := bindings.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("binding stream final EOF: %v", err)
	}
}

func TestWatchLimitsOneOversizeEventBeforeReadingTheRest(t *testing.T) {
	raw := `{"type":"BOOKMARK","object":{"padding":"` + strings.Repeat("a", 2*permissionPageBytes) + `"}}`
	body := strings.NewReader(raw)
	events := newPermissionWatchEvents(io.NopCloser(body))
	if _, err := events.next(); !errors.Is(err, value.ErrLimit) || len(raw)-body.Len() != permissionPageBytes+1 {
		t.Fatal("oversize watch event", err, len(raw)-body.Len())
	}
}

func TestPermissionRequestsStillBoundOpeningAndFiniteReads(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces/asservat-system" {
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
			return
		}
		if r.URL.Query().Get("watch") != "true" {
			w.Header().Set("Content-Type", "application/json")
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	c, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, permissionCluster, permissionControl, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := NewRetentionClient(c)
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]func(context.Context) error{
		"binding headers":        func(ctx context.Context) error { _, err := c.WatchBindings(ctx, "1"); return err },
		"retention headers":      func(ctx context.Context) error { _, err := retention.WatchRetentionPolicies(ctx, "1"); return err },
		"ordinary response body": func(ctx context.Context) error { _, err := c.raw(ctx, "/api/v1/namespaces/wait", nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			if err := request(ctx); err == nil || ctx.Err() != nil {
				t.Fatalf("request overstayed its own deadline: %v %v", err, ctx.Err())
			}
		})
	}
}
