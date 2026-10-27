package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

var namespaceTestKeys = value.NamespaceKeys{Labels: []string{"example.invalid/managed"}, Annotations: []string{"example.invalid/owner"}}

func namespaceTestServer(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *PermissionClient {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/namespaces" || r.URL.Query().Has("labelSelector") || r.URL.Query().Has("fieldSelector") {
			t.Error("unexpected namespace request", r.URL.String())
		}
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	cfg := &rest.Config{Host: s.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})}}
	c, err := NewPermissionClient(cfg, permissionCluster, permissionControl, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func namespaceItem(name, uid, rv string, withKeys bool) map[string]any {
	o := permissionNamespace(name, uid)
	m := o["metadata"].(map[string]any)
	m["resourceVersion"] = rv
	if !withKeys {
		m["labels"] = map[string]string{"unrelated": "MUST-NOT-LEAK"}
		m["annotations"] = map[string]string{"unrelated": "MUST-NOT-LEAK"}
	}
	// Core list items carry no type.
	delete(o, "apiVersion")
	delete(o, "kind")
	return o
}

func TestNamespaceListIsCompleteAndMinimized(t *testing.T) {
	c := namespaceTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("resourceVersion") || r.URL.Query().Get("limit") != "200" {
			t.Error("namespace list cached or unbounded")
		}
		page := map[string]any{"apiVersion": "v1", "kind": "NamespaceList", "metadata": map[string]any{"resourceVersion": "100", "continue": "next"}, "items": []any{namespaceItem("payments", "p-uid", "7", true)}}
		if r.URL.Query().Get("continue") == "next" {
			page = map[string]any{"apiVersion": "v1", "kind": "NamespaceList", "metadata": map[string]any{"resourceVersion": "100"}, "items": []any{namespaceItem("plain", "q-uid", "8", false)}}
		}
		permissionReply(w, page)
	})
	l, err := c.ListNamespaces(context.Background(), namespaceTestKeys)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(l)
	if l.ResourceVersion != "100" || len(l.Namespaces) != 1 || strings.Contains(string(encoded), "MUST-NOT-LEAK") || strings.Contains(string(encoded), `"payments"}`) {
		t.Fatalf("list not complete and minimized: %s", encoded)
	}
	n := l.Namespaces[0]
	if n.UID != "p-uid" || n.ResourceVersion != "7" || n.Annotations["example.invalid/owner"] != port.ValueDigest("payments") || n.Labels["example.invalid/managed"] != port.ValueDigest("true") || len(n.Labels)+len(n.Annotations) != 2 {
		t.Fatalf("namespace not reduced to digests of observed keys: %+v", n)
	}
	if _, err = c.ListNamespaces(context.Background(), value.NamespaceKeys{}); !errors.Is(err, value.ErrInvalid) {
		t.Fatal("empty key set accepted")
	}
}

func TestNamespaceListRejectsInconsistentPages(t *testing.T) {
	c := namespaceTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		rv := "100"
		next := "next"
		if r.URL.Query().Get("continue") == "next" {
			rv, next = "101", ""
		}
		permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "NamespaceList", "metadata": map[string]any{"resourceVersion": rv, "continue": next}, "items": []any{}})
	})
	if _, err := c.ListNamespaces(context.Background(), namespaceTestKeys); err == nil {
		t.Fatal("pages at different resource versions accepted")
	}
}

func TestNamespaceWatchDeliversOrderedReducedTransitions(t *testing.T) {
	c := namespaceTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("watch") != "true" || q.Get("resourceVersion") != "100" || q.Get("timeoutSeconds") != "2" {
			t.Error("watch not resumed from the cursor", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		modified := namespaceItem("payments", "p-uid", "101", true)
		modified["apiVersion"], modified["kind"] = "v1", "Namespace"
		_ = e.Encode(map[string]any{"type": "MODIFIED", "object": modified})
		_ = e.Encode(map[string]any{"type": "BOOKMARK", "object": map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"resourceVersion": "102"}}})
		if q.Get("resourceVersion") == "100" {
			_ = e.Encode(map[string]any{"type": "ERROR", "object": map[string]any{"kind": "Status", "code": 410}})
		}
	})
	w, err := c.WatchNamespaces(context.Background(), "100", namespaceTestKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	e, err := w.Next(context.Background())
	if err != nil || e.Type != "MODIFIED" || e.ResourceVersion != "101" || e.Namespace == nil || e.Namespace.Annotations["example.invalid/owner"] != port.ValueDigest("payments") {
		t.Fatalf("transition %+v %v", e, err)
	}
	if e, err = w.Next(context.Background()); err != nil || e.Type != "BOOKMARK" || e.ResourceVersion != "102" || e.Namespace != nil {
		t.Fatalf("bookmark %+v %v", e, err)
	}
	if _, err = w.Next(context.Background()); !errors.Is(err, value.ErrChanged) {
		t.Fatal("expired history not reported as a changed history", err)
	}
}

func TestNamespaceWatchCleanEndIsEOF(t *testing.T) {
	c := namespaceTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
	})
	w, err := c.WatchNamespaces(context.Background(), "100", namespaceTestKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatal("clean session end not EOF", err)
	}
}
