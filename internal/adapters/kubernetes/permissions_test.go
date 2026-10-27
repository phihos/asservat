package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

const permissionCluster = "11111111-1111-4111-8111-111111111111"

var permissionControl = value.NamespaceRef{Name: "asservat-system", UID: "control-ns-uid"}

func permissionBinding(index int) map[string]any {
	return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": fmt.Sprintf("binding-%d", index), "namespace": permissionControl.Name, "uid": fmt.Sprintf("uid-%d", index), "generation": 1, "resourceVersion": "opaque:item"}, "spec": map[string]any{"effect": "Allow", "subjects": []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "team-a"}}, "roles": []string{"workload-maintainer"}, "scope": map[string]any{"clusterID": permissionCluster, "namespaceRef": map[string]any{"name": "payments", "uid": "payments-uid"}}, "reason": "synthetic fixture"}, "status": map[string]any{"phase": "Ready", "observedGeneration": 999}}
}
func permissionSource() map[string]any {
	return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "PermissionSource", "metadata": map[string]any{"name": "owners", "namespace": permissionControl.Name, "uid": "source-uid", "generation": 1, "resourceVersion": "opaque:source"}, "spec": map[string]any{"enabled": true, "clusterID": permissionCluster, "type": "namespaceMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]any{"example.invalid/managed": "true"}}, "excludedNamespaces": []string{"kube-system"}, "role": "evidence-owner", "maxDecisionAgeSeconds": 30, "maxNamespaces": 200, "protection": map[string]any{"mode": "administratorManaged", "reviewRef": "synthetic-review"}, "metadataMapping": map[string]any{"field": "annotation", "key": "example.invalid/owner", "mode": "valueMap", "issuer": "https://id.example.invalid", "values": map[string]any{"payments": []string{"team-a", "team-b"}}}}}
}
func permissionList(kind, rv, next string, items ...map[string]any) map[string]any {
	if items == nil {
		items = []map[string]any{}
	}
	return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": kind + "List", "metadata": map[string]any{"resourceVersion": rv, "continue": next}, "items": items}
}
func permissionNamespace(name, uid string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": name, "uid": uid, "resourceVersion": "opaque:ns", "labels": map[string]string{"example.invalid/managed": "true", "unrelated": "MUST-NOT-LEAK"}, "annotations": map[string]string{"example.invalid/owner": "payments", "unrelated": "MUST-NOT-LEAK"}}}
}
func permissionReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type permissionFixture struct {
	client *PermissionClient
	config *rest.Config
	clock  *atomic.Int64
}

func newPermissionFixture(t *testing.T, extra func(http.ResponseWriter, *http.Request) bool) permissionFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC).UnixNano())
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method != "GET" && !(r.Method == "POST" && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews")) || r.Header.Get("Authorization") != "Bearer synthetic-only" {
			t.Error("unexpected request method/credential")
		}
		if r.URL.Query().Has("resourceVersion") || r.URL.Query().Has("labelSelector") || r.URL.Query().Has("fieldSelector") {
			t.Error("authority list was cached or filtered")
		}
		if extra != nil && extra(w, r) {
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/asservat-system":
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
		case "/api/v1/namespaces/payments":
			permissionReply(w, permissionNamespace("payments", "payments-uid"))
		case "/apis/asservat.io/v1alpha1/namespaces/asservat-system/accessbindings":
			permissionReply(w, permissionList("AccessBinding", "opaque:bindings", "", permissionBinding(1)))
		case "/apis/asservat.io/v1alpha1/namespaces/asservat-system/permissionsources":
			permissionReply(w, permissionList("PermissionSource", "opaque:sources", "", permissionSource()))
		default:
			t.Error("unexpected API path")
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	cfg := &rest.Config{Host: s.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})}}
	c, err := NewPermissionClient(cfg, permissionCluster, permissionControl, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return permissionFixture{c, cfg, clock}
}

func TestPermissionSnapshotAndMinimizedNamespace(t *testing.T) {
	f := newPermissionFixture(t, nil)
	s, err := f.client.PermissionSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Bindings) != 1 || len(s.Sources) != 1 || s.BindingResourceVersion != "opaque:bindings" || s.SourceResourceVersion != "opaque:sources" || s.FreshUntil.Sub(s.ObservedAt) != 5*time.Second {
		t.Fatal("incomplete snapshot")
	}
	b := s.Bindings[0]
	if b.Resource.UID != "uid-1" || b.Resource.Generation != 1 || b.Resource.NamespaceUID != permissionControl.UID || b.Resource.SpecDigest == ([32]byte{}) {
		t.Fatal("source provenance lost")
	}
	ns, err := f.client.NamespaceMetadata(context.Background(), value.NamespaceQuery{Namespace: value.NamespaceRef{Name: "payments", UID: "payments-uid"}, LabelKeys: []string{"example.invalid/managed"}, AnnotationKeys: []string{"example.invalid/owner"}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(ns)
	if strings.Contains(string(encoded), "MUST-NOT-LEAK") || len(ns.Labels) != 1 || len(ns.Annotations) != 1 {
		t.Fatal("unselected namespace content escaped")
	}
	target := value.Target{ClusterID: permissionCluster, Namespace: ns.Namespace, Workload: value.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload-uid"}}
	observation := &value.NamespaceObservation{ClusterID: permissionCluster, Keys: value.NamespaceKeys{Labels: []string{"example.invalid/managed"}, Annotations: []string{"example.invalid/owner"}},
		Namespaces: []value.ObservedNamespace{{Name: ns.Namespace.Name, UID: ns.Namespace.UID, Labels: map[string]string{"example.invalid/managed": port.ValueDigest(ns.Labels["example.invalid/managed"])}, Annotations: map[string]string{"example.invalid/owner": port.ValueDigest(ns.Annotations["example.invalid/owner"])}}}}
	if grants, reason := port.NamespaceGrants(s.Sources[0], permissionCluster, observation); reason != "" || len(grants) != 1 || len(grants[0].Subjects) != 2 {
		t.Fatal("mapping did not preserve multiple teams", reason)
	}
	if p := value.ProposeBinding(b, target, s.ObservedAt); len(p.Candidates) != 1 || p.Reason != "RequiresAcceptance" {
		t.Fatal("binding was not an unaccepted proposal")
	}
}

func TestUnavailableAllowSourcesDoNotDiscardCompleteBindings(t *testing.T) {
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/permissionsources") {
			http.Error(w, "MUST-NOT-LEAK", http.StatusForbidden)
			return true
		}
		return false
	})
	s, err := f.client.PermissionSnapshot(context.Background())
	if err != nil || len(s.Bindings) != 1 {
		t.Fatal("unavailable allow-only sources discarded complete explicit bindings")
	}
	if s.SourcesComplete || len(s.Sources) != 0 || s.SourceResourceVersion != "" {
		t.Fatal("failed source list presented as current")
	}
}

func TestPermissionPaginationIsCompleteOrUnavailable(t *testing.T) {
	for _, mode := range []string{"complete", "changedRV", "duplicateUID", "duplicateName", "cycle", "expired", "secondPageForbidden", "overflow", "emptyMiddle", "missingItems", "tooManyInPage"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/accessbindings") {
					return false
				}
				page := calls.Add(1)
				if r.URL.Query().Get("limit") != "64" {
					t.Error("missing list bound")
				}
				if mode == "overflow" {
					var items []map[string]any
					for i := 0; i < 64; i++ {
						items = append(items, permissionBinding(int(page)*64+i))
					}
					permissionReply(w, permissionList("AccessBinding", "rv", fmt.Sprint(page), items...))
					return true
				}
				if mode == "tooManyInPage" {
					var items []map[string]any
					for i := 0; i < 65; i++ {
						items = append(items, permissionBinding(i))
					}
					permissionReply(w, permissionList("AccessBinding", "rv", "", items...))
					return true
				}
				if page == 1 {
					permissionReply(w, permissionList("AccessBinding", "rv", "next", permissionBinding(1)))
					return true
				}
				if page == 2 && r.URL.Query().Get("continue") != "next" {
					t.Error("continuation lost")
				}
				rv := "rv"
				item := permissionBinding(2)
				next := ""
				switch mode {
				case "expired":
					http.Error(w, "MUST-NOT-LEAK", http.StatusGone)
					return true
				case "secondPageForbidden":
					http.Error(w, "MUST-NOT-LEAK", http.StatusForbidden)
					return true
				case "changedRV":
					rv = "new"
				case "duplicateUID":
					item["metadata"].(map[string]any)["uid"] = "uid-1"
				case "duplicateName":
					item["metadata"].(map[string]any)["name"] = "binding-1"
				case "cycle":
					next = "next"
				case "emptyMiddle":
					if page == 2 {
						permissionReply(w, permissionList("AccessBinding", rv, "final"))
						return true
					}
				case "missingItems":
					v := permissionList("AccessBinding", rv, "")
					delete(v, "items")
					permissionReply(w, v)
					return true
				}
				permissionReply(w, permissionList("AccessBinding", rv, next, item))
				return true
			})
			s, err := f.client.PermissionSnapshot(context.Background())
			if mode == "complete" || mode == "emptyMiddle" {
				if err != nil || len(s.Bindings) != 2 {
					t.Fatalf("complete list: %v", err)
				}
				return
			}
			if err == nil || len(s.Bindings) != 0 || s.BindingResourceVersion != "" {
				t.Fatal("partial/inconsistent list escaped")
			}
			if strings.Contains(err.Error(), "MUST-NOT-LEAK") {
				t.Fatal("downstream error content leaked")
			}
		})
	}
}

func TestPermissionMalformedObjectsAndIdentity(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong kind":       func(o map[string]any) { o["kind"] = "PermissionSource" },
		"wrong namespace":  func(o map[string]any) { o["metadata"].(map[string]any)["namespace"] = "other" },
		"missing uid":      func(o map[string]any) { delete(o["metadata"].(map[string]any), "uid") },
		"uid alias":        func(o map[string]any) { m := o["metadata"].(map[string]any); m["UID"] = m["uid"]; delete(m, "uid") },
		"generation zero":  func(o map[string]any) { o["metadata"].(map[string]any)["generation"] = 0 },
		"effect alias":     func(o map[string]any) { s := o["spec"].(map[string]any); s["Effect"] = "Allow"; delete(s, "effect") },
		"effect unknown":   func(o map[string]any) { o["spec"].(map[string]any)["effect"] = "Maybe" },
		"unknown spec key": func(o map[string]any) { o["spec"].(map[string]any)["grantAll"] = true },
		"empty subjects":   func(o map[string]any) { o["spec"].(map[string]any)["subjects"] = []any{} },
		"wildcard role":    func(o map[string]any) { o["spec"].(map[string]any)["roles"] = []string{"*"} },
		"null roles":       func(o map[string]any) { o["spec"].(map[string]any)["roles"] = nil },
		"invalid scope name": func(o map[string]any) {
			o["spec"].(map[string]any)["scope"].(map[string]any)["namespaceRef"] = map[string]string{"name": "../other", "uid": "uid"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/accessbindings") {
					return false
				}
				o := permissionBinding(1)
				mutate(o)
				permissionReply(w, permissionList("AccessBinding", "rv", "", o))
				return true
			})
			if s, err := f.client.PermissionSnapshot(context.Background()); err == nil || len(s.Bindings) != 0 {
				t.Fatal("malformed authority accepted")
			}
		})
	}
}

func TestPermissionSourceClockAndNamespaceReplacement(t *testing.T) {
	for _, mode := range []string{"advance", "rollback", "replaceControl", "deletingControl", "replaceTarget", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var count atomic.Int64
			var f permissionFixture
			f = newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if strings.HasSuffix(r.URL.Path, "/permissionsources") {
					if mode == "advance" {
						f.clock.Add(int64(6 * time.Second))
					}
					if mode == "rollback" {
						f.clock.Add(-int64(time.Second))
					}
				}
				if r.URL.Path == "/api/v1/namespaces/asservat-system" && count.Add(1) == 2 {
					if mode == "replaceControl" {
						permissionReply(w, permissionNamespace(permissionControl.Name, "replacement"))
						return true
					}
					if mode == "deletingControl" {
						o := permissionNamespace(permissionControl.Name, permissionControl.UID)
						o["metadata"].(map[string]any)["deletionTimestamp"] = "2026-10-10T12:00:00Z"
						permissionReply(w, o)
						return true
					}
				}
				return false
			})
			if mode == "replaceTarget" {
				_, err := f.client.NamespaceMetadata(context.Background(), value.NamespaceQuery{Namespace: value.NamespaceRef{Name: "payments", UID: "wrong"}})
				if !errors.Is(err, value.ErrChanged) {
					t.Fatal("target replacement accepted")
				}
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			if s, err := f.client.PermissionSnapshot(ctx); err == nil || len(s.Bindings) != 0 {
				t.Fatal("stale/replaced source accepted")
			}
		})
	}
}

func TestPermissionTLSRedirectAndResponseBounds(t *testing.T) {
	for _, mode := range []string{"tls", "redirect", "oversize", "duplicateJSON", "trailingJSON", "deepJSON"} {
		t.Run(mode, func(t *testing.T) {
			var redirected atomic.Int64
			destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer destination.Close()
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if mode == "tls" {
					return false
				}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "redirect":
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
				case "oversize":
					_, _ = w.Write([]byte(`{"padding":"` + strings.Repeat("a", permissionPageBytes) + `"}`))
				case "duplicateJSON":
					_, _ = w.Write([]byte(`{"kind":"Namespace","kind":"Namespace"}`))
				case "trailingJSON":
					_, _ = w.Write([]byte(`{} {}`))
				case "deepJSON":
					_, _ = w.Write([]byte(strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40)))
				}
				return true
			})
			if mode == "tls" {
				cfg := rest.CopyConfig(f.config)
				cfg.CAData = nil
				var err error
				f.client, err = NewPermissionClient(cfg, permissionCluster, permissionControl, time.Now)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.client.PermissionSnapshot(context.Background()); err == nil {
				t.Fatal("unsafe transport response accepted")
			}
			if redirected.Load() != 0 {
				t.Fatal("redirect forwarded source credential")
			}
		})
	}
}

func TestPermissionSchemaMatchesReviewedExamples(t *testing.T) {
	v, err := newPermissionValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"access-binding", "access-binding-owners", "permission-source-namespace", "permission-source-workload", "permission-source-rbac", "permission-source-exec"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile("../../../examples/" + name + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			b, err = yaml.YAMLToJSONStrict(b)
			if err != nil {
				t.Fatal(err)
			}
			o, err := objectEnvelope(b)
			if err != nil {
				t.Fatal(err)
			}
			if o.Kind == "AccessBinding" {
				_, err = v.binding(o, value.Resource{})
			} else {
				_, err = v.source(o, value.Resource{})
			}
			if err != nil {
				t.Fatal("canonical example rejected", err)
			}
		})
	}
}

func TestPermissionCanonicalDigestIgnoresStatusAndKeyOrder(t *testing.T) {
	v, err := newPermissionValidator()
	if err != nil {
		t.Fatal(err)
	}
	o := permissionBinding(1)
	b, _ := json.Marshal(o)
	parsed, _ := objectEnvelope(b)
	one, err := v.binding(parsed, value.Resource{})
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	_ = json.Unmarshal(parsed.Spec, &spec)
	parsed.Spec, _ = json.MarshalIndent(spec, "", "  ")
	two, err := v.binding(parsed, value.Resource{})
	if err != nil || one.Resource.SpecDigest != two.Resource.SpecDigest {
		t.Fatal("canonical digest changed with whitespace")
	}
	spec["effect"] = "Deny"
	parsed.Spec, _ = json.Marshal(spec)
	three, err := v.binding(parsed, value.Resource{})
	if err != nil || three.Resource.SpecDigest == one.Resource.SpecDigest {
		t.Fatal("authority change lost from digest")
	}
}

func FuzzPermissionJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `{"kind":"Namespace"}`, `{"a":1,"a":2}`, `null`, `[]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if permissionJSON(b, 64<<10, 16384) == nil {
			_, _ = objectEnvelope(b)
			_, _ = decodeMetadata(b, false)
			_, _, _ = listEnvelope(b, "AccessBinding")
		}
	})
}
