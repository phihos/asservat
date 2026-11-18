package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/configuration"
)

// ADR-329: a connector delivers its cluster's bindings with their namespace
// UIDs and raw specs; the hub decodes them for the authenticated cluster with
// the same validator, and a refused spec grants nothing.
func TestAccessBindingDeliveryRoundTrip(t *testing.T) {
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/apis/asservat.io/v1alpha1/accessbindings" {
			return false
		}
		broken := permissionBinding(2)
		broken["metadata"].(map[string]any)["name"] = "broken"
		broken["spec"].(map[string]any)["roles"] = []string{"*"}
		permissionReply(w, permissionList("AccessBinding", "opaque:bindings", "", permissionBinding(1), broken))
		return true
	})
	d, err := f.client.AccessBindingDelivery(context.Background())
	if err != nil || len(d.Items) != 3 || d.ResourceVersion != "opaque:bindings" || d.ClusterResourceVersion != "opaque:cabs" {
		t.Fatal(err, d)
	}
	if i := d.Items[0]; i.Namespace != "payments" || i.NamespaceUID != "payments-uid" || i.UID != "uid-1" || i.Generation != 1 || len(i.Spec) == 0 {
		t.Fatalf("item %+v", i)
	}
	// The delivery travels as JSON and names no cluster.
	raw, _ := json.Marshal(d)
	var wire contracts.AccessBindingDelivery
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	decoder, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	const remote = "22222222-2222-4222-8222-222222222222"
	bindings, err := decoder.DeliveredBindings(remote, wire)
	if err != nil || len(bindings) != 3 {
		t.Fatal(err, bindings)
	}
	cab := bindings[2]
	if cab.Resource.Kind != value.ClusterAccessBindingKind || cab.Scope.ClusterID != remote || cab.Scope.Namespace != value.AllNamespaces || cab.NamespaceSelector["example.invalid/managed"] != "true" {
		t.Fatalf("cluster-scoped binding lost its authenticated scope or selector: %+v", cab)
	}
	ok, refused := bindings[0], bindings[1]
	if ok.Invalid || ok.Scope.ClusterID != remote || ok.Scope.Namespace != (value.NamespaceRef{Name: "payments", UID: "payments-uid"}) || ok.Effect != "Allow" || len(ok.Subjects) != 1 {
		t.Fatalf("valid binding %+v", ok)
	}
	if !refused.Invalid || len(refused.Roles) != 0 || refused.Resource.SpecDigest == ([32]byte{}) {
		t.Fatalf("refused spec %+v", refused)
	}
	if !(value.RemoteBindings{ClusterID: remote, ObservedAt: time.Now(), Bindings: bindings}).Valid() {
		t.Fatal("decoded delivery invalid")
	}
	for name, mutate := range map[string]func(*contracts.DeliveredAccessBinding){
		"namespace": func(i *contracts.DeliveredAccessBinding) { i.Namespace = "../x" },
		"uid":       func(i *contracts.DeliveredAccessBinding) { i.UID = "" },
		"no spec":   func(i *contracts.DeliveredAccessBinding) { i.Spec = nil },
		"gen":       func(i *contracts.DeliveredAccessBinding) { i.Generation = 0 },
	} {
		bad := wire
		bad.Items = append([]contracts.DeliveredAccessBinding(nil), wire.Items...)
		mutate(&bad.Items[0])
		if _, err = decoder.DeliveredBindings(remote, bad); err == nil {
			t.Fatal(name)
		}
	}
}

func TestDeliveredClusterDenyRetainsSchemaValidLongReason(t *testing.T) {
	decoder, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	const cluster = "22222222-2222-4222-8222-222222222222"
	spec := json.RawMessage(`{"effect":"Deny","subjects":[{"kind":"Group","id":"developers"}],"roles":["workload-maintainer"],"reason":"` + strings.Repeat("x", 70<<10) + `"}`)
	item := contracts.DeliveredAccessBinding{Kind: value.ClusterAccessBindingKind, Name: "blocked", UID: "binding", Generation: 1, ResourceVersion: "1", Spec: spec}
	got, err := decoder.DeliveredBindings(cluster, contracts.AccessBindingDelivery{ResourceVersion: "1", Items: []contracts.DeliveredAccessBinding{item}})
	if err != nil || len(got) != 1 || got[0].Invalid || got[0].Effect != "Deny" {
		t.Fatal("valid cluster-wide Deny lost in delivery", err)
	}
}

func TestLegacyMixedBindingSubjects(t *testing.T) {
	decoder, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"", value.ClusterAccessBindingKind} {
		item := contracts.DeliveredAccessBinding{Kind: kind, Name: "binding", UID: "binding", Generation: 1, ResourceVersion: "1"}
		if kind == "" {
			item.Namespace, item.NamespaceUID = "app", "app-uid"
		}
		// Kubernetes accepted a path as a URI in the former CRD. Its literal
		// value never substitutes for the verified issuer of another subject.
		item.Spec = json.RawMessage(`{"effect":"Deny","subjects":[{"kind":"Group","id":"developers"},{"kind":"Group","id":"other","issuer":"/legacy"}],"roles":["workload-maintainer"],"reason":"synthetic"}`)
		got, err := decoder.DeliveredBindings(permissionCluster, contracts.AccessBindingDelivery{ResourceVersion: "1", Items: []contracts.DeliveredAccessBinding{item}})
		if err != nil || len(got) != 1 || got[0].Invalid || len(got[0].Subjects) != 2 || got[0].Subjects[1].Issuer != "/legacy" {
			t.Fatalf("legacy issuer obscured valid %q Deny: %v", kind, err)
		}
		for _, bad := range []map[string]string{
			{"kind": "Group", "id": strings.Repeat("x", 257)},
			{"kind": "Group", "id": strings.Repeat("é", 129)},
			{"kind": "Group", "id": "developers\u0000"},
			{"kind": "Group", "id": "developers", "issuer": "https://example.test/" + strings.Repeat("x", 2048)},
		} {
			for _, effect := range []string{"Allow", "Deny"} {
				item.Spec, _ = json.Marshal(map[string]any{"effect": effect, "subjects": []map[string]string{{"kind": "Group", "id": "developers"}, bad}, "roles": []string{"workload-maintainer"}, "reason": "synthetic"})
				got, err := decoder.DeliveredBindings(permissionCluster, contracts.AccessBindingDelivery{ResourceVersion: "1", Items: []contracts.DeliveredAccessBinding{item}})
				if effect == "Deny" {
					if !errors.Is(err, value.ErrLimit) || len(got) != 0 {
						t.Fatalf("unrepresentable mixed-subject %q Deny accepted: %v", kind, err)
					}
				} else if err != nil || len(got) != 1 || got[0].Invalid || len(got[0].Subjects) != 1 || got[0].Subjects[0].ID != "developers" {
					t.Fatalf("unrepresentable subject obscured valid %q Allow", kind)
				}
			}
		}
	}
}

func TestBindingDeliveryReadsOversizedKubernetesPage(t *testing.T) {
	const count = 40
	objects := make([]map[string]any, count)
	for i := range objects {
		o := permissionClusterBinding()
		m := o["metadata"].(map[string]any)
		m["name"], m["uid"] = fmt.Sprintf("binding-%d", i), fmt.Sprintf("uid-%d", i)
		o["spec"].(map[string]any)["reason"] = strings.Repeat("x", 60<<10)
		objects[i] = o
	}
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/apis/asservat.io/v1alpha1/accessbindings" {
			permissionReply(w, permissionList("AccessBinding", "1", ""))
			return true
		}
		if r.URL.Path != "/apis/asservat.io/v1alpha1/clusteraccessbindings" {
			return false
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		start, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		end := min(start+limit, count)
		next := ""
		if end < count {
			next = strconv.Itoa(end)
		}
		permissionReply(w, permissionList(value.ClusterAccessBindingKind, "2", next, objects[start:end]...))
		return true
	})
	d, err := f.client.AccessBindingDelivery(t.Context())
	if err != nil || len(d.Items) != count || d.Bounded().Unavailable {
		t.Fatal("complete delivery refused", len(d.Items), err)
	}
}

func TestHubListsLegacyDeniesAtTheirActualClusters(t *testing.T) {
	const peer = "22222222-2222-4222-8222-222222222222"
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		var obj map[string]any
		var kind string
		switch r.URL.Path {
		case "/apis/asservat.io/v1alpha1/accessbindings":
			kind, obj = "AccessBinding", permissionBinding(1)
		case "/apis/asservat.io/v1alpha1/clusteraccessbindings":
			kind, obj = value.ClusterAccessBindingKind, permissionClusterBinding()
			obj["spec"].(map[string]any)["clusters"] = []string{"peer"}
		default:
			return false
		}
		spec := obj["spec"].(map[string]any)
		spec["effect"], spec["subjects"] = "Deny", []map[string]string{{"kind": "Group", "id": strings.Repeat("x", 257)}}
		permissionReply(w, permissionList(kind, "1", "", obj))
		return true
	})
	s, err := f.client.WithClusterNames(map[string]string{"peer": peer}).PermissionSnapshot(t.Context())
	if err != nil || len(s.Bindings) != 1 || len(s.ClusterBindings) != 1 || !s.Bindings[0].UnavailableDeny || !s.ClusterBindings[0].UnavailableDeny || s.Bindings[0].Scope.ClusterID != permissionCluster || s.ClusterBindings[0].Scope.ClusterID != peer {
		t.Fatal("unrelated cluster lost when the hub observed a legacy Deny", err)
	}
}

func TestBindingDeliveryCompletesDelayedPagesWithinCallerDeadline(t *testing.T) {
	t.Parallel()
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/apis/asservat.io/v1alpha1/accessbindings" {
			permissionReply(w, permissionList("AccessBinding", "1", ""))
			return true
		}
		if r.URL.Path != "/apis/asservat.io/v1alpha1/clusteraccessbindings" {
			return false
		}
		// Each page is within the REST request deadline. Together they
		// exceed five seconds, including when the wire data is tiny.
		select {
		case <-time.After(2600 * time.Millisecond):
		case <-r.Context().Done():
			return true
		}
		o := permissionClusterBinding()
		cursor := r.URL.Query().Get("continue")
		next := ""
		switch cursor {
		case "":
			next = "second"
		case "second":
			m := o["metadata"].(map[string]any)
			m["name"], m["uid"] = "second", "second-uid"
		default:
			t.Errorf("unexpected cursor %q", cursor)
		}
		permissionReply(w, permissionList(value.ClusterAccessBindingKind, "consistent", next, o))
		return true
	})
	d, err := f.client.AccessBindingDelivery(t.Context())
	if err != nil || len(d.Items) != 2 || d.ClusterResourceVersion != "consistent" || d.Items[1].UID != "second-uid" {
		t.Fatalf("complete paginated observation lost: %d items, %v", len(d.Items), err)
	}
	hub, err := f.client.PermissionSnapshot(t.Context())
	if err != nil || len(hub.ClusterBindings) != 2 || hub.ClusterBindingResourceVersion != "consistent" {
		t.Errorf("hub baseline lost delayed continuation: %d items, %v", len(hub.ClusterBindings), err)
	}
	early, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	d, err = f.client.AccessBindingDelivery(early)
	if !errors.Is(err, context.DeadlineExceeded) || len(d.Items) != 0 {
		t.Fatal("caller deadline ignored", err)
	}
}

func TestBindingDeliveryReadsEachUnplacedNamespaceOnce(t *testing.T) {
	var gets atomic.Int64
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces/payments":
			gets.Add(1)
			return false
		case "/apis/asservat.io/v1alpha1/accessbindings":
			var items []map[string]any
			for i := range permissionPageSize {
				items = append(items, permissionBinding(i))
			}
			// The current namespace is newer than just this binding.
			items[0]["metadata"].(map[string]any)["creationTimestamp"] = "2026-09-01T00:00:00Z"
			permissionReply(w, permissionList("AccessBinding", "1", "", items...))
			return true
		}
		return false
	})
	d, err := f.client.AccessBindingDelivery(t.Context())
	if err != nil || len(d.Items) != permissionPageSize || gets.Load() != 1 {
		t.Fatal("namespace placement", len(d.Items), gets.Load(), err)
	}
	decoder, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := decoder.DeliveredBindings(permissionCluster, d)
	if err != nil || !value.ValidClusterBindings(permissionCluster, bindings) {
		t.Fatal("hub refused complete replacement", err)
	}
	for i, item := range d.Items[:permissionPageSize-1] {
		if item.NamespaceUID != "payments-uid" || item.UID == "uid-0" {
			t.Fatal("binding placed in different incarnation", i, item.NamespaceUID)
		}
	}
}

func TestConnectorStopsReadingWhenBothCollectionsExceedTransferBudget(t *testing.T) {
	var clusterPages atomic.Int64
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		var kind string
		var obj map[string]any
		switch r.URL.Path {
		case "/apis/asservat.io/v1alpha1/accessbindings":
			kind, obj = "AccessBinding", permissionBinding(1)
		case "/apis/asservat.io/v1alpha1/clusteraccessbindings":
			kind, obj = value.ClusterAccessBindingKind, permissionClusterBinding()
			clusterPages.Add(1)
		default:
			return false
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		m := obj["metadata"].(map[string]any)
		m["name"], m["uid"] = fmt.Sprintf("binding-%d", page), fmt.Sprintf("%s-%d", kind, page)
		obj["spec"].(map[string]any)["reason"] = strings.Repeat("x", 1<<20)
		next := strconv.Itoa(page + 1)
		if page == 4 {
			next = ""
		}
		permissionReply(w, permissionList(kind, "rv", next, obj))
		return true
	})
	d, err := f.client.AccessBindingDelivery(t.Context())
	if err != nil || !d.Unavailable || d.ResourceVersion != "rv" || d.ClusterResourceVersion != "rv" || len(d.Items) != 0 || clusterPages.Load() != 3 {
		t.Fatalf("oversized observation: %d items, %d cluster pages, %v", len(d.Items), clusterPages.Load(), err)
	}
}

func TestNamespacedBindingsAloneExceedBudget(t *testing.T) {
	var pages, metadataReads atomic.Int64
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/apis/asservat.io/v1alpha1/accessbindings":
			n := int(pages.Add(1))
			o := permissionBinding(n)
			o["spec"].(map[string]any)["reason"] = strings.Repeat("x", 1<<20)
			next := strconv.Itoa(n)
			if n == 10 {
				next = ""
			}
			permissionReply(w, permissionList("AccessBinding", "oversized-local", next, o))
		case "/apis/asservat.io/v1alpha1/clusteraccessbindings":
			metadataReads.Add(1)
			if r.URL.Query().Get("limit") != "1" || !strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadataList") {
				t.Error("read full cluster binding data after budget was exhausted")
			}
			permissionReply(w, map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadataList", "metadata": map[string]string{"resourceVersion": "cluster-metadata", "continue": "unneeded"}, "items": nil})
		default:
			return false
		}
		return true
	})
	d, err := f.client.AccessBindingDelivery(t.Context())
	if err != nil || !d.Unavailable || len(d.Items) != 0 || d.ResourceVersion != "oversized-local" || d.ClusterResourceVersion != "cluster-metadata" || metadataReads.Load() != 1 || pages.Load() != 8 {
		t.Fatal("cannot watch oversized replacement", d.ResourceVersion, d.ClusterResourceVersion, pages.Load(), metadataReads.Load(), err)
	}
}
