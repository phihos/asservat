package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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

func TestLegacyMixedSubjectDenyClosesDelivery(t *testing.T) {
	decoder, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"", value.ClusterAccessBindingKind} {
		item := contracts.DeliveredAccessBinding{Kind: kind, Name: "blocked", UID: "binding", Generation: 1, ResourceVersion: "1"}
		if kind == "" {
			item.Namespace, item.NamespaceUID = "app", "app-uid"
		}
		for _, id := range []string{strings.Repeat("x", 257), strings.Repeat("é", 129)} {
			item.Spec, _ = json.Marshal(map[string]any{"effect": "Deny", "subjects": []map[string]string{{"kind": "Group", "id": "developers"}, {"kind": "Group", "id": id}}, "roles": []string{"workload-maintainer"}, "reason": "synthetic"})
			got, err := decoder.DeliveredBindings(permissionCluster, contracts.AccessBindingDelivery{ResourceVersion: "1", Items: []contracts.DeliveredAccessBinding{item}})
			if !errors.Is(err, value.ErrLimit) || len(got) != 0 {
				t.Fatalf("unrepresentable mixed-subject %q Deny accepted: %v", kind, err)
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
