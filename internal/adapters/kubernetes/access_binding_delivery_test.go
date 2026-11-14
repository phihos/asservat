package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
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
	if err != nil || len(d.Items) != 2 || d.ResourceVersion != "opaque:bindings" {
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
	if err != nil || len(bindings) != 2 {
		t.Fatal(err, bindings)
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
