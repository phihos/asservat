package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func capacityMetadataItem(kind, namespace, name, uid string, labels map[string]string, owned bool) map[string]any {
	m := map[string]any{"name": name, "uid": uid, "resourceVersion": "rv-" + name}
	if namespace != "" {
		m["namespace"] = namespace
	}
	if labels != nil {
		m["labels"] = labels
	}
	if owned {
		m["ownerReferences"] = []map[string]any{{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs", "uid": "rs-uid"}}
	}
	return map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": m}
}

func capacityMetadataList(items ...map[string]any) map[string]any {
	if items == nil {
		items = []map[string]any{}
	}
	return map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadataList", "metadata": map[string]any{"resourceVersion": "7"}, "items": items}
}

// ADR-330: a connector delivers only the namespaces carrying a capacity key,
// with only those labels, and their Deployments, StatefulSets and unowned
// Pods; the hub attributes the delivery to the authenticated cluster.
func TestCapacityDeliveryRoundTrip(t *testing.T) {
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces":
			permissionReply(w, capacityMetadataList(capacityMetadataItem("Namespace", "", "payments", "ns-1", map[string]string{"asservat-trial": "true", "team": "secret"}, false),
				capacityMetadataItem("Namespace", "", "other", "ns-2", map[string]string{"team": "x"}, false)))
		case "/apis/apps/v1/namespaces/payments/deployments":
			permissionReply(w, capacityMetadataList(capacityMetadataItem("Deployment", "payments", "api", "w-1", nil, false)))
		case "/apis/apps/v1/namespaces/payments/statefulsets":
			permissionReply(w, capacityMetadataList())
		case "/api/v1/namespaces/payments/pods":
			permissionReply(w, capacityMetadataList(capacityMetadataItem("Pod", "payments", "api-1", "p-1", nil, true), capacityMetadataItem("Pod", "payments", "bare", "p-2", nil, false)))
		default:
			return false
		}
		return true
	})
	f.clock.Store(time.Now().UnixNano()) // the page deadlines use the client clock
	d, err := f.client.CapacityDelivery(context.Background(), []string{"asservat-trial"})
	if err != nil || len(d.Namespaces) != 1 {
		t.Fatal(err, d)
	}
	n := d.Namespaces[0]
	if n.Name != "payments" || n.UID != "ns-1" || len(n.Labels) != 1 || n.Labels["asservat-trial"] != "true" || len(n.Workloads) != 2 || n.Workloads[0].Kind != "Deployment" || n.Workloads[1].Name != "bare" {
		t.Fatalf("namespace %+v", n)
	}
	raw, _ := json.Marshal(d)
	var wire contracts.CapacityDelivery
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	const remote = "22222222-2222-4222-8222-222222222222"
	at := time.Now()
	c, err := DeliveredCapacity(remote, at, wire)
	if err != nil || c.ClusterID != remote || !c.ObservedAt.Equal(at) || len(c.Namespaces) != 1 || len(c.Namespaces[0].Workloads) != 2 {
		t.Fatal(err, c)
	}
	for name, mutate := range map[string]func(*contracts.DeliveredCapacityNamespace){
		"namespace": func(n *contracts.DeliveredCapacityNamespace) { n.Name = "../x" },
		"no labels": func(n *contracts.DeliveredCapacityNamespace) { n.Labels = nil },
		"label":     func(n *contracts.DeliveredCapacityNamespace) { n.Labels = map[string]string{"bad key!": "v"} },
		"workload":  func(n *contracts.DeliveredCapacityNamespace) { n.Workloads[0].Name = "Bad" },
		"kind":      func(n *contracts.DeliveredCapacityNamespace) { n.Workloads[0].Kind = "Job" },
	} {
		bad := contracts.CapacityDelivery{Namespaces: []contracts.DeliveredCapacityNamespace{wire.Namespaces[0]}}
		bad.Namespaces[0].Workloads = append([]contracts.DeliveredCapacityWorkload(nil), wire.Namespaces[0].Workloads...)
		mutate(&bad.Namespaces[0])
		if _, err = DeliveredCapacity(remote, at, bad); err == nil {
			t.Error(name)
		}
	}
	if _, err = f.client.CapacityDelivery(context.Background(), nil); err == nil {
		t.Fatal("delivery without keys")
	}
}
