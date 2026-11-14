package kubernetes

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func capacityObject(namespace, name, uid string, labels map[string]string, owned bool) *metav1.PartialObjectMetadata {
	m := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid), ResourceVersion: "rv-" + name, Generation: 2, Labels: labels}}
	if owned {
		m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid"}}
	}
	return m
}

// ADR-330: a connector delivers only the namespaces carrying a capacity key,
// with only those labels, and their Deployments, StatefulSets and unowned
// Pods, in a fixed order; status-only changes leave the digest unchanged.
// The hub attributes the delivery to the authenticated cluster.
func TestCapacityDeliveryFromCacheRoundTrip(t *testing.T) {
	keys := []string{"asservat-trial"}
	namespaces := []*metav1.PartialObjectMetadata{capacityObject("", "payments", "ns-1", map[string]string{"asservat-trial": "true", "team": "secret"}, false), capacityObject("", "other", "ns-2", map[string]string{"team": "x"}, false)}
	pods := []*metav1.PartialObjectMetadata{capacityObject("payments", "bare", "p-2", nil, false), capacityObject("payments", "api-1", "p-1", nil, true), capacityObject("other", "x", "p-3", nil, false)}
	deployments := []*metav1.PartialObjectMetadata{capacityObject("payments", "api", "w-1", nil, false)}
	d, err := CapacityDeliveryFromCache(keys, namespaces, deployments, nil, pods)
	if err != nil || len(d.Namespaces) != 1 {
		t.Fatal(err, d)
	}
	n := d.Namespaces[0]
	if n.Name != "payments" || n.UID != "ns-1" || len(n.Labels) != 1 || len(n.Workloads) != 2 || n.Workloads[0].Kind != "Deployment" || n.Workloads[1].Name != "bare" || n.Workloads[1].ResourceVersion != "g2" {
		t.Fatalf("namespace %+v", n)
	}
	// A status-only update (new resource version, same generation) sends nothing.
	pods[0].ResourceVersion = "rv-later"
	again, err := CapacityDeliveryFromCache(keys, namespaces, deployments, nil, []*metav1.PartialObjectMetadata{pods[2], pods[1], pods[0]})
	if err != nil || again.Digest() != d.Digest() {
		t.Fatal("status-only change or cache order changed the digest", err)
	}
	raw, _ := json.Marshal(d)
	var wire contracts.CapacityDelivery
	if err = json.Unmarshal(raw, &wire); err != nil || wire.Digest() != d.Digest() {
		t.Fatal("wire digest", err)
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
	if _, err = CapacityDeliveryFromCache(nil, namespaces, nil, nil, nil); err == nil {
		t.Fatal("delivery without keys")
	}
}
