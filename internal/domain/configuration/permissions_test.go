package configuration

import (
	"strings"
	"testing"
	"time"
)

func TestBindingScopeExpiryAndDeletingDenies(t *testing.T) {
	n := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ns := NamespaceRef{"payments", "namespace-uid"}
	target := Target{ClusterID: "cluster", Namespace: ns, Workload: WorkloadRef{"Deployment", "api", "workload-uid"}}
	b := Binding{Resource: Resource{UID: "binding"}, Effect: "Allow", Subjects: []Subject{{"Group", "https://id.example.invalid", "team"}}, Roles: []string{"workload-maintainer", "evidence-owner"}, Scope: Scope{ClusterID: target.ClusterID, Namespace: ns, Workloads: []WorkloadRef{target.Workload}}}
	if p := ProposeBinding(b, target, n); len(p.Candidates) != 2 || p.Reason != "RequiresAcceptance" {
		t.Fatal("roles not expanded")
	}
	changed := target
	changed.Workload.UID = "new"
	if len(ProposeBinding(b, changed, n).Candidates) != 0 {
		t.Fatal("workload UID ignored")
	}
	b.Scope.Workloads = nil
	if len(ProposeBinding(b, changed, n).Candidates) != 2 {
		t.Fatal("namespace-wide binding failed for future workload")
	}
	b.Resource.Deleting = true
	if len(ProposeBinding(b, target, n).Candidates) != 0 {
		t.Fatal("terminating allow remained active")
	}
	b.Effect = "Deny"
	if len(ProposeBinding(b, target, n).Candidates) != 2 {
		t.Fatal("terminating deny disappeared before actual deletion")
	}
	b.NotAfter = n
	if len(ProposeBinding(b, target, n).Candidates) != 0 {
		t.Fatal("expired binding proposed")
	}
}

func TestNamespaceObservationIsMinimizedAndBounded(t *testing.T) {
	digest := strings.Repeat("a", 64)
	o := NamespaceObservation{ClusterID: "11111111-1111-4111-8111-111111111111", Keys: NamespaceKeys{Labels: []string{"managed"}, Annotations: []string{"owner"}},
		Namespaces: []ObservedNamespace{{Name: "a", UID: "uid-a", Labels: map[string]string{"managed": digest}}, {Name: "b", UID: "uid-b", Annotations: map[string]string{"owner": ""}}}}
	if !o.Valid() {
		t.Fatal("valid observation rejected")
	}
	for name, mutate := range map[string]func(*NamespaceObservation){
		"raw value":        func(o *NamespaceObservation) { o.Namespaces[0].Labels["managed"] = "payments" },
		"unobserved key":   func(o *NamespaceObservation) { o.Namespaces[0].Labels["other"] = digest },
		"resource version": func(o *NamespaceObservation) { o.Namespaces[0].ResourceVersion = "1" },
		"no observed key":  func(o *NamespaceObservation) { o.Namespaces[0].Labels = nil },
		"unsorted":         func(o *NamespaceObservation) { o.Namespaces[0], o.Namespaces[1] = o.Namespaces[1], o.Namespaces[0] },
		"duplicate name":   func(o *NamespaceObservation) { o.Namespaces[1].Name = "a" },
		"unsorted keys":    func(o *NamespaceObservation) { o.Keys.Labels = []string{"z", "managed"} },
		"no keys":          func(o *NamespaceObservation) { o.Keys = NamespaceKeys{} },
		"cluster":          func(o *NamespaceObservation) { o.ClusterID = "cluster" },
	} {
		t.Run(name, func(t *testing.T) {
			c := o
			c.Namespaces = []ObservedNamespace{{Name: "a", UID: "uid-a", Labels: map[string]string{"managed": digest}}, {Name: "b", UID: "uid-b", Annotations: map[string]string{"owner": ""}}}
			mutate(&c)
			if c.Valid() {
				t.Fatal("invalid observation accepted")
			}
		})
	}
}
