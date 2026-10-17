package configuration

import (
	"testing"
	"time"
)

func permissionValues() (Source, NamespaceMetadata, Target, time.Time) {
	n := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ns := NamespaceMetadata{ClusterID: "cluster", Namespace: NamespaceRef{"payments", "namespace-uid"}, ResourceVersion: "rv", ObservedAt: n, FreshUntil: n.Add(30 * time.Second), Labels: map[string]string{"managed": "true"}, Annotations: map[string]string{"owner": "payments"}}
	s := Source{Resource: Resource{UID: "source-uid"}, Enabled: true, Type: "namespaceMetadata", ClusterID: "cluster", Role: "evidence-owner", NamespaceSelector: map[string]string{"managed": "true"}, MaxDecisionAge: 30 * time.Second, MaxNamespaces: 100, Protection: Protection{Mode: "administratorManaged", ReviewRef: "review"}, Mapping: Mapping{Field: "annotation", Key: "owner", Mode: "valueMap", Issuer: "https://id.example.invalid", Values: map[string][]string{"payments": {"team-a", "team-b"}}}}
	target := Target{ClusterID: ns.ClusterID, Namespace: ns.Namespace, Workload: WorkloadRef{"Deployment", "api", "workload-uid"}}
	return s, ns, target, n
}

func TestNamespaceMappingCannotManufactureTrust(t *testing.T) {
	s, ns, target, n := permissionValues()
	if p := ProposeNamespace(s, ns, target, n); p.Reason != "RequiresProtectionQualification" || len(p.Candidates) != 2 {
		t.Fatal("trusted review was assumed or owner teams lost")
	}
	for name, mutate := range map[string]func(*Source, *NamespaceMetadata, *Target){
		"unknown value":      func(s *Source, ns *NamespaceMetadata, t *Target) { ns.Annotations["owner"] = "other" },
		"comma list":         func(s *Source, ns *NamespaceMetadata, t *Target) { ns.Annotations["owner"] = "team-a,team-b" },
		"case changed":       func(s *Source, ns *NamespaceMetadata, t *Target) { ns.Annotations["owner"] = "Payments" },
		"missing annotation": func(s *Source, ns *NamespaceMetadata, t *Target) { delete(ns.Annotations, "owner") },
		"label spoof": func(s *Source, ns *NamespaceMetadata, t *Target) {
			delete(ns.Annotations, "owner")
			ns.Labels["owner"] = "payments"
		},
		"missing selector":      func(s *Source, ns *NamespaceMetadata, t *Target) { delete(ns.Labels, "managed") },
		"excluded namespace":    func(s *Source, ns *NamespaceMetadata, t *Target) { s.ExcludedNamespaces = []string{"payments"} },
		"other cluster":         func(s *Source, ns *NamespaceMetadata, t *Target) { ns.ClusterID = "other" },
		"same name replacement": func(s *Source, ns *NamespaceMetadata, t *Target) { ns.Namespace.UID = "new" },
		"deleting namespace":    func(s *Source, ns *NamespaceMetadata, t *Target) { ns.Deleting = true },
		"disabled":              func(s *Source, ns *NamespaceMetadata, t *Target) { s.Enabled = false },
		"deleting source":       func(s *Source, ns *NamespaceMetadata, t *Target) { s.Resource.Deleting = true },
		"short original deadline": func(s *Source, ns *NamespaceMetadata, t *Target) {
			s.MaxDecisionAge = time.Second
			ns.ObservedAt = ns.ObservedAt.Add(-2 * time.Second)
		},
		"expired observation":            func(s *Source, ns *NamespaceMetadata, t *Target) { ns.FreshUntil = ns.ObservedAt },
		"future observation":             func(s *Source, ns *NamespaceMetadata, t *Target) { ns.ObservedAt = ns.ObservedAt.Add(time.Second) },
		"directory not qualified":        func(s *Source, ns *NamespaceMetadata, t *Target) { s.Mapping.Mode = "groupID" },
		"exec not qualified":             func(s *Source, ns *NamespaceMetadata, t *Target) { s.Type = "kubernetesExec" },
		"controller chain not qualified": func(s *Source, ns *NamespaceMetadata, t *Target) { s.Type = "workloadMetadata" },
	} {
		t.Run(name, func(t *testing.T) {
			s, ns, target, n := permissionValues()
			mutate(&s, &ns, &target)
			if p := ProposeNamespace(s, ns, target, n); len(p.Candidates) != 0 {
				t.Fatal("invalid source produced candidates")
			}
		})
	}
}

func TestBindingScopeExpiryAndDeletingDenies(t *testing.T) {
	_, ns, target, n := permissionValues()
	b := Binding{Resource: Resource{UID: "binding"}, Effect: "Allow", Subjects: []Subject{{"Group", "https://id.example.invalid", "team"}}, Roles: []string{"workload-maintainer", "evidence-owner"}, Scope: Scope{ClusterID: target.ClusterID, Namespace: ns.Namespace, Workloads: []WorkloadRef{target.Workload}}}
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
