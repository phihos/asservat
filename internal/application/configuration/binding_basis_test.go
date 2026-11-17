package configuration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

// ADR-335 D4: an omitted issuer is the installation's issuer; without one
// the subject grants nothing. A workload named without uid stays in the
// basis scope; evaluation matches it by kind and name.
func TestBindingBasisDefaultsIssuerAndKeepsNamedWorkloads(t *testing.T) {
	now := time.Now()
	b := value.Binding{Resource: value.Resource{Kind: "AccessBinding", UID: "b", ResourceVersion: "1", Generation: 1, SpecDigest: artifact.Digest{1}}, Effect: "Allow", Roles: []string{"evidence-reader"},
		Subjects: []value.Subject{{Kind: "Group", ID: "/payments"}, {Kind: "Group", Issuer: "https://other.example", ID: "/x"}},
		Scope:    value.Scope{ClusterID: inheritanceCluster, Namespace: value.NamespaceRef{Name: "payments", UID: "p"}}}
	p, ok := bindingBasis(b, now)
	if !ok {
		t.Fatal("binding dropped")
	}
	if got := withIssuer([]value.PermissionBasis{p}, "https://id.example"); len(got) != 1 || got[0].Subjects[0].Issuer != "https://id.example" || got[0].Subjects[1].Issuer != "https://other.example" {
		t.Fatalf("issuer not defaulted: %+v", got)
	}
	if got := withIssuer([]value.PermissionBasis{p}, ""); len(got) != 1 || len(got[0].Subjects) != 1 {
		t.Fatalf("subject without any issuer kept: %+v", got)
	}
	b.Scope.Workloads = []value.WorkloadRef{{Kind: "Deployment", Name: "api"}}
	for _, effect := range []string{"Allow", "Deny"} {
		b.Effect = effect
		if p, ok := bindingBasis(b, now); !ok || len(p.Scope.Workloads) != 1 || p.Scope.Workloads[0].Name != "api" {
			t.Fatalf("%s named workload not kept: %+v", effect, p)
		}
	}
}
