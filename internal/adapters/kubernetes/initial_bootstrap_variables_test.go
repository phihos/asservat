package kubernetes

import "testing"

// The actual API rejected namespace as a reserved CEL identifier. Matching is
// request-only now, so these unused declarations must not reach Kubernetes.
func TestInitialBootstrapAdmissionHasNoReservedCELVariable(t *testing.T) {
	p, _, err := InitialBootstrapAdmission(bootstrapAdmissionFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range p.Spec.Variables {
		if v.Name == "namespace" {
			t.Fatal("namespace is a reserved CEL identifier")
		}
	}
	if len(p.Spec.Variables) != 1 || p.Spec.Variables[0].Name != "sub" {
		t.Fatal("unexpected unused bootstrap variables")
	}
}
