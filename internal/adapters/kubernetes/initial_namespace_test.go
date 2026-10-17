package kubernetes

import (
	"strings"
	"testing"

	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
)

func TestInitialNamespacePlanCannotBroadenItsStagingScope(t *testing.T) {
	p := cfg.InitialNamespaceAdministration{Name: "install-stage", Namespace: "asservat-install", ProbeSource: "preparation", Inputs: "inputs", Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "operator"}}}
	policy, binding, err := InitialNamespaceAdmission(p)
	if err != nil {
		t.Fatal(err)
	}
	if *policy.Spec.FailurePolicy != admission.Fail || len(binding.Spec.ValidationActions) != 1 || binding.Spec.ValidationActions[0] != admission.Deny || *policy.Spec.MatchConstraints.ResourceRules[0].Scope != admission.NamespacedScope {
		t.Fatal("staging policy does not enforce namespaced mutations")
	}
	for _, change := range []func(*cfg.InitialNamespaceAdministration){
		func(p *cfg.InitialNamespaceAdministration) { p.Namespace = "default" },
		func(p *cfg.InitialNamespaceAdministration) { p.Namespace = "kube-system" },
		func(p *cfg.InitialNamespaceAdministration) { p.Namespace = "../other" },
		func(p *cfg.InitialNamespaceAdministration) { p.Inputs = p.ProbeSource },
		func(p *cfg.InitialNamespaceAdministration) { p.Administrators = nil },
		func(p *cfg.InitialNamespaceAdministration) {
			p.Administrators = append(p.Administrators, p.Administrators[0])
		},
		func(p *cfg.InitialNamespaceAdministration) { p.Inputs = strings.Repeat("a", 254) },
	} {
		bad := p
		change(&bad)
		if _, _, err := InitialNamespaceAdmission(bad); err == nil {
			t.Fatal("invalid staging scope accepted")
		}
	}
}
