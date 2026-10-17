package kubernetes

import (
	"encoding/json"
	"strings"

	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const capacitySourceDenial = "Asservat capacity administrator is required."
const capacityNamespaceDenial = "Asservat capacity selector administrator is required."

func capacityLiteral(v any) string { b, _ := json.Marshal(v); return string(b) }
func capacityActors(v []cfg.KubernetesActor) string {
	parts := make([]string, 0, len(v))
	for _, a := range v {
		if a.Kind == "User" {
			parts = append(parts, "request.userInfo.username == "+capacityLiteral(a.Name))
		} else {
			parts = append(parts, capacityLiteral(a.Name)+" in request.userInfo.groups")
		}
	}
	return "(" + strings.Join(parts, " || ") + ")"
}

func CapacityAdmission(p cfg.CapacityAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Label(p.ControlNamespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(p.ProbeAccount.Name)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	statusUsers := append([]string{}, p.StatusUsers...)
	fail, equivalent := admission.Fail, admission.Equivalent
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{
		FailurePolicy:    &fail,
		MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete}, Rule: admission.Rule{APIGroups: []string{"asservat.io"}, APIVersions: []string{"*"}, Resources: []string{"evidencestoragepools", "evidencestoragepools/status", "evidencebudgetpolicies", "evidencebudgetpolicies/status"}}}}}},
		// Admission match conditions have no variables environment. Scope must
		// depend on the request, including DELETE's absent new object.
		MatchConditions: []admission.MatchCondition{{Name: "capacity-control-namespace", Expression: "request.namespace == " + capacityLiteral(p.ControlNamespace.Name)}},
		Validations:     []admission.Validation{{Expression: "(has(request.subResource) && request.subResource == 'status') ? request.userInfo.username in " + capacityLiteral(statusUsers) + " : " + capacityActors(p.Administrators), Message: capacitySourceDenial}},
	}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

func CapacityNamespaceAdmission(p cfg.CapacityNamespaceAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Label(p.ProbeNamespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(p.ProbeAccount.Name)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	for _, k := range p.Keys {
		if len(validation.IsQualifiedName(k)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
	}
	keys := capacityLiteral(p.Keys)
	// Unprivileged CREATE may omit these keys; UPDATE must preserve their
	// exact presence and values. Other namespace labels/status are unaffected.
	present := func(o string) string { return "(has(" + o + ".metadata.labels) && k in " + o + ".metadata.labels)" }
	unchanged := keys + ".all(k, " + present("object") + " == " + present("oldObject") + " && (!" + present("object") + " || object.metadata.labels[k] == oldObject.metadata.labels[k]))"
	expression := capacityActors(p.Administrators) + " || (request.operation == 'CREATE' ? " + keys + ".all(k, !" + present("object") + ") : " + unchanged + ")"
	fail, equivalent := admission.Fail, admission.Equivalent
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update}, Rule: admission.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"namespaces"}}}}}}, Validations: []admission.Validation{{Expression: expression, Message: capacityNamespaceDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}
