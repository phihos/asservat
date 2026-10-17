package kubernetes

import (
	"encoding/json"
	"strings"

	value "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// RetentionAdmission keeps policy authors separate from source administrators,
// workload maintainers and status writers. Runtime protection qualification must
// pin this exact installed policy/binding and control namespace incarnation.
func RetentionAdmission(p value.RetentionAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Label(p.ControlNamespace.Name)) != 0 {
		return nil, nil, value.ErrInvalid
	}
	literal := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	actors := func(v []value.KubernetesActor) string {
		var parts []string
		for _, a := range v {
			if a.Kind == "User" {
				parts = append(parts, "request.userInfo.username == "+literal(a.Name))
			} else {
				parts = append(parts, literal(a.Name)+" in request.userInfo.groups")
			}
		}
		return "(" + strings.Join(parts, " || ") + ")"
	}
	var grants []string
	for _, d := range p.Delegations {
		if !selectorValid(d.Scope.NamespaceLabels) || !selectorValid(d.Scope.WorkloadLabels) {
			return nil, nil, value.ErrInvalid
		}
		terms := []string{actors(d.Writers)}
		for _, object := range []string{"object", "oldObject"} {
			var scope []string
			if len(d.Scope.ClusterIDs) > 0 {
				scope = append(scope, "has("+object+".spec.scope.clusterIDs) && "+object+".spec.scope.clusterIDs.all(c, c in "+literal(d.Scope.ClusterIDs)+")")
			}
			for i, labels := range []map[string]string{d.Scope.NamespaceLabels, d.Scope.WorkloadLabels} {
				field := "namespaceSelector"
				if i == 1 {
					field = "workloadSelector"
				}
				if len(labels) > 0 {
					scope = append(scope, "has("+object+".spec.scope."+field+") && "+literal(labels)+".all(k, k in "+object+".spec.scope."+field+".matchLabels && "+object+".spec.scope."+field+".matchLabels[k] == "+literal(labels)+"[k])")
				}
			}
			terms = append(terms, "("+object+" == null || ("+strings.Join(scope, " && ")+"))")
		}
		grants = append(grants, "("+strings.Join(terms, " && ")+")")
	}
	allowed := actors(p.Administrators)
	if len(grants) > 0 {
		allowed += " || " + strings.Join(grants, " || ")
	}
	fail, equivalent := admission.Fail, admission.Equivalent
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete}, Rule: admission.Rule{APIGroups: []string{"asservat.io"}, APIVersions: []string{"*"}, Resources: []string{"evidenceretentionpolicies", "evidenceretentionpolicies/status"}}}}}}, MatchConditions: []admission.MatchCondition{{Name: "protected-control-namespace", Expression: "request.namespace == " + literal(p.ControlNamespace.Name)}}, Validations: []admission.Validation{{Expression: "(has(request.subResource) && request.subResource == 'status') ? request.userInfo.username in " + literal(p.StatusUsers) + " : (" + allowed + ")", Message: "Asservat retention administrator or matching retention delegation is required."}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}
