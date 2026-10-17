package kubernetes

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	value "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// PermissionAdmission renders native API-server validation. Only protected
// installation administration can choose these literals. This builder neither
// installs resources nor treats their presence as runtime qualification.
func PermissionAdmission(p value.PermissionAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Label(p.ControlNamespace.Name)) != 0 {
		return nil, nil, value.ErrInvalid
	}
	literal := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	actors := func(v []value.KubernetesActor) string {
		rows := make([]map[string]string, 0, len(v))
		for _, a := range v {
			rows = append(rows, map[string]string{"kind": a.Kind, "name": a.Name})
		}
		return literal(rows) + `.exists(a, a.kind == 'User' ? a.name == request.userInfo.username : a.name in request.userInfo.groups)`
	}
	type delegation struct {
		Writers                          []map[string]string `json:"writers"`
		Cluster, Namespace, NamespaceUID string
		Roles, Issuers                   []string
		Workloads                        []map[string]string
	}
	delegates := make([]delegation, 0, len(p.Delegations))
	for _, d := range p.Delegations {
		v := delegation{Writers: make([]map[string]string, 0, len(d.Writers)), Cluster: d.Scope.ClusterID, Namespace: d.Scope.Namespace.Name, NamespaceUID: d.Scope.Namespace.UID, Roles: d.Roles, Issuers: d.Issuers, Workloads: make([]map[string]string, 0, len(d.Scope.Workloads))}
		for _, a := range d.Writers {
			v.Writers = append(v.Writers, map[string]string{"kind": a.Kind, "name": a.Name})
		}
		for _, w := range d.Scope.Workloads {
			v.Workloads = append(v.Workloads, map[string]string{"kind": w.Kind, "name": w.Name, "uid": w.UID})
		}
		delegates = append(delegates, v)
	}
	// CEL literals infer homogeneous map values. Explicit dyn on each value
	// permits the reviewed mixed list/string fields without weakening inputs.
	delegateLiterals := make([]string, 0, len(delegates))
	for _, d := range delegates {
		var fields map[string]json.RawMessage
		b, _ := json.Marshal(d)
		_ = json.Unmarshal(b, &fields)
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, literal(k)+":dyn("+string(fields[k])+")")
		}
		delegateLiterals = append(delegateLiterals, "{"+strings.Join(parts, ",")+"}")
	}
	// Check both sides of UPDATE and DELETE. A scoped writer cannot take over or
	// delete another scope by changing its target into a permitted one.
	scope := func(object string) string {
		return fmt.Sprintf(`(%[1]s == null || variables.delegations.exists(d,
 d.writers.exists(a, a.kind == 'User' ? a.name == request.userInfo.username : a.name in request.userInfo.groups) &&
 %[1]s.spec.scope.clusterID == d.Cluster && %[1]s.spec.scope.namespaceRef.name == d.Namespace && %[1]s.spec.scope.namespaceRef.uid == d.NamespaceUID &&
 %[1]s.spec.roles.all(r, r in d.Roles) && %[1]s.spec.subjects.all(s, s.issuer in d.Issuers) &&
 !has(%[1]s.spec.automation) &&
 (size(d.Workloads) == 0 || (has(%[1]s.spec.scope.workloads) && %[1]s.spec.scope.workloads.all(w, d.Workloads.exists(v, v.kind == w.kind && v.name == w.name && v.uid == w.uid))))))`, object)
	}
	fail := admission.Fail
	equivalent := admission.Equivalent
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: metav1.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{
		FailurePolicy: &fail, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete}, Rule: admission.Rule{APIGroups: []string{"asservat.io"}, APIVersions: []string{"*"}, Resources: []string{"accessbindings", "permissionsources", "accessbindings/status", "permissionsources/status"}}}}}},
		Variables: []admission.Variable{{Name: "administrator", Expression: actors(p.Administrators)}, {Name: "delegations", Expression: "[" + strings.Join(delegateLiterals, ",") + "]"}},
		Validations: []admission.Validation{
			{Expression: `request.namespace == ` + literal(p.ControlNamespace.Name), Message: "Asservat permission configuration requires the configured control namespace."},
			{Expression: `(has(request.subResource) && request.subResource == 'status') ? request.userInfo.username in ` + literal(p.StatusUsers) + ` : (variables.administrator || (request.resource.resource == 'accessbindings' && ` + scope("object") + ` && ` + scope("oldObject") + `))`, Message: "Asservat permission administrator or matching delegation is required."},
		},
	}}
	if len(delegates) == 0 {
		policy.Spec.Variables = policy.Spec.Variables[:1]
		policy.Spec.Validations[1].Expression = `(has(request.subResource) && request.subResource == 'status') ? request.userInfo.username in ` + literal(p.StatusUsers) + ` : variables.administrator`
	}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: metav1.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: metav1.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}
