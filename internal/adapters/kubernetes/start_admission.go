package kubernetes

import (
	"encoding/json"

	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// StartAdmission complements structural/CEL transitions with role separation.
// The initial profile cannot delete records. Installing this builder is not a
// qualification of the capacity writer or protection of the installation policy.
func StartAdmission(p configuration.LocalStartAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if len(validation.IsDNS1123Subdomain(p.Name)) != 0 || !namespaceRefValid(p.ControlNamespace) || !identity.Text(p.CapacityUser, 256) || !identity.Text(p.ExecutionUser, 256) || p.CapacityUser == p.ExecutionUser {
		return nil, nil, value.ErrInvalid
	}
	literal := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	fail, equivalent := admission.Fail, admission.Equivalent
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: metav1.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{
		FailurePolicy: &fail, MatchConditions: []admission.MatchCondition{{Name: "local-start-control-namespace", Expression: "request.namespace == " + literal(p.ControlNamespace.Name)}}, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete}, Rule: admission.Rule{APIGroups: []string{"asservat.io"}, APIVersions: []string{"*"}, Resources: []string{"capacityreservations", "capacityreservations/status"}}}}}},
		Validations: []admission.Validation{
			{Expression: `request.namespace == ` + literal(p.ControlNamespace.Name), Message: "Local start records require the configured control namespace."},
			{Expression: `request.operation != 'DELETE'`, Message: "Start record deletion requires a separately qualified reconciliation path."},
			{Expression: `object == null || object.spec.profile != 'apiContextStart/v1' || !(request.operation == 'UPDATE' && has(request.subResource) && request.subResource == 'status' && has(object.status) && object.status.phase == 'StartCommitted') || (request.userInfo.uid == object.spec.executorAccountUID && has(request.userInfo.extra) && 'authentication.kubernetes.io/pod-uid' in request.userInfo.extra && size(request.userInfo.extra['authentication.kubernetes.io/pod-uid']) == 1 && request.userInfo.extra['authentication.kubernetes.io/pod-uid'][0] == object.spec.executorPodUID)`, Message: "API execution consumption requires the exact bound Pod and account."},
			{Expression: `object == null || ((!has(object.metadata.ownerReferences) || size(object.metadata.ownerReferences) == 0) && (!has(object.metadata.finalizers) || size(object.metadata.finalizers) == 0))`, Message: "Start records cannot be garbage collected through another object."},
			{Expression: `request.operation == 'CREATE' ? request.userInfo.username == ` + literal(p.CapacityUser) + ` : (request.operation == 'UPDATE' && has(request.subResource) && request.subResource == 'status' && object != null && oldObject != null && has(object.status) && ((!has(oldObject.status) && object.status.phase == 'Ready' && request.userInfo.username == ` + literal(p.CapacityUser) + `) || (has(oldObject.status) && oldObject.status.phase == 'Ready' && object.status.phase == 'StartCommitted' && request.userInfo.username == ` + literal(p.ExecutionUser) + `)))`, Message: "Capacity prepares Ready records; execution only consumes an existing Ready record."},
		},
	}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: metav1.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: metav1.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}
