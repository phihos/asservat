package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type guardPolicyReader struct {
	policy admission.ValidatingAdmissionPolicy
}

func (r guardPolicyReader) raw(context.Context, string, map[string]string) ([]byte, error) {
	return json.Marshal(r.policy)
}

// An HA API server type-checks a new policy asynchronously. A status that has
// not yet caught up with the policy's own generation is pending (retryable),
// not a change; warnings and identity mismatches still are changes.
func TestAdmissionGuardPendingStatusIsNotAChange(t *testing.T) {
	policy := admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"},
		ObjectMeta: meta.ObjectMeta{Name: "guard", UID: "policy-uid", Generation: 1}}
	pin := GuardPin{PolicyUID: "policy-uid", PolicyGeneration: 1}
	check := func(p admission.ValidatingAdmissionPolicy) error {
		_, err := checkAdmissionGuard(context.Background(), guardPolicyReader{p}, "guard", pin, admission.ValidatingAdmissionPolicySpec{}, admission.ValidatingAdmissionPolicyBindingSpec{})
		return err
	}
	pending := policy
	if err := check(pending); errors.Is(err, value.ErrChanged) || !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("unobserved status", err)
	}
	pending.Status = admission.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1}
	if err := check(pending); errors.Is(err, value.ErrChanged) || !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("observed without type checking", err)
	}
	warned := policy
	warned.Status = admission.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admission.TypeChecking{ExpressionWarnings: []admission.ExpressionWarning{{FieldRef: "spec.validations[0]", Warning: "w"}}}}
	if err := check(warned); !errors.Is(err, value.ErrChanged) {
		t.Fatal("expression warning accepted", err)
	}
	other := policy
	other.UID = "replacement"
	other.Status = admission.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admission.TypeChecking{}}
	if err := check(other); !errors.Is(err, value.ErrChanged) {
		t.Fatal("replaced policy accepted", err)
	}
}
