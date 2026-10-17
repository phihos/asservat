package integration

import (
	"errors"
	"fmt"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestInitialPreparationCleanupStatus(t *testing.T) {
	policy := "initial-resume-continuity"
	cause := "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request: Asservat preparation identities must remain occupied and may only lose setup authority."
	// Mirrors the actual apiserver VAP dispatcher: NewForbidden's text survives
	// while the default reason/code become Invalid/422 and a cause is appended.
	native := apierrors.NewForbidden(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "clusterroles"}, "owned", errors.New(cause))
	native.ErrStatus.Reason = meta.StatusReasonInvalid
	native.ErrStatus.Code = 422
	native.ErrStatus.Details.Causes = []meta.StatusCause{{Message: cause}}
	if apierrors.IsForbidden(native) {
		t.Fatal("test did not reproduce VAP status override")
	}
	if !initialPreparerCleanupDenial(native, policy) || !initialPreparerCleanupDenial(fmt.Errorf("wrapped: %w", native), policy) {
		t.Fatal("native exact removed-policy denial is not retryable")
	}
	for _, mode := range []string{"other-policy", "other-binding", "text-only", "server-error", "unrelated-invalid"} {
		t.Run(mode, func(t *testing.T) {
			copy := &apierrors.StatusError{ErrStatus: *native.ErrStatus.DeepCopy()}
			switch mode {
			case "other-policy":
				if initialPreparerCleanupDenial(copy, "different") {
					t.Fatal("another policy accepted")
				}
				return
			case "other-binding":
				copy.ErrStatus.Details.Causes[0].Message = "ValidatingAdmissionPolicy '" + policy + "' with binding 'different' denied request: Asservat preparation identities must remain occupied and may only lose setup authority."
			case "text-only":
				copy.ErrStatus.Details.Causes = nil
			case "server-error":
				copy.ErrStatus.Code = 500
				copy.ErrStatus.Reason = meta.StatusReasonInternalError
			case "unrelated-invalid":
				copy.ErrStatus.Details.Causes[0].Message = "invalid deletion request"
			}
			if initialPreparerCleanupDenial(copy, policy) {
				t.Fatal("unqualified cleanup error became retryable")
			}
		})
	}
}
