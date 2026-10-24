package presentation

import (
	"errors"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

func TestContextProcessingCoverageFailurePreservesUnknownEarlierRequest(t *testing.T) {
	for _, request := range []bool{false, true} {
		failure := publicCaptureFailure(value.ErrProcessingCoverage, request)
		if failure.Code != "ProcessingCoverageUnavailable" || failure.Retryable {
			t.Fatal("known short coverage became transient retry", failure)
		}
		if !strings.Contains(failure.Message, "selected duration") || strings.Contains(failure.Message, "nothing happened") {
			t.Fatal("insufficient coverage explanation", failure)
		}
		if request && (!strings.Contains(failure.Message, "earlier") || !strings.Contains(failure.Message, "original request's status")) {
			t.Fatal("earlier same-key uncertainty erased", failure)
		}
	}
	unavailable := publicCaptureFailure(errors.New("private database failure"), true)
	if unavailable.Code != "OutcomeUnknown" || !unavailable.Retryable || strings.Contains(unavailable.Message, "private") {
		t.Fatal("transient read failure misclassified", unavailable)
	}
}

func TestPreviewChangeIsRetryableButRequestChangeIsReviewChanged(t *testing.T) {
	if f := publicCaptureFailure(value.ErrChanged, false); f.Code != "NotAvailable" || !f.Retryable {
		t.Fatalf("preview: %+v", f)
	}
	if f := publicCaptureFailure(value.ErrChanged, true); f.Code != "ReviewChanged" || f.Retryable {
		t.Fatalf("request: %+v", f)
	}
}

// A target read resolves the workload before authorizing it: a denied existing
// target must project exactly like an absent or unreachable one.
func TestTargetReadDenialIsNotAnExistenceOracle(t *testing.T) {
	absent := publicCaptureFailure(targets.ErrChanged, false)
	for _, err := range []error{value.ErrDenied, identity.ErrDenied, targets.ErrDenied, targets.ErrUnavailable, value.ErrChanged} {
		if f := publicCaptureFailure(err, false); f != absent {
			t.Fatalf("%v: %+v differs from absent target %+v", err, f, absent)
		}
	}
}
