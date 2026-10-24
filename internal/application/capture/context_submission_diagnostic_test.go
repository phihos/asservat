package capture

import (
	"context"
	"errors"
	"slices"
	"testing"

	auditapp "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/capture"
)

type untrustedSubmissionDiagnostic struct{}

func (untrustedSubmissionDiagnostic) Error() string     { return "private-provider-detail" }
func (untrustedSubmissionDiagnostic) FixedStep() string { return "private-provider-detail" }

func TestContextSubmissionReportsClosedIntentFailureWithoutChangingAdmission(t *testing.T) {
	for _, mode := range []string{"dependency", "publication", "record"} {
		t.Run(mode, func(t *testing.T) {
			f, x, s, p := submissionTest(t)
			var reports []string
			s.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
			x.current = f.source(t, context.Background())
			want := "request/intent/unavailable"
			if mode == "dependency" {
				x.intentErr = untrustedSubmissionDiagnostic{}
			} else if mode == "publication" {
				_, x.intentErr = (auditapp.CaptureOperationPublication{}).AcknowledgedCaptureIntent(context.Background(), p.CaptureID)
				want = "request/intent/configuration"
			} else {
				x.changeIntent = true
				want = "request/intent/record"
			}
			accepted, err := s.Request(context.Background(), x.current, p.ID, "original")
			if !errors.Is(err, value.ErrUnavailable) || accepted.CaptureID != p.CaptureID ||
				!slices.Equal(reports, []string{want}) || x.starts != 0 || x.intentReads != 1 || f.admissions.Load() != 1 {
				t.Fatal("intent failure lost closed diagnostic or changed accepted work", err, reports, x.starts, x.intentReads, f.admissions.Load())
			}
		})
	}
}
