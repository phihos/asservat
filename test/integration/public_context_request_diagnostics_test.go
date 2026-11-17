package integration

import (
	"context"
	"testing"

	captureapp "asservat.local/asservat/internal/application/capture"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/bootstrap"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

func (s publicJourneyPreviewDiagnostics) LookupContextAdmission(c context.Context, in capturevalue.ReplayQuery) (capturevalue.Accepted, bool, error) {
	v, found, e := s.ContextAdmissionReplay.LookupContextAdmission(c, in)
	s.trace.record(journeyRequestLookup, journeyDiagnosticError(e))
	return v, found, e
}
func (s publicJourneyPreviewDiagnostics) ReadContextPreview(c context.Context, root, id string, actor identity.Principal) (capturevalue.ContextPreview, error) {
	v, e := s.ContextPreviewStore.ReadContextPreview(c, root, id, actor)
	s.trace.record(journeyRequestPreview, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) AdmitReviewedContext(c context.Context, id string, in capturevalue.Admission) (capturevalue.Accepted, error) {
	v, e := s.ReviewedAdmissionTransaction.AdmitReviewedContext(c, id, in)
	s.trace.record(journeyRequestAdmit, journeyDiagnosticError(e))
	return v, e
}

// The decorator inspects only the original returned error's closed code.
type publicJourneyCaptureDiagnostics struct {
	captureapp.ContextAcceptedIntents
	trace *publicJourneyDiagnostics
}

func (s *publicJourneyDiagnostics) Publication(in captureapp.ContextAcceptedIntents) captureapp.ContextAcceptedIntents {
	if in == nil {
		return nil
	}
	return publicJourneyCaptureDiagnostics{in, s}
}
func (s publicJourneyCaptureDiagnostics) AcceptedCaptureIntent(c context.Context, id string) (auditvalue.CaptureIntent, error) {
	v, e := s.ContextAcceptedIntents.AcceptedCaptureIntent(c, id)
	s.trace.record(journeyCaptureIntent, journeyDiagnosticError(e))
	return v, e
}

type publicJourneyRegionalDiagnostics struct {
	executionapp.APIExecutionReader
	trace *publicJourneyDiagnostics
}

func (s *publicJourneyDiagnostics) Regional(in bootstrap.RegionalAPIContextStart) bootstrap.RegionalAPIContextStart {
	p := publicJourneyRegionalDiagnostics{in.Runner.Read, s}
	if in.Runner.Read != nil {
		in.Runner.Read = p
	}
	return in
}
func (s publicJourneyRegionalDiagnostics) ReadAPIContextWork(c context.Context, id string, actor identity.Identity) (executionapp.APIContextWork, error) {
	v, e := s.APIExecutionReader.ReadAPIContextWork(c, id, actor)
	s.trace.record(journeyRegionalRead, journeyDiagnosticError(e))
	return v, e
}

type journeyDiagnosticCaptureRead func(context.Context, string) (auditvalue.CaptureIntent, error)

func (f journeyDiagnosticCaptureRead) AcceptedCaptureIntent(c context.Context, id string) (auditvalue.CaptureIntent, error) {
	return f(c, id)
}

// Drive the actual publication entry point, preserving its normalization and
// cancellation rather than testing a second copy of the production dispatch.
func TestPublicJourneyDiagnosticsFirstRequestPublication(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "private-read-failure", true: "canceled-before-dispatch"}[canceled], func(t *testing.T) {
			trace := &publicJourneyDiagnostics{}
			if trace.BeginRequest() {
				t.Fatal("request trace opened before preview returned")
			}
			trace.record(0, 0)
			trace.freeze("success")
			trace.Report(t)
			if !trace.BeginRequest() || trace.first != 0 || trace.outcome != 0 || trace.calls[0] != 0 {
				t.Fatal("request inherited preview diagnostics")
			}
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			if canceled {
				stop()
			}
			private := &journeyDiagnosticPrivateError{}
			id := "00000000-0000-4000-8000-000000000001"
			calls := 0
			publication := trace.Publication(journeyDiagnosticCaptureRead(func(c context.Context, got string) (auditvalue.CaptureIntent, error) {
				if c.Err() != nil {
					return auditvalue.CaptureIntent{}, c.Err()
				}
				calls++
				if got != id {
					t.Fatal("decorator changed original ID")
				}
				return auditvalue.CaptureIntent{}, private
			}))
			if ctx.Err() == nil {
				publication.AcceptedCaptureIntent(ctx, id)
			}
			if canceled {
				if calls != 0 || trace.first != 0 {
					t.Fatal("canceled publication dispatched")
				}
			} else if calls != 1 || trace.first != journeyCaptureIntent+1 || trace.calls[journeyCaptureIntent] != 1 || trace.reasons[journeyCaptureIntent] != 9 {
				t.Fatal("original publication refusal lost or replayed")
			}
			trace.Report(t) // Neither private Error nor Unwrap may be invoked.
			before := trace.calls
			trace.record(journeyCaptureIntent, 9)
			if trace.BeginRequest() || trace.calls != before {
				t.Fatal("completed first request reopened or observed a later call")
			}
		})
	}
}
