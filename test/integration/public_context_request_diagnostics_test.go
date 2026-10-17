package integration

import (
	"context"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
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

// These decorators inspect only the original returned error's closed code.
// In particular an uncertain capture write is never replayed for diagnosis.
type publicJourneyCaptureDiagnostics struct {
	auditapp.CaptureOperationIntentReader
	auditapp.CaptureOperationJournal
	auditapp.CaptureOperationAcknowledgements
	auditapp.ClosedOperationObjects
	auditapp.CaptureOperationReader
	trace *publicJourneyDiagnostics
}

func (s *publicJourneyDiagnostics) Publication(in auditapp.CaptureOperationPublication) auditapp.CaptureOperationPublication {
	p := publicJourneyCaptureDiagnostics{in.Completed, in.Journal, in.Acknowledgements, in.Writer, in.Reader, s}
	if in.Completed != nil {
		in.Completed = p
	}
	if in.Journal != nil {
		in.Journal = p
	}
	if in.Acknowledgements != nil {
		in.Acknowledgements = p
	}
	if in.Writer != nil {
		in.Writer = p
	}
	if in.Reader != nil {
		in.Reader = p
	}
	return in
}
func (s publicJourneyCaptureDiagnostics) ReadCaptureOperationIntent(c context.Context, id string) (auditapp.CaptureOperationIntentSnapshot, error) {
	v, e := s.CaptureOperationIntentReader.ReadCaptureOperationIntent(c, id)
	s.trace.record(journeyCaptureCompleted, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyCaptureDiagnostics) ReadCaptureOperation(c context.Context, id string) (auditvalue.OperationSnapshot, error) {
	v, e := s.CaptureOperationJournal.ReadCaptureOperation(c, id)
	s.trace.record(journeyCaptureJournal, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyCaptureDiagnostics) ClaimCaptureWrite(c context.Context, in auditvalue.OperationIntent, phase string) (auditvalue.CaptureWriteClaim, error) {
	v, e := s.CaptureOperationJournal.ClaimCaptureWrite(c, in, phase)
	s.recordPhase(phase, journeyCaptureClaimIntent, journeyCaptureClaimOutcome, e)
	return v, e
}
func (s publicJourneyCaptureDiagnostics) FreezeOperationOutcome(c context.Context, in auditvalue.OperationOutcome) (auditvalue.OperationSnapshot, error) {
	v, e := s.CaptureOperationJournal.FreezeOperationOutcome(c, in)
	s.trace.record(journeyCaptureFreeze, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyCaptureDiagnostics) CreateClosedOperationIntent(c context.Context, in auditvalue.OperationIntent) (auditvalue.OperationWriteCompletion, error) {
	v, e := s.ClosedOperationObjects.CreateClosedOperationIntent(c, in)
	s.trace.record(journeyCaptureWriteIntent, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyCaptureDiagnostics) CreateClosedOperationOutcome(c context.Context, in auditvalue.OperationOutcome) (auditvalue.OperationWriteCompletion, error) {
	v, e := s.ClosedOperationObjects.CreateClosedOperationOutcome(c, in)
	s.trace.record(journeyCaptureWriteOutcome, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyCaptureDiagnostics) RecordOperationCompletion(c context.Context, in auditvalue.OperationIntent, phase string, v auditvalue.OperationWriteCompletion) error {
	e := s.CaptureOperationAcknowledgements.RecordOperationCompletion(c, in, phase, v)
	s.recordPhase(phase, journeyCaptureCompleteIntent, journeyCaptureCompleteOutcome, e)
	return e
}
func (s publicJourneyCaptureDiagnostics) AcknowledgeOperation(c context.Context, in auditvalue.OperationIntent, phase string, r auditvalue.Receipt) error {
	e := s.CaptureOperationAcknowledgements.AcknowledgeOperation(c, in, phase, r)
	s.recordPhase(phase, journeyCaptureAckIntent, journeyCaptureAckOutcome, e)
	return e
}
func (s publicJourneyCaptureDiagnostics) AcknowledgeCapturePair(c context.Context, in auditvalue.OperationIntent) error {
	e := s.CaptureOperationAcknowledgements.AcknowledgeCapturePair(c, in)
	s.trace.record(journeyCaptureAckPair, journeyDiagnosticError(e))
	return e
}
func (s publicJourneyCaptureDiagnostics) ClaimCaptureReconciliation(c context.Context, in auditvalue.OperationIntent, phase string) (auditvalue.CaptureReconciliationClaim, error) {
	v, e := s.CaptureOperationJournal.ClaimCaptureReconciliation(c, in, phase)
	s.recordPhase(phase, journeyCaptureReconcileClaimIntent, journeyCaptureReconcileClaimOutcome, e)
	return v, e
}
func (s publicJourneyCaptureDiagnostics) FindOperationIntent(c context.Context, in auditvalue.OperationIntent) (auditvalue.Receipt, error) {
	v, e := s.CaptureOperationReader.FindOperationIntent(c, in)
	s.trace.record(journeyCaptureFindIntent, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyCaptureDiagnostics) FindOperationOutcome(c context.Context, in auditvalue.OperationOutcome) (auditvalue.Receipt, error) {
	v, e := s.CaptureOperationReader.FindOperationOutcome(c, in)
	s.trace.record(journeyCaptureFindOutcome, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyCaptureDiagnostics) AcknowledgeReconciledCapture(c context.Context, in auditvalue.OperationIntent, phase string, r auditvalue.Receipt, claim auditvalue.CaptureReconciliationClaim) error {
	e := s.CaptureOperationAcknowledgements.AcknowledgeReconciledCapture(c, in, phase, r, claim)
	s.recordPhase(phase, journeyCaptureReconcileAckIntent, journeyCaptureReconcileAckOutcome, e)
	return e
}
func (s publicJourneyCaptureDiagnostics) recordPhase(phase string, intent, outcome int, e error) {
	if phase == "intent" {
		s.trace.record(intent, journeyDiagnosticError(e))
	} else if phase == "outcome" {
		s.trace.record(outcome, journeyDiagnosticError(e))
	}
}

type publicJourneyRegionalDiagnostics struct {
	executionapp.APIExecutionReader
	fleetapp.APIContextWorkSigner
	trace *publicJourneyDiagnostics
}

func (s *publicJourneyDiagnostics) Regional(in bootstrap.RegionalAPIContextStart) bootstrap.RegionalAPIContextStart {
	p := publicJourneyRegionalDiagnostics{in.Runner.Read, in.Signer, s}
	if in.Runner.Read != nil {
		in.Runner.Read = p
	}
	if in.Signer != nil {
		in.Signer = p
	}
	return in
}
func (s publicJourneyRegionalDiagnostics) ReadAPIContextWork(c context.Context, id string, actor identity.Identity, recovery artifact.RecoveryProof) (executionapp.APIContextWork, error) {
	v, e := s.APIExecutionReader.ReadAPIContextWork(c, id, actor, recovery)
	s.trace.record(journeyRegionalRead, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyRegionalDiagnostics) SignAPIContextWork(c context.Context, in fleetvalue.APIContextWork) ([]byte, error) {
	v, e := s.APIContextWorkSigner.SignAPIContextWork(c, in)
	s.trace.record(journeyRegionalSign, journeyDiagnosticError(e))
	return v, e
}

type journeyDiagnosticCaptureRead struct {
	read func(context.Context, string) (auditapp.CaptureOperationIntentSnapshot, error)
}

func (s journeyDiagnosticCaptureRead) ReadCaptureOperationIntent(c context.Context, id string) (auditapp.CaptureOperationIntentSnapshot, error) {
	return s.read(c, id)
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
			publication := trace.Publication(auditapp.CaptureOperationPublication{RootID: "00000000-0000-4000-8000-000000000002", Now: time.Now, Completed: journeyDiagnosticCaptureRead{func(c context.Context, got string) (auditapp.CaptureOperationIntentSnapshot, error) {
				calls++
				if got != id || c.Err() != nil {
					t.Fatal("publication changed original ID/context")
				}
				return auditapp.CaptureOperationIntentSnapshot{}, private
			}}})
			if publication.Journal != nil || publication.Writer != nil || publication.Reader != nil || publication.Acknowledgements != nil {
				t.Fatal("decorator invented missing publication ports")
			}
			_, e := publication.AcknowledgedCaptureIntent(ctx, id)
			if e != auditapp.ErrUnavailable {
				t.Fatal("publication normalization changed")
			}
			if canceled {
				if calls != 0 || trace.first != 0 {
					t.Fatal("canceled publication dispatched")
				}
			} else if calls != 1 || trace.first != journeyCaptureCompleted+1 || trace.calls[journeyCaptureCompleted] != 1 || trace.reasons[journeyCaptureCompleted] != 9 {
				t.Fatal("original publication refusal lost or replayed")
			}
			trace.Report(t) // Neither private Error nor Unwrap may be invoked.
			before := trace.calls
			trace.record(journeyCaptureJournal, 9)
			if trace.BeginRequest() || trace.calls != before {
				t.Fatal("completed first request reopened or observed a later call")
			}
		})
	}
}
