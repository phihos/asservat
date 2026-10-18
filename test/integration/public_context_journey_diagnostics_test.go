package integration

import (
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// This fixed fixture-only inventory observes the original preview, then one
// separately delimited original first request. Only diagnostic counters reset. It
// stores no error, identity, input, timestamp, receipt or provider text, and
// performs no additional SQL/API/time read. Every decorator delegates once and
// returns the original values and error. Report runs only after the call ends.
const (
	journeyRequestLookup = 19 + iota
	journeyRequestPreview
	journeyRequestAdmit
	journeyCaptureCompleted
	journeyCaptureJournal
	journeyCaptureClaimIntent
	journeyCaptureWriteIntent
	journeyCaptureCompleteIntent
	journeyCaptureAckIntent
	journeyCaptureFreeze
	journeyCaptureClaimOutcome
	journeyCaptureWriteOutcome
	journeyCaptureCompleteOutcome
	journeyCaptureAckOutcome
	journeyCaptureAckPair
	journeyCaptureReconcileClaimIntent
	journeyCaptureReconcileClaimOutcome
	journeyCaptureFindIntent
	journeyCaptureFindOutcome
	journeyCaptureReconcileAckIntent
	journeyCaptureReconcileAckOutcome
	journeyRegionalRead
	journeyRegionalSign
	journeyRegionalVerify
	journeyRunnerRecovery
	journeyRunnerRead
	journeyRunnerTarget
	journeyRunnerEligibility
	journeyRunnerCapability
	journeyRunnerRetention
	journeyRunnerProcess
	journeyRunnerPrepare
	journeyRunnerKeys
	journeyRunnerLocalPrepare
	journeyRunnerBind
	journeyRunnerReady
	journeyRunnerConsume
	journeyRunnerRecord
	journeyRunnerEligibilityIdentity
	journeyDiagnosticStages
)

var journeyDiagnosticNames = [journeyDiagnosticStages]string{
	"audit-reserve", "audit-claim-intent", "audit-write-intent", "audit-complete-intent", "audit-ack-intent",
	"audit-freeze", "audit-claim-outcome", "audit-write-outcome", "audit-complete-outcome", "audit-ack-outcome",
	"preview-recovery", "preview-workload", "preview-pod", "preview-eligibility", "preview-capability",
	"preview-retention", "preview-storage", "preview-processing", "preview-create",
	"request-lookup", "request-preview-read", "request-admit",
	"capture-completed", "capture-journal", "capture-claim-intent", "capture-write-intent", "capture-complete-intent", "capture-ack-intent", "capture-freeze",
	"capture-claim-outcome", "capture-write-outcome", "capture-complete-outcome", "capture-ack-outcome", "capture-ack-pair",
	"capture-reconcile-claim-intent", "capture-reconcile-claim-outcome", "capture-find-intent", "capture-find-outcome", "capture-reconcile-ack-intent", "capture-reconcile-ack-outcome",
	"regional-read", "regional-sign",
	"regional-verify", "runner-recovery", "runner-read", "runner-target", "runner-eligibility", "runner-capability", "runner-retention", "runner-process", "runner-prepare", "runner-keys", "runner-local-prepare", "runner-bind", "runner-ready", "runner-consume", "runner-record-start", "runner-eligibility-identity",
}

type publicJourneyDiagnostics struct {
	mu                                 sync.Mutex
	stopped                            bool
	requestWindow                      bool
	calls, refusals                    [journeyDiagnosticStages]uint32
	reasons                            [journeyDiagnosticStages]uint8
	first                              int    // One-based; zero means no dependency returned a refusal.
	outcome                            uint8  // Closed output status supplied to the actual Freeze call.
	identityCanceled, identityDeadline uint32 // Returned original identity-call contexts only.
}

func (s *publicJourneyDiagnostics) record(stage int, code uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || stage < 0 || stage >= journeyDiagnosticStages {
		return
	}
	s.calls[stage]++
	if code != 0 {
		if s.reasons[stage] == 0 {
			s.reasons[stage] = code
		}
		s.refusals[stage]++
		if s.first == 0 {
			s.first = stage + 1
		}
	}
}
func (s *publicJourneyDiagnostics) freeze(status string) {
	// Unknown/arbitrary status is never retained or rendered.
	var v uint8
	switch status {
	case "success":
		v = 1
	case "denied":
		v = 2
	case "invalid":
		v = 3
	case "unavailable":
		v = 4
	case "interrupted":
		v = 5
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped && s.outcome == 0 {
		s.outcome = v
	}
}

// BeginRequest can reopen this recorder only once, after the preview has been
// reported and its original call returned. It never touches operation state.
func (s *publicJourneyDiagnostics) BeginRequest() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped || s.requestWindow {
		return false
	}
	s.calls, s.refusals, s.reasons = [journeyDiagnosticStages]uint32{}, [journeyDiagnosticStages]uint32{}, [journeyDiagnosticStages]uint8{}
	s.first, s.outcome = 0, 0
	s.identityCanceled, s.identityDeadline = 0, 0
	s.requestWindow, s.stopped = true, false
	return true
}

func (s *publicJourneyDiagnostics) Report(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	s.stopped = true
	calls, refusals, reasons, first, outcome := s.calls, s.refusals, s.reasons, s.first, s.outcome
	identityCanceled, identityDeadline := s.identityCanceled, s.identityDeadline
	phase := "preview"
	if s.requestWindow {
		phase = "request"
	}
	s.mu.Unlock()
	for i, count := range calls {
		if count != 0 {
			t.Logf("journey %s diagnostic stage=%s calls=%d refusals=%d reason=%s", phase, journeyDiagnosticNames[i], count, refusals[i], journeyDiagnosticReason(reasons[i]))
		}
	}
	name := "none"
	if first > 0 && first <= journeyDiagnosticStages {
		name = journeyDiagnosticNames[first-1]
	}
	status := "absent-or-unknown"
	switch outcome {
	case 1:
		status = "success"
	case 2:
		status = "denied"
	case 3:
		status = "invalid"
	case 4:
		status = "unavailable"
	case 5:
		status = "interrupted"
	}
	t.Logf("journey %s diagnostic first-refusal=%s frozen-outcome=%s", phase, name, status)
	if calls[journeyRunnerEligibilityIdentity] != 0 {
		t.Logf("journey original eligibility identity calls-context-canceled=%d calls-context-deadline=%d", identityCanceled, identityDeadline)
	}
}

type publicJourneyAuditDiagnostics struct {
	auditapp.OperationJournal
	auditapp.OperationAcknowledgements
	auditapp.ClosedOperationObjects
	auditapp.OperationCompletions
	trace *publicJourneyDiagnostics
}

func (s publicJourneyAuditDiagnostics) ReserveOperation(c context.Context, in auditvalue.OperationIntent) (auditvalue.OperationSnapshot, error) {
	v, e := s.OperationJournal.ReserveOperation(c, in)
	s.trace.record(0, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyAuditDiagnostics) ClaimOperationWrite(c context.Context, in auditvalue.OperationIntent, phase string) (bool, error) {
	v, e := s.OperationJournal.ClaimOperationWrite(c, in, phase)
	if phase == "intent" {
		s.trace.record(1, journeyDiagnosticError(e))
	} else if phase == "outcome" {
		s.trace.record(6, journeyDiagnosticError(e))
	}
	return v, e
}
func (s publicJourneyAuditDiagnostics) FreezeOperationOutcome(c context.Context, out auditvalue.OperationOutcome) (auditvalue.OperationSnapshot, error) {
	s.trace.freeze(out.Status)
	v, e := s.OperationJournal.FreezeOperationOutcome(c, out)
	s.trace.record(5, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyAuditDiagnostics) AcknowledgeOperation(c context.Context, in auditvalue.OperationIntent, phase string, r auditvalue.Receipt) error {
	e := s.OperationAcknowledgements.AcknowledgeOperation(c, in, phase, r)
	if phase == "intent" {
		s.trace.record(4, journeyDiagnosticError(e))
	} else if phase == "outcome" {
		s.trace.record(9, journeyDiagnosticError(e))
	}
	return e
}
func (s publicJourneyAuditDiagnostics) CreateClosedOperationIntent(c context.Context, in auditvalue.OperationIntent) (auditvalue.OperationWriteCompletion, error) {
	v, e := s.ClosedOperationObjects.CreateClosedOperationIntent(c, in)
	s.trace.record(2, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyAuditDiagnostics) CreateClosedOperationOutcome(c context.Context, out auditvalue.OperationOutcome) (auditvalue.OperationWriteCompletion, error) {
	v, e := s.ClosedOperationObjects.CreateClosedOperationOutcome(c, out)
	s.trace.record(7, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyAuditDiagnostics) RecordOperationCompletion(c context.Context, in auditvalue.OperationIntent, phase string, v auditvalue.OperationWriteCompletion) error {
	e := s.OperationCompletions.RecordOperationCompletion(c, in, phase, v)
	if phase == "intent" {
		s.trace.record(3, journeyDiagnosticError(e))
	} else if phase == "outcome" {
		s.trace.record(8, journeyDiagnosticError(e))
	}
	return e
}

// ReadOperationCompletion is deliberately the embedded original method: first
// preview starts a fresh request, never replays to manufacture a diagnostic.

func (s *publicJourneyDiagnostics) Investigation(in captureapp.ContextInvestigation) captureapp.ContextInvestigation {
	p := publicJourneyPreviewDiagnostics{ContextAdmissionReplay: in.Replay, ReviewedAdmissionTransaction: in.Admission, ContextTargets: in.Targets, ContextEligibilityReader: in.Eligibility, ContextCapabilityReader: in.Capabilities, ContextRetentionResolver: in.Retention, ContextStorageReader: in.Storage, ContextProcessingCoverageReader: in.Processing, ContextPreviewStore: in.Previews, RecoveryReader: in.Recovery, trace: s}
	if in.Replay != nil {
		in.Replay = p
	}
	if in.Admission != nil {
		in.Admission = p
	}
	if in.Targets != nil {
		in.Targets = p
	}
	if in.Eligibility != nil {
		in.Eligibility = p
	}
	if in.Capabilities != nil {
		in.Capabilities = p
	}
	if in.Retention != nil {
		in.Retention = p
	}
	if in.Storage != nil {
		in.Storage = p
	}
	if in.Processing != nil {
		in.Processing = p
	}
	if in.Previews != nil {
		in.Previews = p
	}
	if in.Recovery != nil {
		in.Recovery = p
	}
	return in
}

type publicJourneyPreviewDiagnostics struct {
	captureapp.ContextAdmissionReplay
	captureapp.ReviewedAdmissionTransaction
	captureapp.ContextTargets
	captureapp.ContextEligibilityReader
	captureapp.ContextCapabilityReader
	captureapp.ContextRetentionResolver
	captureapp.ContextStorageReader
	captureapp.ContextProcessingCoverageReader
	captureapp.ContextPreviewStore
	fleetapp.RecoveryReader
	trace *publicJourneyDiagnostics
}

func (s publicJourneyPreviewDiagnostics) RecoveryState(c context.Context) (fleet.RecoveryState, error) {
	v, e := s.RecoveryReader.RecoveryState(c)
	s.trace.record(10, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) ResolveWorkload(c context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	v, e := s.ContextTargets.ResolveWorkload(c, r)
	s.trace.record(11, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) ResolvePod(c context.Context, r targets.Request) (targets.PodResolution, error) {
	v, e := s.ContextTargets.ResolvePod(c, r)
	s.trace.record(12, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) ContextEligibilityCurrent(c context.Context, i identities.CurrentIdentity, t authorization.Target) authorization.CaptureEligibility {
	v := s.ContextEligibilityReader.ContextEligibilityCurrent(c, i, t)
	code := uint8(0)
	if !v.Eligible {
		code = 3
	}
	s.trace.record(13, code)
	return v
}
func (s publicJourneyPreviewDiagnostics) ContextCapability(c context.Context, t authorization.Target) (planning.ContextCapability, error) {
	v, e := s.ContextCapabilityReader.ContextCapability(c, t)
	s.trace.record(14, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) Resolve(c context.Context, in privacy.Input) (privacy.Resolution, error) {
	v, e := s.ContextRetentionResolver.Resolve(c, in)
	s.trace.record(15, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) ContextStorage(c context.Context, t authorization.Target) (captureapp.ContextStorageObservation, error) {
	v, e := s.ContextStorageReader.ContextStorage(c, t)
	s.trace.record(16, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) ContextProcessingCoverage(c context.Context, r capturevalue.ProcessingCoverageRequest, p artifact.RecoveryProof) (capturevalue.ProcessingCoverage, error) {
	v, e := s.ContextProcessingCoverageReader.ContextProcessingCoverage(c, r, p)
	s.trace.record(17, journeyDiagnosticError(e))
	return v, e
}
func (s publicJourneyPreviewDiagnostics) CreateContextPreview(c context.Context, v capturevalue.ContextPreview) error {
	e := s.ContextPreviewStore.CreateContextPreview(c, v)
	s.trace.record(18, journeyDiagnosticError(e))
	return e
}

// Compare only known sentinels; do not invoke Error, Is, As or Unwrap on a
// provider error. Wrapped/unknown errors stay a fixed unknown-refusal code.
func journeyDiagnosticError(err error) uint8 {
	if err == nil {
		return 0
	}
	if err == context.Canceled {
		return 1
	}
	if err == context.DeadlineExceeded {
		return 2
	}
	if err == identity.ErrDenied || err == capturevalue.ErrDenied {
		return 3
	}
	if err == capturevalue.ErrChanged {
		return 4
	}
	if err == auditapp.ErrUnavailable {
		return 5
	}
	if err == capturevalue.ErrUnavailable {
		return 6
	}
	if err == capturevalue.ErrProcessingCoverage {
		return 7
	}
	if err == capturevalue.ErrCapacity {
		return 8
	}
	return 9
}
func journeyDiagnosticReason(code uint8) string {
	switch code {
	case 0:
		return "none"
	case 1:
		return "canceled"
	case 2:
		return "deadline"
	case 3:
		return "denied"
	case 4:
		return "changed"
	case 5:
		return "audit-unavailable"
	case 6:
		return "capture-unavailable"
	case 7:
		return "processing-coverage"
	case 8:
		return "capacity"
	case 10:
		return "regional-invalid"
	case 11:
		return "regional-unavailable"
	case 12:
		return "execution-conflict"
	case 13:
		return "preparation-uncertain"
	case 14:
		return "exchange-protocol"
	case 20:
		return "eligibility-authority-unavailable"
	case 21:
		return "eligibility-identity-unavailable"
	case 22:
		return "eligibility-permission-unavailable"
	case 23:
		return "eligibility-invalid-request"
	case 24:
		return "eligibility-explicit-deny"
	case 25:
		return "eligibility-insufficient-scope"
	case 26:
		return "eligibility-no-entitlement"
	case 27:
		return "eligibility-no-audience"
	case 28:
		return "eligibility-audience-overflow"
	default:
		return "unknown-refusal"
	}
}

type journeyDiagnosticPrivateError struct{}

func (*journeyDiagnosticPrivateError) Error() string { panic("private error rendered") }
func (*journeyDiagnosticPrivateError) Unwrap() error { panic("private cause inspected") }
func (*journeyDiagnosticPrivateError) Is(error) bool { panic("private error inspected") }

type journeyDiagnosticJournal struct {
	auditapp.OperationJournal
	reserve func(context.Context, auditvalue.OperationIntent) (auditvalue.OperationSnapshot, error)
	claim   func(context.Context, auditvalue.OperationIntent, string) (bool, error)
	freeze  func(context.Context, auditvalue.OperationOutcome) (auditvalue.OperationSnapshot, error)
}

func (s journeyDiagnosticJournal) ReserveOperation(c context.Context, v auditvalue.OperationIntent) (auditvalue.OperationSnapshot, error) {
	return s.reserve(c, v)
}
func (s journeyDiagnosticJournal) ClaimOperationWrite(c context.Context, v auditvalue.OperationIntent, p string) (bool, error) {
	return s.claim(c, v, p)
}
func (s journeyDiagnosticJournal) FreezeOperationOutcome(c context.Context, v auditvalue.OperationOutcome) (auditvalue.OperationSnapshot, error) {
	return s.freeze(c, v)
}

// Run the actual auditor's Begin/Finish dispatch and normalization, not a
// second diagnostic-only rendition. A private failure is observed once and
// never becomes the public error, while the explanatory first stage survives.
func TestPublicJourneyDiagnosticsOriginalAuditDispatch(t *testing.T) {
	n := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	in := auditvalue.OperationIntent{ID: "00000000-0000-4000-8000-000000000001", TraceID: "00000000-0000-4000-8000-000000000001", RootID: "00000000-0000-4000-8000-000000000002", Name: "preview_capture", InputFormat: "context-input/v1", MACVersion: "v1", AccountVersion: "v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
	out := auditvalue.OperationOutcome{Intent: in, Status: "unavailable", Reason: "authority_unavailable", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{3}, MetadataUntil: in.RequestUntil, RecordedAt: n}
	if !in.Valid() || !out.Valid() {
		t.Fatal("invalid audit test input")
	}
	for _, phase := range []string{"reserve", "claim", "finish"} {
		t.Run(phase, func(t *testing.T) {
			c := context.WithValue(context.Background(), struct{}{}, "original-context")
			private := &journeyDiagnosticPrivateError{}
			var got []string
			journal := journeyDiagnosticJournal{}
			journal.reserve = func(ctx context.Context, v auditvalue.OperationIntent) (auditvalue.OperationSnapshot, error) {
				if ctx != c || !reflect.DeepEqual(v, in) {
					t.Fatal("reserve replaced original input")
				}
				got = append(got, "reserve")
				if phase == "reserve" {
					return auditvalue.OperationSnapshot{}, private
				}
				return auditvalue.OperationSnapshot{Intent: v}, nil
			}
			journal.claim = func(ctx context.Context, v auditvalue.OperationIntent, p string) (bool, error) {
				if ctx != c || !reflect.DeepEqual(v, in) || p != "intent" {
					t.Fatal("claim replaced original input")
				}
				got = append(got, "claim")
				return false, private
			}
			journal.freeze = func(ctx context.Context, v auditvalue.OperationOutcome) (auditvalue.OperationSnapshot, error) {
				if ctx != c || !reflect.DeepEqual(v, out) {
					t.Fatal("freeze replaced original outcome")
				}
				got = append(got, "finish")
				return auditvalue.OperationSnapshot{}, private
			}
			trace := &publicJourneyDiagnostics{}
			probe := publicJourneyAuditDiagnostics{OperationJournal: journal, trace: trace}
			auditor := auditapp.OperationAuditor{Journal: probe, Acknowledgements: probe, Objects: &objectstoreDiagnosticUnused{}, Now: func() time.Time { return n }}
			var err error
			if phase == "finish" {
				err = auditor.Finish(c, out)
			} else {
				err = auditor.Begin(c, in)
			}
			// Normalized to the sentinel (a closed step may name where it
			// stopped); the private cause is never reachable.
			if !errors.Is(err, auditapp.ErrUnavailable) || errors.Is(err, private) {
				t.Fatal("audit normalization changed")
			}
			expected := []string{phase}
			stage := 0
			if phase == "claim" {
				expected = []string{"reserve", "claim"}
				stage = 1
			}
			if phase == "finish" {
				stage = 5
			}
			if !reflect.DeepEqual(got, expected) || trace.first != stage+1 || trace.refusals[stage] != 1 || trace.reasons[stage] != 9 {
				t.Fatal("actual dispatch/first refusal changed")
			}
			trace.record(18, 4)
			if trace.first != stage+1 {
				t.Fatal("later refusal overwrote original")
			}
			trace.Report(t) // Rendering must never touch the private error methods.
		})
	}
}

// The actual auditor refuses before these embedded, deliberately unavailable
// object methods. Calling one would panic and expose an unexpected dispatch.
type objectstoreDiagnosticUnused struct{ auditapp.OperationObjects }

type journeyDiagnosticStorage struct {
	call func(context.Context, authorization.Target) (captureapp.ContextStorageObservation, error)
}

func (s journeyDiagnosticStorage) ContextStorage(c context.Context, t authorization.Target) (captureapp.ContextStorageObservation, error) {
	return s.call(c, t)
}
func TestPublicJourneyDiagnosticsOriginalPreviewDelegate(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed", true: "canceled"}[stop], func(t *testing.T) {
			c, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stop {
				cancel()
			}
			target := authorization.Target{ClusterID: "original-cluster", NamespaceUID: "original-namespace", WorkloadUID: "original-workload", PodUID: "original-pod"}
			result := captureapp.ContextStorageObservation{Selection: capturevalue.ContextStorageSelection{StoreID: "original-store"}}
			want := error(capturevalue.ErrChanged)
			if stop {
				want = context.Canceled
			}
			calls := 0
			inner := journeyDiagnosticStorage{call: func(ctx context.Context, v authorization.Target) (captureapp.ContextStorageObservation, error) {
				calls++
				if ctx != c || v != target {
					t.Fatal("diagnostic substituted original context/target")
				}
				return result, want
			}}
			trace := &publicJourneyDiagnostics{}
			wrapped := trace.Investigation(captureapp.ContextInvestigation{Storage: inner})
			if wrapped.Targets != nil || wrapped.Previews != nil || wrapped.Recovery != nil {
				t.Fatal("diagnostics filled absent authority")
			}
			got, err := wrapped.Storage.ContextStorage(c, target)
			if calls != 1 || err != want || got != result || trace.first != 17 || trace.calls[16] != 1 || trace.refusals[16] != 1 {
				t.Fatal("original storage dispatch changed")
			}
			trace.Report(t)
			before := trace.calls
			trace.record(0, 9)
			if trace.calls != before {
				t.Fatal("completed diagnostic recorded a later operation")
			}
		})
	}
}
