package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

// Accepted installation inputs, not user options. The immutable policy is copied
// at construction; Finish cannot extend dates using a later configuration/time.
type HealthyOperationAuditor struct {
	auditor OperationAuditor
	policy  value.OperationLifecyclePolicy
}
type OperationCompletions interface {
	RecordOperationCompletion(context.Context, value.OperationIntent, string, value.OperationWriteCompletion) error
	ReadOperationCompletion(context.Context, value.OperationIntent, string) (value.OperationWriteCompletion, error)
}
type ClosedOperationObjects interface {
	CreateClosedOperationIntent(context.Context, value.OperationIntent) (value.OperationWriteCompletion, error)
	CreateClosedOperationOutcome(context.Context, value.OperationOutcome) (value.OperationWriteCompletion, error)
}

func NewHealthyOperationAuditor(p value.OperationLifecyclePolicy, journal OperationJournal, acknowledgements OperationAcknowledgements, legacy OperationObjects, closed ClosedOperationObjects, completions OperationCompletions, now func() time.Time) (*HealthyOperationAuditor, error) {
	if !p.CertificateVerificationBacked() || journal == nil || acknowledgements == nil || legacy == nil || closed == nil || completions == nil || now == nil {
		return nil, ErrUnavailable
	}
	if p.History != nil {
		q := *p.History
		p.History = &q
	}
	objects := healthyOperationObjects{legacy, closed, completions}
	return &HealthyOperationAuditor{OperationAuditor{journal, acknowledgements, objects, now}, p}, nil
}
func BindOperationLifecycle(in value.OperationIntent, p value.OperationLifecyclePolicy) (value.OperationIntent, error) {
	if p.History != nil {
		q := *p.History
		p.History = &q
	}
	original := in.Lifecycle
	in.Lifecycle = nil
	if !in.Valid() || !p.Valid() {
		return value.OperationIntent{}, ErrUnavailable
	}
	b := time.Duration(p.CleanupBudgetSeconds) * time.Second
	live := in.RetainUntil.Add(-2*time.Duration(p.BackupHorizonSeconds)*time.Second - b)
	cert := live.Add(-b)
	binding := value.OperationLifecycleBinding{Protocol: value.OperationWriterProtocol, Policy: p, OriginalPurgeAt: cert.Add(-time.Duration(p.ProofWindowSeconds)*time.Second - b), CertificatePurgeAt: cert, LiveRetireBy: live, HistoryReleaseAt: in.RetainUntil.Add(-time.Duration(p.BackupHorizonSeconds)*time.Second - b), HistoryDeleteBy: in.RetainUntil.Add(-time.Duration(p.BackupHorizonSeconds) * time.Second)}
	if !binding.Valid(in) || original != nil && !sameOperationRecord(*original, binding) {
		return value.OperationIntent{}, ErrUnavailable
	}
	in.Lifecycle = &binding
	if !in.Valid() {
		return value.OperationIntent{}, ErrUnavailable
	}
	return in, nil
}

// Configured validates immutable composition only. Current recovery/backing
// authority is still checked by every underlying operation.
func (s *HealthyOperationAuditor) Configured() bool {
	return s != nil && s.policy.CertificateVerificationBacked() && s.auditor.Journal != nil && s.auditor.Acknowledgements != nil && s.auditor.Objects != nil && s.auditor.Now != nil
}
func (s *HealthyOperationAuditor) Begin(ctx context.Context, in value.OperationIntent) error {
	if s == nil {
		return ErrUnavailable
	}
	bound, e := BindOperationLifecycle(in, s.policy)
	if e != nil {
		return operationStep("lifecycle")
	}
	return s.auditor.Begin(ctx, bound)
}
func (s *HealthyOperationAuditor) Finish(ctx context.Context, out value.OperationOutcome) error {
	if s == nil {
		return ErrUnavailable
	}
	bound, e := BindOperationLifecycle(out.Intent, s.policy)
	if e != nil {
		return operationStep("lifecycle")
	}
	out.Intent = bound
	return s.auditor.Finish(ctx, out)
}

type healthyOperationObjects struct {
	legacy      OperationObjects
	closed      ClosedOperationObjects
	completions OperationCompletions
}

func (s healthyOperationObjects) receipt(ctx context.Context, in value.OperationIntent, phase string, record any, c value.OperationWriteCompletion, err error, recordCompletion bool) (value.Receipt, error) {
	if err != nil {
		return value.Receipt{}, operationStep("closed", err)
	}
	if in.Lifecycle == nil || !c.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, phase, in.CreatedAt, in.WriteUntil) || c.RecordDigest != OperationLifecycleDigest(record) {
		return value.Receipt{}, operationStep("completion-invalid")
	}
	if recordCompletion {
		if err = s.completions.RecordOperationCompletion(ctx, in, phase, c); err != nil {
			return value.Receipt{}, operationStep("completion-record")
		}
	}
	return c.Receipt, nil
}
func (s healthyOperationObjects) CreateOperationIntent(ctx context.Context, in value.OperationIntent) (value.Receipt, error) {
	c, e := s.closed.CreateClosedOperationIntent(ctx, in)
	return s.receipt(ctx, in, "intent", in, c, e, true)
}
func (s healthyOperationObjects) CreateOperationOutcome(ctx context.Context, out value.OperationOutcome) (value.Receipt, error) {
	c, e := s.closed.CreateClosedOperationOutcome(ctx, out)
	return s.receipt(ctx, out.Intent, "outcome", out, c, e, true)
}
func (s healthyOperationObjects) FindOperationIntent(ctx context.Context, in value.OperationIntent) (value.Receipt, error) {
	c, e := s.completions.ReadOperationCompletion(ctx, in, "intent")
	r, e := s.receipt(ctx, in, "intent", in, c, e, false)
	if e != nil {
		return r, e
	}
	observed, e := s.legacy.FindOperationIntent(ctx, in)
	if e != nil || !sameOperationRecord(r, observed) {
		return value.Receipt{}, ErrUnavailable
	}
	return r, nil
}
func (s healthyOperationObjects) FindOperationOutcome(ctx context.Context, out value.OperationOutcome) (value.Receipt, error) {
	c, e := s.completions.ReadOperationCompletion(ctx, out.Intent, "outcome")
	r, e := s.receipt(ctx, out.Intent, "outcome", out, c, e, false)
	if e != nil {
		return r, e
	}
	observed, e := s.legacy.FindOperationOutcome(ctx, out)
	if e != nil || !sameOperationRecord(r, observed) {
		return value.Receipt{}, ErrUnavailable
	}
	return r, nil
}

// Digests bind minimized records/ciphertext receipts, never native evidence.
func OperationLifecycleDigest(v any) artifact.Digest {
	switch r := v.(type) {
	case value.OperationIntent:
		if r.Name == value.CaptureOperationName {
			return captureCompletionDigest(r, "intent")
		}
	case value.OperationOutcome:
		if r.Intent.Name == value.CaptureOperationName {
			return captureCompletionDigest(r, "outcome")
		}
	case *value.OperationIntent:
		if r != nil && r.Name == value.CaptureOperationName {
			return captureCompletionDigest(*r, "intent")
		}
	case *value.OperationOutcome:
		if r != nil && r.Intent.Name == value.CaptureOperationName {
			return captureCompletionDigest(*r, "outcome")
		}
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > 32<<10 {
		return artifact.Digest{}
	}
	return artifact.Digest(sha256.Sum256(b))
}

type OperationRetirementSigner interface {
	SignOperationRetirement(context.Context, value.OperationRetirement) ([]byte, error)
}
type OperationRetirementVerifier interface {
	VerifyOperationRetirement(context.Context, value.OperationRetirement, []byte) error
}
type OperationLifecycleJournal interface {
	ReadOperationLifecycle(context.Context, string) (value.OperationLifecycleSnapshot, error)
	BeginOperationPurge(context.Context, string, string) (value.OperationPurgeLease, error)
	RecordOriginalOperationPurge(context.Context, value.OperationPurgeLease) (value.OperationRetirement, error)
	ClaimOperationCertificate(context.Context, value.OperationRetirement) (bool, error)
	RecordCertificateCompletion(context.Context, value.OperationRetirement, value.OperationWriteCompletion) error
	RecordTerminalOperationPurge(context.Context, value.OperationPurgeLease) (value.OperationTerminalPurge, error)
}
type OperationLifecycleAcknowledgements interface {
	ClaimOperationCertificateVerification(context.Context, value.OperationRetirement, value.Receipt) (time.Time, error)
	AcknowledgeOperationCertificate(context.Context, value.OperationRetirement, value.Receipt) error
	AcknowledgeTerminalOperationPurge(context.Context, value.OperationPurgeLease, value.OperationTerminalPurge) error
}
type OperationRetirementFinalizer interface {
	RetireOperationAudit(context.Context, string) error
}
type OperationCleanupObjects interface {
	PurgeOperationObjects(context.Context, value.OperationPurgeLease) error
	CreateOperationCertificate(context.Context, value.OperationRetirement) (value.OperationWriteCompletion, error)
}
type OperationCleanupVerifier interface {
	VerifyOperationCertificate(context.Context, value.OperationRetirement, value.Receipt) error
	VerifyOperationAbsence(context.Context, value.OperationPurgeLease) error
}

// The verifier uses independent credentials and never returns writer closure
// from Find. All operations are finite; scheduling/supervision is outside this port.
type OperationCleanup struct {
	Journal          OperationLifecycleJournal
	Acknowledgements OperationLifecycleAcknowledgements
	Finalizer        OperationRetirementFinalizer
	Objects          OperationCleanupObjects
	Verifier         OperationCleanupVerifier
}

func (s OperationCleanup) Advance(ctx context.Context, id string) error {
	if ctx == nil || ctx.Err() != nil || s.Journal == nil || s.Acknowledgements == nil || s.Finalizer == nil || s.Objects == nil || s.Verifier == nil {
		return ErrUnavailable
	}
	state, e := s.Journal.ReadOperationLifecycle(ctx, id)
	if e != nil {
		return ErrUnavailable
	}
	// Historical unacknowledged records have no fresh verifier allowance.
	// Do not destroy their originals or create a certificate that cannot be
	// acknowledged. Already acknowledged history can still finish terminal
	// cleanup; explicit overdue-original reconciliation is a separate path.
	if state.CertificateReceipt == nil && (state.Intent.Lifecycle == nil || !state.Intent.Lifecycle.Policy.CertificateVerificationBacked()) {
		return ErrUnavailable
	}
	if state.Retirement == nil {
		lease, e := s.Journal.BeginOperationPurge(ctx, id, "original")
		if e != nil {
			return ErrUnavailable
		}
		if e = s.Objects.PurgeOperationObjects(ctx, lease); e != nil {
			return ErrUnavailable
		}
		r, e := s.Journal.RecordOriginalOperationPurge(ctx, lease)
		if e != nil {
			return ErrUnavailable
		}
		state.Retirement = &r
	}
	r := *state.Retirement
	if state.CertificateReceipt == nil {
		if state.CertificateWriter == nil {
			fresh, e := s.Journal.ClaimOperationCertificate(ctx, r)
			if e != nil || !fresh {
				return ErrUnavailable
			}
			c, e := s.Objects.CreateOperationCertificate(ctx, r)
			if e != nil {
				return ErrUnavailable
			}
			if e = s.Journal.RecordCertificateCompletion(ctx, r, c); e != nil {
				return ErrUnavailable
			}
			state.CertificateWriter = &c
		}
		receipt := state.CertificateWriter.Receipt
		// Spend the independent verifier's original durable allowance before any
		// provider read/unwrap. Unknown claim/acknowledgement replies stay spent.
		deadline := identity.Earlier(time.Now().Add(5*time.Second), r.CertificateWriteUntil)
		verification, stop := context.WithDeadline(ctx, deadline)
		defer stop()
		until, e := s.Acknowledgements.ClaimOperationCertificateVerification(verification, r, receipt)
		if e != nil || verification.Err() != nil || !time.Now().Before(until) || until.After(deadline) {
			return ErrUnavailable
		}
		verification, stopVerification := context.WithDeadline(verification, until)
		defer stopVerification()
		if e = s.Verifier.VerifyOperationCertificate(verification, r, receipt); e != nil || verification.Err() != nil {
			return ErrUnavailable
		}
		if e = s.Acknowledgements.AcknowledgeOperationCertificate(verification, r, receipt); e != nil || verification.Err() != nil {
			return ErrUnavailable
		}
	}
	// The second lease is available only after the ORIGINAL certificate proof
	// deadline. Early calls return unavailable without changing that schedule.
	lease, e := s.Journal.BeginOperationPurge(ctx, id, "terminal")
	if e != nil {
		return ErrUnavailable
	}
	if e = s.Objects.PurgeOperationObjects(ctx, lease); e != nil {
		return ErrUnavailable
	}
	terminal, e := s.Journal.RecordTerminalOperationPurge(ctx, lease)
	if e != nil {
		return ErrUnavailable
	}
	if e = s.Verifier.VerifyOperationAbsence(ctx, lease); e != nil {
		return ErrUnavailable
	}
	if e = s.Acknowledgements.AcknowledgeTerminalOperationPurge(ctx, lease, terminal); e != nil {
		return ErrUnavailable
	}
	return s.Finalizer.RetireOperationAudit(ctx, id)
}

// Each sweep is a bounded private control operation. A timer/supervisor does not
// confer recovery authority or silently clear unknown records.
type OperationHistoryJournal interface {
	DueOperationHistory(context.Context) ([]value.OperationHistoryKey, error)
}
type OperationHistoryFinalizer interface {
	ReleaseOperationHistory(context.Context, value.OperationHistoryKey) (value.OperationHistoryRelease, error)
}
type OperationHistoryCleanup struct {
	Journal   OperationHistoryJournal
	Finalizer OperationHistoryFinalizer
}

func (s OperationHistoryCleanup) Sweep(ctx context.Context) (value.OperationHistoryRelease, error) {
	var total value.OperationHistoryRelease
	if ctx == nil || s.Journal == nil || s.Finalizer == nil {
		return total, ErrUnavailable
	}
	keys, e := s.Journal.DueOperationHistory(ctx)
	if e != nil || len(keys) > 16 {
		return total, ErrUnavailable
	}
	for _, key := range keys {
		r, e := s.Finalizer.ReleaseOperationHistory(ctx, key)
		if e != nil {
			return total, ErrUnavailable
		}
		total.Records += r.Records
		total.Overdue = total.Overdue || r.Overdue
	}
	return total, nil
}
