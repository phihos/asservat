package evidence

import (
	"context"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

type ClosedDownloadStopObjects interface {
	CreateClosedDownloadStop(context.Context, audit.DownloadStopLifecycleBinding, artifact.DownloadStopDecision) (audit.DownloadStopWriteCompletion, error)
}
type DownloadStopCompletions interface {
	ReadDownloadStopBinding(context.Context, artifact.DownloadStopDecision) (audit.DownloadStopLifecycleBinding, error)
	ReadDownloadStopCompletion(context.Context, artifact.DownloadStopDecision) (audit.DownloadStopWriteCompletion, error)
	RecordDownloadStopCompletion(context.Context, artifact.DownloadStopDecision, audit.DownloadStopWriteCompletion) error
}

// Explicit protected composition; legacy receipts are never upgraded. The same
// Stop coordinator still owns the one-use claim and independent acknowledgement.
func NewHealthyDownloadStopObjects(legacy DownloadStopObjects, closed ClosedDownloadStopObjects, completions DownloadStopCompletions) (DownloadStopObjects, error) {
	if legacy == nil || closed == nil || completions == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return healthyDownloadStopObjects{legacy, closed, completions}, nil
}

type healthyDownloadStopObjects struct {
	legacy      DownloadStopObjects
	closed      ClosedDownloadStopObjects
	completions DownloadStopCompletions
}

func (s healthyDownloadStopObjects) CreateDownloadStop(ctx context.Context, d artifact.DownloadStopDecision) (audit.Receipt, error) {
	b, e := s.completions.ReadDownloadStopBinding(ctx, d)
	if e != nil || !validStopDecisionBinding(d, b) {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	c, e := s.closed.CreateClosedDownloadStop(ctx, b, d)
	if e != nil || !validStopCompletion(b, d, c) {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	if e = s.completions.RecordDownloadStopCompletion(ctx, d, c); e != nil {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	return c.Receipt, nil
}
func (s healthyDownloadStopObjects) FindDownloadStop(ctx context.Context, d artifact.DownloadStopDecision) (audit.Receipt, error) {
	b, e := s.completions.ReadDownloadStopBinding(ctx, d)
	if e != nil || !validStopDecisionBinding(d, b) {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	c, e := s.completions.ReadDownloadStopCompletion(ctx, d)
	if e != nil || !validStopCompletion(b, d, c) {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	r, e := s.legacy.FindDownloadStop(ctx, d)
	if e != nil || r != c.Receipt {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	return r, nil
}
func validStopDecisionBinding(d artifact.DownloadStopDecision, b audit.DownloadStopLifecycleBinding) bool {
	return d.Valid() && b.Valid() && d.RootID == b.RootID && d.DownloadID == b.DownloadID && d.StoreID == b.Policy.StoreID && !d.RequestedAt.Before(b.ReservedAt) && d.WriteUntil.Before(b.OriginalPurgeAt) && d.RetainUntil.Equal(b.HardDeleteBy)
}
func validStopCompletion(b audit.DownloadStopLifecycleBinding, d artifact.DownloadStopDecision, c audit.DownloadStopWriteCompletion) bool {
	return validStopDecisionBinding(d, b) && c.Valid(b, "decision", d.RequestedAt, d.WriteUntil) && c.BindingDigest == auditapp.OperationLifecycleDigest(b) && c.RecordDigest == auditapp.OperationLifecycleDigest(d)
}

type DownloadStopRetirementSigner interface {
	SignDownloadStopRetirement(context.Context, audit.DownloadStopRetirement) ([]byte, error)
}
type DownloadStopRetirementVerifier interface {
	VerifyDownloadStopRetirement(context.Context, audit.DownloadStopRetirement, []byte) error
}
type DownloadStopLifecycleJournal interface {
	ReadDownloadStopLifecycle(context.Context, string) (audit.DownloadStopLifecycleSnapshot, error)
	BeginDownloadStopPurge(context.Context, string, string) (audit.DownloadStopPurgeLease, error)
	RecordOriginalDownloadStopPurge(context.Context, audit.DownloadStopPurgeLease) (audit.DownloadStopRetirement, error)
	ClaimDownloadStopCertificate(context.Context, audit.DownloadStopRetirement) (bool, error)
	RecordDownloadStopCertificateCompletion(context.Context, audit.DownloadStopRetirement, audit.DownloadStopWriteCompletion) error
	RecordTerminalDownloadStopPurge(context.Context, audit.DownloadStopPurgeLease) (audit.DownloadStopPurgeResult, error)
}
type DownloadStopLifecycleAcknowledgements interface {
	ClaimDownloadStopCertificateVerification(context.Context, audit.DownloadStopRetirement) (bool, error)
	AcknowledgeDownloadStopCertificate(context.Context, audit.DownloadStopRetirement, audit.Receipt) error
	AcknowledgeDownloadStopAbsence(context.Context, audit.DownloadStopPurgeLease, audit.DownloadStopPurgeResult) error
}
type DownloadStopLifecycleFinalizer interface {
	RetireDownloadStop(context.Context, string) error
}
type DownloadStopCleanupObjects interface {
	PurgeDownloadStopObjects(context.Context, audit.DownloadStopPurgeLease) error
	CreateDownloadStopCertificate(context.Context, audit.DownloadStopLifecycleBinding, audit.DownloadStopRetirement) (audit.DownloadStopWriteCompletion, error)
}
type DownloadStopCleanupVerifier interface {
	VerifyDownloadStopCertificate(context.Context, audit.DownloadStopRetirement, audit.Receipt) error
	VerifyDownloadStopAbsence(context.Context, audit.DownloadStopPurgeLease) error
}

// Each call is finite and preserves SQL's original phase boundaries. It neither
// schedules work nor creates new decisions/producer attempts on a read retry.
type DownloadStopCleanup struct {
	Journal          DownloadStopLifecycleJournal
	Acknowledgements DownloadStopLifecycleAcknowledgements
	Finalizer        DownloadStopLifecycleFinalizer
	Objects          DownloadStopCleanupObjects
	Verifier         DownloadStopCleanupVerifier
	Now              func() time.Time
}

func (s DownloadStopCleanup) Advance(ctx context.Context, id string) error {
	if ctx == nil || ctx.Err() != nil || s.Journal == nil || s.Acknowledgements == nil || s.Finalizer == nil || s.Objects == nil || s.Verifier == nil || s.Now == nil {
		return artifact.ErrDownloadUnavailable
	}
	state, e := s.Journal.ReadDownloadStopLifecycle(ctx, id)
	if e != nil || !state.Binding.Valid() || state.Binding.DownloadID != id {
		return artifact.ErrDownloadUnavailable
	}
	b := state.Binding
	// Selecting overdue is an irreversible SQL fence, only available when no
	// certificate claim was issued. The original proof interval never slides.
	if !state.CertificateStarted && !s.Now().Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)) {
		return s.terminal(ctx, id, "overdue")
	}
	if state.Retirement == nil {
		lease, e := s.Journal.BeginDownloadStopPurge(ctx, id, "original")
		if e != nil {
			return artifact.ErrDownloadUnavailable
		}
		if e = s.Objects.PurgeDownloadStopObjects(ctx, lease); e != nil {
			return e
		}
		r, e := s.Journal.RecordOriginalDownloadStopPurge(ctx, lease)
		if e != nil {
			return e
		}
		state.Retirement = &r
	}
	r := *state.Retirement
	if state.CertificateReceipt == nil {
		if state.CertificateWriter == nil {
			fresh, e := s.Journal.ClaimDownloadStopCertificate(ctx, r)
			if e != nil || !fresh {
				return artifact.ErrDownloadUnavailable
			}
			c, e := s.Objects.CreateDownloadStopCertificate(ctx, b, r)
			if e != nil {
				return e
			}
			if e = s.Journal.RecordDownloadStopCertificateCompletion(ctx, r, c); e != nil {
				return e
			}
			state.CertificateWriter = &c
		}
		receipt := state.CertificateWriter.Receipt
		fresh, e := s.Acknowledgements.ClaimDownloadStopCertificateVerification(ctx, r)
		if e != nil || !fresh {
			return artifact.ErrDownloadUnavailable
		}
		if e = s.Verifier.VerifyDownloadStopCertificate(ctx, r, receipt); e != nil {
			return e
		}
		if e = s.Acknowledgements.AcknowledgeDownloadStopCertificate(ctx, r, receipt); e != nil {
			return e
		}
	}
	return s.terminal(ctx, id, "terminal")
}
func (s DownloadStopCleanup) terminal(ctx context.Context, id, phase string) error {
	l, e := s.Journal.BeginDownloadStopPurge(ctx, id, phase)
	if e != nil {
		return e
	}
	if e = s.Objects.PurgeDownloadStopObjects(ctx, l); e != nil {
		return e
	}
	p, e := s.Journal.RecordTerminalDownloadStopPurge(ctx, l)
	if e != nil {
		return e
	}
	if e = s.Verifier.VerifyDownloadStopAbsence(ctx, l); e != nil {
		return e
	}
	if e = s.Acknowledgements.AcknowledgeDownloadStopAbsence(ctx, l, p); e != nil {
		return e
	}
	return s.Finalizer.RetireDownloadStop(ctx, id)
}

type DownloadStopHistoryJournal interface {
	DueDownloadStopHistory(context.Context) ([]audit.DownloadStopHistoryKey, error)
	ReleaseDownloadStopHistory(context.Context, audit.DownloadStopHistoryKey) (audit.OperationHistoryRelease, error)
}

func SweepDownloadStopHistory(ctx context.Context, j DownloadStopHistoryJournal) (audit.OperationHistoryRelease, error) {
	var out audit.OperationHistoryRelease
	if ctx == nil || j == nil {
		return out, artifact.ErrDownloadUnavailable
	}
	keys, e := j.DueDownloadStopHistory(ctx)
	if e != nil || len(keys) > 16 {
		return out, artifact.ErrDownloadUnavailable
	}
	for _, k := range keys {
		if !k.Valid() {
			return out, artifact.ErrDownloadUnavailable
		}
		r, e := j.ReleaseDownloadStopHistory(ctx, k)
		if e != nil {
			return out, e
		}
		out.Records += r.Records
		out.Overdue = out.Overdue || r.Overdue
	}
	return out, nil
}
