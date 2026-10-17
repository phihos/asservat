package fleet

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"time"
)

type OwnerConfigurationLedger interface {
	ObserveOwnerConfiguration(context.Context, value.OwnerConfigurationObservation) (audit.Receipt, bool, error)
	FenceOwnerConfiguration(context.Context, time.Time) error
}

// Acceptance journals protected observations before separate encrypted audit.
// Neither audit completion nor retry refreshes the original observation lease.
type OwnerConfigurationObserver struct {
	Reader           OwnerConfigurationReader
	Ledger           OwnerConfigurationLedger
	Audit            auditapp.OwnerConfigurationWriter
	Acknowledgements auditapp.OwnerConfigurationAcknowledgements
	Now              func() time.Time
}

func (s *OwnerConfigurationObserver) Observe(ctx context.Context) error {
	candidate, acknowledged, err := s.observeForAudit(ctx)
	if err != nil || acknowledged {
		return err
	}
	return s.auditObserved(ctx, candidate)
}

// This private value is one independently read and SQL-observed source, not a
// replacement clock. The fresh worker's background actor retains this exact
// identity/end after the source loop releases its completed read context.
type ownerConfigurationAuditCandidate struct {
	observation value.OwnerConfigurationObservation
	until       time.Time
	superseded  bool
}

func (s *OwnerConfigurationObserver) observeForAudit(ctx context.Context) (ownerConfigurationAuditCandidate, bool, error) {
	return s.observeForAuditNotifying(ctx, nil)
}

// The optional concrete mailbox receives only cancellation, before a negative
// SQL fence can block. It cannot supply observations, acknowledgements or a new
// deadline. Legacy synchronous Observe has no mailbox and keeps its fence path.
func (s *OwnerConfigurationObserver) observeForAuditNotifying(ctx context.Context, mailbox *workerOwnerAudit) (ownerConfigurationAuditCandidate, bool, error) {
	var out ownerConfigurationAuditCandidate
	if s == nil || ctx == nil || s.Reader == nil || s.Ledger == nil || s.Audit == nil || s.Acknowledgements == nil || s.Now == nil {
		return out, false, value.ErrInvalid
	}
	start := s.Now()
	fence := func(at time.Time) {
		mailbox.invalidate()
		cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer end()
		_ = s.Ledger.FenceOwnerConfiguration(cleanup, at)
	}
	o, err := s.Reader.ReadOwnerConfiguration(ctx)
	if err != nil || !o.Valid(s.Now()) || ctx.Err() != nil {
		fence(start)
		return out, false, value.ErrUnavailable
	}
	o.Configuration = o.Configuration.Clone()
	// A changed complete source is known before its SQL observation can wait.
	// Cancel prior local work immediately; this notification authorizes nothing.
	superseded := mailbox.noteSource(o.Configuration)
	ctx, end := context.WithDeadline(ctx, o.FreshUntil)
	defer end()
	r, ack, err := s.Ledger.ObserveOwnerConfiguration(ctx, o)
	if err != nil {
		fence(o.ObservedAt)
		return out, false, err
	}
	if ctx.Err() != nil || !o.Valid(s.Now()) {
		mailbox.invalidate()
		return out, false, value.ErrUnavailable
	}
	if ack && !r.ValidOwnerConfiguration(o.Configuration) {
		fence(o.ObservedAt)
		return out, false, value.ErrDenied
	}
	until, _ := ctx.Deadline()
	return ownerConfigurationAuditCandidate{observation: o, until: until, superseded: superseded}, ack, nil
}

func (s *OwnerConfigurationObserver) auditObserved(ctx context.Context, c ownerConfigurationAuditCandidate) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !c.observation.Valid(s.Now()) || !s.Now().Before(c.until) {
		return value.ErrUnavailable
	}
	ctx, end := context.WithDeadline(ctx, c.until)
	defer end()
	o := c.observation
	r, err := s.Audit.WriteOwnerConfiguration(ctx, o.Configuration)
	if err != nil {
		return err
	}
	if ctx.Err() != nil || !o.Valid(s.Now()) || !s.Now().Before(c.until) {
		return value.ErrUnavailable
	}
	if !r.ValidOwnerConfiguration(o.Configuration) {
		return value.ErrDenied
	}
	if err = s.Acknowledgements.AcknowledgeOwnerConfiguration(ctx, o.Configuration, r); err != nil {
		return err
	}
	if ctx.Err() != nil || !o.Valid(s.Now()) || !s.Now().Before(c.until) {
		return value.ErrUnavailable
	}
	return nil
}
