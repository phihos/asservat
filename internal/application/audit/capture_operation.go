package audit

import (
	"context"
	"encoding/json"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// PrepareCaptureOperation is called inside admission after the exact original
// CaptureIntent has been reconstructed. It reserves nothing and grants no I/O.
func PrepareCaptureOperation(c value.CaptureIntent, a value.CaptureAuditAccount, mac *OperationMAC, requestUntil time.Time) (value.OperationIntent, error) {
	if !c.Valid() || !a.Valid() || c.RootID != a.RootID || mac == nil || mac.AccountVersion() != a.AccountVersion {
		return value.OperationIntent{}, ErrUnavailable
	}
	account, err := mac.CaptureAccount(a.Policy.InstallationID, a.RootID, a.AllocationID)
	if err != nil || account != a.AccountDigest {
		return value.OperationIntent{}, ErrUnavailable
	}
	raw, err := captureEncoding(c, 8<<10)
	if err != nil || len(raw) > 8<<10 {
		return value.OperationIntent{}, ErrUnavailable
	}
	defer clear(raw)
	input, err := mac.Digest(value.CaptureOperationInputFormat, raw)
	if err != nil {
		return value.OperationIntent{}, err
	}
	until := identity.Earlier(c.Deadline, c.CreatedAt.Add(30*time.Second))
	// Only the live caller bound is reduced to SQL precision. Never round up
	// an expiry or rewrite the already accepted capture's historical dates.
	requestUntil = identity.Earlier(requestUntil, identity.Earlier(c.CreatedAt.Add(5*time.Second), until)).UTC().Truncate(time.Microsecond)
	in := value.OperationIntent{ID: c.CaptureID, RootID: c.RootID, TraceID: c.OccurrenceID, Name: value.CaptureOperationName, InputFormat: value.CaptureOperationInputFormat, MACVersion: mac.Version(), AccountVersion: a.AccountVersion, Actor: c.Actor, PrincipalDigest: account, InputDigest: input, CreatedAt: c.CreatedAt, RequestUntil: requestUntil, WriteUntil: until, RetainUntil: c.CreatedAt.Add(time.Duration(a.RetainedSeconds) * time.Second), Capture: &c}
	return BindOperationLifecycle(in, a.Policy)
}

// This is a private exact lookup of an already atomically reserved capture pair.
// ReserveOperation itself is lookup-only for this purpose; no background queue.
type CaptureOperationJournal interface {
	ReserveOperation(context.Context, value.OperationIntent) (value.OperationSnapshot, error)
	FreezeOperationOutcome(context.Context, value.OperationOutcome) (value.OperationSnapshot, error)
	ClaimCaptureWrite(context.Context, value.OperationIntent, string) (value.CaptureWriteClaim, error)
	ReadCaptureOperation(context.Context, string) (value.OperationSnapshot, error)
	ClaimCaptureReconciliation(context.Context, value.OperationIntent, string) (value.CaptureReconciliationClaim, error)
}
type CaptureOperationAcknowledgements interface {
	OperationAcknowledgements
	OperationCompletions
	AcknowledgeCapturePair(context.Context, value.OperationIntent) error
	AcknowledgeReconciledCapture(context.Context, value.OperationIntent, string, value.Receipt, value.CaptureReconciliationClaim) error
}
type CaptureOperationReader interface {
	FindOperationIntent(context.Context, value.OperationIntent) (value.Receipt, error)
	FindOperationOutcome(context.Context, value.OperationOutcome) (value.Receipt, error)
}

// This is retained original provenance. OperationID is the explicit new-protocol
// binding, not authority or evidence that a collector started.
type CaptureOperationIntentSnapshot struct {
	Intent      value.CaptureIntent
	OperationID string
	Receipt     *value.Receipt
}
type CaptureOperationIntentReader interface {
	ReadCaptureOperationIntent(context.Context, string) (CaptureOperationIntentSnapshot, error)
}

// Publication continues only the original admitted audit obligation. It never
// invokes collection. An unknown PUT may recover receipt bytes, but only the
// original successful joined writer may supply a completion for later cleanup.
type CaptureOperationPublication struct {
	RootID           string
	Completed        CaptureOperationIntentReader
	Journal          CaptureOperationJournal
	Acknowledgements CaptureOperationAcknowledgements
	Writer           ClosedOperationObjects
	Reader           CaptureOperationReader
	MAC              *OperationMAC
	Now              func() time.Time
}

func (s CaptureOperationPublication) current(ctx context.Context, since, until time.Time) error {
	n := s.Now()
	if ctx.Err() != nil || n.Before(since) || !n.Before(until) {
		return ErrUnavailable
	}
	return nil
}
func (s CaptureOperationPublication) AcknowledgedCaptureIntent(ctx context.Context, captureID string) (value.CaptureIntent, error) {
	var zero value.CaptureIntent
	if ctx == nil || ctx.Err() != nil || s.Completed == nil || s.Now == nil || !authorization.UUID(s.RootID) || !authorization.UUID(captureID) {
		return zero, ErrUnavailable
	}
	// Observe the independently acknowledged accepted row before opening the
	// active write path. This read may outlive audit object retention but grants
	// no new collection/disclosure authority and performs no journal/object I/O.
	started := s.Now()
	until := started.Add(5 * time.Second)
	if parent, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, parent)
	}
	observed, endRead := context.WithDeadline(ctx, until)
	completed, err := s.Completed.ReadCaptureOperationIntent(observed, captureID)
	current := s.current(observed, started, until)
	endRead()
	if err != nil || current != nil || !completed.Intent.Valid() || completed.OperationID != captureID || completed.Intent.CaptureID != captureID || completed.Intent.RootID != s.RootID {
		return zero, ErrUnavailable
	}
	if completed.Receipt != nil {
		if !completed.Receipt.ValidOperation(s.RootID, captureID, "intent") {
			return zero, ErrUnavailable
		}
		return completed.Intent, nil
	}
	if s.Journal == nil || s.Acknowledgements == nil || s.Writer == nil || s.Reader == nil || s.MAC == nil {
		return zero, ErrUnavailable
	}
	snap, err := s.Journal.ReadCaptureOperation(ctx, captureID)
	in := snap.Intent
	if err != nil || !in.Valid() || in.Name != value.CaptureOperationName || in.ID != captureID || in.Capture == nil || !sameOperationRecord(*in.Capture, completed.Intent) || in.Lifecycle == nil || !value.CaptureOperationPolicy(in.Lifecycle.Policy) || in.MACVersion != s.MAC.Version() {
		return zero, ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, in.WriteUntil)
	defer end()
	if err = s.current(live, in.CreatedAt, in.WriteUntil); err != nil {
		return zero, err
	}
	if snap.IntentReceipt == nil {
		if err = s.phase(live, snap, "intent"); err != nil {
			return zero, err
		}
		snap, err = s.Journal.ReadCaptureOperation(live, captureID)
		if err != nil || !sameOperationRecord(snap.Intent, in) || snap.IntentReceipt == nil {
			return zero, ErrUnavailable
		}
	}
	if !snap.IntentReceipt.ValidOperation(in.RootID, in.ID, "intent") {
		return zero, ErrUnavailable
	}
	if snap.Outcome == nil {
		at := s.Now().UTC().Truncate(time.Microsecond)
		raw, err := json.Marshal(struct{ Format, CaptureID string }{"capture-intent-result/v1", in.ID})
		if err != nil {
			return zero, ErrUnavailable
		}
		d, err := s.MAC.Digest("capture-intent-result/v1", raw)
		clear(raw)
		if err != nil {
			return zero, ErrUnavailable
		}
		out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", CaptureIDs: []string{in.ID}, OutputDigest: d, MetadataUntil: in.RequestUntil, RecordedAt: at}
		if !out.Valid() {
			return zero, ErrUnavailable
		}
		snap, err = s.Journal.FreezeOperationOutcome(live, out)
		if err != nil || !sameOperationRecord(snap.Intent, in) || snap.Outcome == nil {
			return zero, ErrUnavailable
		}
	}
	if !snap.Outcome.Valid() || !sameOperationRecord(snap.Outcome.Intent, in) {
		return zero, ErrUnavailable
	}
	if snap.OutcomeReceipt == nil {
		if err = s.phase(live, snap, "outcome"); err != nil {
			return zero, err
		}
	} else if !snap.OutcomeReceipt.ValidOperation(in.RootID, in.ID, "outcome") {
		return zero, ErrUnavailable
	}
	if err = s.Acknowledgements.AcknowledgeCapturePair(live, in); err != nil {
		return zero, ErrUnavailable
	}
	if err = s.current(live, in.CreatedAt, in.WriteUntil); err != nil {
		return zero, err
	}
	return *in.Capture, nil
}
func (s CaptureOperationPublication) phase(ctx context.Context, snap value.OperationSnapshot, phase string) error {
	in := snap.Intent
	writeClaim, err := s.Journal.ClaimCaptureWrite(ctx, in, phase)
	if err != nil || !writeClaim.Valid() || writeClaim.Until.After(in.WriteUntil) {
		return ErrUnavailable
	}
	var receipt value.Receipt
	phaseCtx := ctx
	phaseUntil := in.WriteUntil
	var readClaim value.CaptureReconciliationClaim
	if writeClaim.Fresh {
		until := identity.Earlier(in.WriteUntil, writeClaim.Until)
		if phase == "intent" {
			until = identity.Earlier(until, in.RequestUntil)
		}
		live, end := context.WithDeadline(ctx, until)
		defer end()
		phaseCtx = live
		phaseUntil = until
		if err = s.current(live, in.CreatedAt, until); err != nil {
			return err
		}
		var c value.OperationWriteCompletion
		var record any = in
		if phase == "intent" {
			c, err = s.Writer.CreateClosedOperationIntent(live, in)
		} else {
			if snap.Outcome == nil {
				return ErrUnavailable
			}
			record = *snap.Outcome
			c, err = s.Writer.CreateClosedOperationOutcome(live, *snap.Outcome)
		}
		if err != nil || s.current(live, in.CreatedAt, until) != nil || !c.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, phase, in.CreatedAt, until) || c.RecordDigest != OperationLifecycleDigest(record) {
			return ErrUnavailable
		}
		if err = s.Acknowledgements.RecordOperationCompletion(live, in, phase, c); err != nil {
			return ErrUnavailable
		}
		receipt = c.Receipt
	} else {
		claim, err := s.Journal.ClaimCaptureReconciliation(ctx, in, phase)
		if err != nil || !claim.Valid() || claim.Until.After(in.WriteUntil) {
			return ErrUnavailable
		}
		readClaim = claim
		until := claim.Until
		live, end := context.WithDeadline(ctx, until)
		defer end()
		phaseCtx = live
		phaseUntil = until
		if err = s.current(live, in.CreatedAt, until); err != nil {
			return err
		}
		if phase == "intent" {
			receipt, err = s.Reader.FindOperationIntent(live, in)
		} else {
			if snap.Outcome == nil {
				return ErrUnavailable
			}
			receipt, err = s.Reader.FindOperationOutcome(live, *snap.Outcome)
		}
		if err != nil || s.current(live, in.CreatedAt, until) != nil {
			return ErrUnavailable
		}
	}
	if !receipt.ValidOperation(in.RootID, in.ID, phase) || s.current(phaseCtx, in.CreatedAt, phaseUntil) != nil {
		return ErrUnavailable
	}
	if readClaim.Valid() {
		err = s.Acknowledgements.AcknowledgeReconciledCapture(phaseCtx, in, phase, receipt, readClaim)
	} else {
		err = s.Acknowledgements.AcknowledgeOperation(phaseCtx, in, phase, receipt)
	}
	if err != nil || s.current(phaseCtx, in.CreatedAt, phaseUntil) != nil {
		return ErrUnavailable
	}
	return nil
}
