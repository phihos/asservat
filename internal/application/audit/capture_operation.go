package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// PrepareCaptureOperation is called inside admission after the exact original
// CaptureIntent has been reconstructed. It reserves nothing and grants no I/O.
func PrepareCaptureOperation(c value.CaptureIntent, a value.CaptureAuditAccount, mac *OperationMAC, requestUntil time.Time) (value.OperationIntent, error) {
	return prepareCaptureOperation(c, a, mac, requestUntil, nil)
}

// PrepareCaptureReasonOperation carries the frozen preview envelope opaquely.
// It performs no key opening or reason parsing during admission/publication.
func PrepareCaptureReasonOperation(c value.CaptureIntent, a value.CaptureAuditAccount, mac *OperationMAC, requestUntil time.Time, envelope value.CaptureReasonEnvelope) (value.OperationIntent, error) {
	return prepareCaptureOperation(c, a, mac, requestUntil, &envelope)
}
func prepareCaptureOperation(c value.CaptureIntent, a value.CaptureAuditAccount, mac *OperationMAC, requestUntil time.Time, envelope *value.CaptureReasonEnvelope) (value.OperationIntent, error) {
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
	format := value.CaptureOperationInputFormat
	if c.ReasonRef != nil {
		if envelope == nil || !CaptureReasonEnvelopeMatches(*c.ReasonRef, *envelope) {
			return value.OperationIntent{}, ErrUnavailable
		}
		format = value.CaptureReasonInputFormat
		ref := *c.ReasonRef
		c.ReasonRef = &ref
		owned := *envelope
		owned.KeyReference = append([]byte(nil), envelope.KeyReference...)
		owned.WrappedKey = append([]byte(nil), envelope.WrappedKey...)
		owned.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
		envelope = &owned
	} else if envelope != nil {
		return value.OperationIntent{}, ErrUnavailable
	}
	input, err := mac.Digest(format, raw)
	if err != nil {
		return value.OperationIntent{}, err
	}
	until := identity.Earlier(c.Deadline, c.CreatedAt.Add(30*time.Second))
	// Only the live caller bound is reduced to SQL precision. Never round up
	// an expiry or rewrite the already accepted capture's historical dates.
	requestUntil = identity.Earlier(requestUntil, identity.Earlier(c.CreatedAt.Add(5*time.Second), until)).UTC().Truncate(time.Microsecond)
	in := value.OperationIntent{ID: c.CaptureID, RootID: c.RootID, TraceID: c.OccurrenceID, Name: value.CaptureOperationName, InputFormat: format, ReasonEnvelope: envelope, MACVersion: mac.Version(), AccountVersion: a.AccountVersion, Actor: c.Requester(), PrincipalDigest: account, InputDigest: input, CreatedAt: c.CreatedAt, RequestUntil: requestUntil, WriteUntil: until, RetainUntil: c.CreatedAt.Add(time.Duration(a.RetainedSeconds) * time.Second), Capture: &c}
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

// CaptureOperationFailureStage exposes only this publisher's finite private
// diagnostic. It never copies a dependency's error text or arbitrary label.
func CaptureOperationFailureStage(err error) string {
	var failure *captureOperationFailure
	if errors.As(err, &failure) {
		return failure.stage
	}
	return "unavailable"
}

type captureOperationFailure struct{ stage string }

func (e *captureOperationFailure) Error() string     { return ErrUnavailable.Error() }
func (e *captureOperationFailure) Unwrap() error     { return ErrUnavailable }
func (e *captureOperationFailure) FixedStep() string { return e.stage }

func captureOperationStep(stage string, cause ...error) *captureOperationFailure {
	if len(cause) == 1 {
		if detail := captureOperationDependencyStep(cause[0]); detail != "" {
			stage += "/" + detail
		}
	}
	return &captureOperationFailure{stage}
}

func captureOperationCallStep(ctx context.Context, stage string, cause ...error) error {
	failure := captureOperationStep(stage, cause...)
	state := "live"
	until, bounded := ctx.Deadline()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || bounded && !time.Now().Before(until):
		state = "deadline"
	case ctx.Err() != nil:
		state = "canceled"
	}
	// Observe only the existing phase context, without creating work or a bound.
	failure.stage += "/" + state
	return failure
}

func captureOperationDependencyStep(err error) string {
	var named interface{ FixedStep() string }
	if !errors.As(err, &named) {
		return ""
	}
	head, tail, nested := strings.Cut(named.FixedStep(), "/")
	switch head {
	case "credentials", "credentials-configuration", "credentials-mounted", "credentials-verify", "credentials-final", "credentials-expired":
		// Provider-specific substeps are not part of this diagnostic contract.
		return head
	case "expired", "seal", "put", "read", "verify", "receipt", "completion":
		if !nested {
			return head
		}
	}
	if head == "put" || head == "read" {
		switch tail {
		case "http-400", "http-401", "http-403", "http-404", "http-405", "http-408", "http-409", "http-410",
			"http-412", "http-413", "http-415", "http-422", "http-425", "http-429",
			"http-500", "http-501", "http-502", "http-503", "http-504",
			"mismatch", "transport", "deadline", "unversioned":
			return head + "/" + tail
		}
	}
	return ""
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
		return zero, captureOperationStep("configuration")
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
	if err != nil {
		return zero, captureOperationStep("completed-read")
	}
	if current != nil || !completed.Intent.Valid() || completed.OperationID != captureID || completed.Intent.CaptureID != captureID || completed.Intent.RootID != s.RootID {
		return zero, captureOperationStep("completed-record")
	}
	if completed.Receipt != nil {
		if !completed.Receipt.ValidOperation(s.RootID, captureID, "intent") {
			return zero, captureOperationStep("completed-receipt")
		}
		return completed.Intent, nil
	}
	if s.Journal == nil || s.Acknowledgements == nil || s.Writer == nil || s.Reader == nil || s.MAC == nil {
		return zero, captureOperationStep("configuration")
	}
	snap, err := s.Journal.ReadCaptureOperation(ctx, captureID)
	in := snap.Intent
	if err != nil {
		return zero, captureOperationStep("journal-read")
	}
	if !in.Valid() || in.Name != value.CaptureOperationName || in.ID != captureID || in.Capture == nil || !sameOperationRecord(*in.Capture, completed.Intent) || in.Lifecycle == nil || !value.CaptureOperationPolicy(in.Lifecycle.Policy) || in.MACVersion != s.MAC.Version() {
		return zero, captureOperationStep("journal-record")
	}
	live, end := context.WithDeadline(ctx, in.WriteUntil)
	defer end()
	if err = s.current(live, in.CreatedAt, in.WriteUntil); err != nil {
		return zero, captureOperationStep("journal-current")
	}
	if snap.IntentReceipt == nil {
		if err = s.phase(live, snap, "intent"); err != nil {
			return zero, err
		}
		snap, err = s.Journal.ReadCaptureOperation(live, captureID)
		if err != nil || !sameOperationRecord(snap.Intent, in) || snap.IntentReceipt == nil {
			return zero, captureOperationStep("intent-readback")
		}
	}
	if !snap.IntentReceipt.ValidOperation(in.RootID, in.ID, "intent") {
		return zero, captureOperationStep("intent-receipt")
	}
	if snap.Outcome == nil {
		at := s.Now().UTC().Truncate(time.Microsecond)
		raw, err := json.Marshal(struct{ Format, CaptureID string }{"capture-intent-result/v1", in.ID})
		if err != nil {
			return zero, captureOperationStep("outcome-record")
		}
		d, err := s.MAC.Digest("capture-intent-result/v1", raw)
		clear(raw)
		if err != nil {
			return zero, captureOperationStep("outcome-record")
		}
		out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", CaptureIDs: []string{in.ID}, OutputDigest: d, MetadataUntil: in.RequestUntil, RecordedAt: at}
		if !out.Valid() {
			return zero, captureOperationStep("outcome-record")
		}
		snap, err = s.Journal.FreezeOperationOutcome(live, out)
		if err != nil || !sameOperationRecord(snap.Intent, in) || snap.Outcome == nil {
			return zero, captureOperationStep("outcome-freeze")
		}
	}
	if !snap.Outcome.Valid() || !sameOperationRecord(snap.Outcome.Intent, in) {
		return zero, captureOperationStep("outcome-record")
	}
	if snap.OutcomeReceipt == nil {
		if err = s.phase(live, snap, "outcome"); err != nil {
			return zero, err
		}
	} else if !snap.OutcomeReceipt.ValidOperation(in.RootID, in.ID, "outcome") {
		return zero, captureOperationStep("outcome-receipt")
	}
	if err = s.Acknowledgements.AcknowledgeCapturePair(live, in); err != nil {
		return zero, captureOperationStep("pair-acknowledge")
	}
	if err = s.current(live, in.CreatedAt, in.WriteUntil); err != nil {
		return zero, captureOperationStep("pair-current")
	}
	return *in.Capture, nil
}
func (s CaptureOperationPublication) phase(ctx context.Context, snap value.OperationSnapshot, phase string) error {
	in := snap.Intent
	writeClaim, err := s.Journal.ClaimCaptureWrite(ctx, in, phase)
	if err != nil || !writeClaim.Valid() || writeClaim.Until.After(in.WriteUntil) {
		return captureOperationStep(phase + "/claim")
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
			return captureOperationStep(phase + "/current")
		}
		var c value.OperationWriteCompletion
		var record any = in
		if phase == "intent" {
			c, err = s.Writer.CreateClosedOperationIntent(live, in)
		} else {
			if snap.Outcome == nil {
				return captureOperationStep(phase + "/record")
			}
			record = *snap.Outcome
			c, err = s.Writer.CreateClosedOperationOutcome(live, *snap.Outcome)
		}
		if err != nil {
			return captureOperationCallStep(live, phase+"/write", err)
		}
		if s.current(live, in.CreatedAt, until) != nil || !c.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, phase, in.CreatedAt, until) || c.RecordDigest != OperationLifecycleDigest(record) {
			return captureOperationCallStep(live, phase+"/write-completion")
		}
		if err = s.Acknowledgements.RecordOperationCompletion(live, in, phase, c); err != nil {
			return captureOperationStep(phase + "/completion")
		}
		receipt = c.Receipt
	} else {
		claim, err := s.Journal.ClaimCaptureReconciliation(ctx, in, phase)
		if err != nil || !claim.Valid() || claim.Until.After(in.WriteUntil) {
			return captureOperationStep(phase + "/reconcile-claim")
		}
		readClaim = claim
		until := claim.Until
		live, end := context.WithDeadline(ctx, until)
		defer end()
		phaseCtx = live
		phaseUntil = until
		if err = s.current(live, in.CreatedAt, until); err != nil {
			return captureOperationStep(phase + "/reconcile-current")
		}
		if phase == "intent" {
			receipt, err = s.Reader.FindOperationIntent(live, in)
		} else {
			if snap.Outcome == nil {
				return captureOperationStep(phase + "/record")
			}
			receipt, err = s.Reader.FindOperationOutcome(live, *snap.Outcome)
		}
		if err != nil {
			return captureOperationCallStep(live, phase+"/reconcile-read", err)
		}
		if s.current(live, in.CreatedAt, until) != nil {
			return captureOperationStep(phase + "/reconcile-current")
		}
	}
	if !receipt.ValidOperation(in.RootID, in.ID, phase) || s.current(phaseCtx, in.CreatedAt, phaseUntil) != nil {
		return captureOperationStep(phase + "/receipt")
	}
	if readClaim.Valid() {
		err = s.Acknowledgements.AcknowledgeReconciledCapture(phaseCtx, in, phase, receipt, readClaim)
	} else {
		err = s.Acknowledgements.AcknowledgeOperation(phaseCtx, in, phase, receipt)
	}
	if err != nil || s.current(phaseCtx, in.CreatedAt, phaseUntil) != nil {
		return captureOperationStep(phase + "/acknowledge")
	}
	return nil
}
