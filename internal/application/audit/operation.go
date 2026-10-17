package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"context"
	"encoding/json"
	"time"
)

// OperationJournal freezes minimized records and irreversibly claims one create
// per phase. False means lookup only; uncertain claims NEVER permit a new PUT.
// Its credentials cannot acknowledge encrypted object receipts.
type OperationJournal interface {
	ReserveOperation(context.Context, value.OperationIntent) (value.OperationSnapshot, error)
	ClaimOperationWrite(context.Context, value.OperationIntent, string) (bool, error)
	FreezeOperationOutcome(context.Context, value.OperationOutcome) (value.OperationSnapshot, error)
}
type OperationAcknowledgements interface {
	AcknowledgeOperation(context.Context, value.OperationIntent, string, value.Receipt) error
}
type OperationObjects interface {
	CreateOperationIntent(context.Context, value.OperationIntent) (value.Receipt, error)
	FindOperationIntent(context.Context, value.OperationIntent) (value.Receipt, error)
	CreateOperationOutcome(context.Context, value.OperationOutcome) (value.Receipt, error)
	FindOperationOutcome(context.Context, value.OperationOutcome) (value.Receipt, error)
}
type OperationAuditor struct {
	Journal          OperationJournal
	Acknowledgements OperationAcknowledgements
	Objects          OperationObjects
	Now              func() time.Time
}

func (s OperationAuditor) configured() bool {
	return s.Journal != nil && s.Acknowledgements != nil && s.Objects != nil && s.Now != nil
}
func (s OperationAuditor) Begin(ctx context.Context, in value.OperationIntent) error {
	if !s.configured() || ctx == nil || ctx.Err() != nil || !in.Valid() || !s.Now().Before(in.RequestUntil) {
		return ErrUnavailable
	}
	snap, err := s.Journal.ReserveOperation(ctx, in)
	if err != nil {
		return ErrUnavailable
	}
	if !sameOperationRecord(snap.Intent, in) || snap.Outcome != nil {
		return ErrUnavailable
	}
	if snap.IntentReceipt != nil {
		if !snap.IntentReceipt.ValidOperation(in.RootID, in.ID, "intent") {
			return ErrUnavailable
		}
		return s.current(ctx, in.RequestUntil)
	}
	fresh, err := s.Journal.ClaimOperationWrite(ctx, in, "intent")
	if err != nil {
		return ErrUnavailable
	}
	var receipt value.Receipt
	if fresh {
		receipt, err = s.Objects.CreateOperationIntent(ctx, in)
	} else {
		receipt, err = s.Objects.FindOperationIntent(ctx, in)
	}
	if err != nil || !receipt.ValidOperation(in.RootID, in.ID, "intent") {
		return ErrUnavailable
	}
	if err = s.Acknowledgements.AcknowledgeOperation(ctx, in, "intent", receipt); err != nil {
		return ErrUnavailable
	}
	return s.current(ctx, in.RequestUntil)
}
func (s OperationAuditor) Finish(ctx context.Context, out value.OperationOutcome) error {
	if !s.configured() || ctx == nil || ctx.Err() != nil || !out.Valid() || !s.Now().Before(out.Intent.WriteUntil) {
		return ErrUnavailable
	}
	snap, err := s.Journal.FreezeOperationOutcome(ctx, out)
	if err != nil || snap.Outcome == nil || snap.IntentReceipt == nil || !sameOperationRecord(snap.Intent, out.Intent) || !sameOperationRecord(*snap.Outcome, out) {
		return ErrUnavailable
	}
	if snap.OutcomeReceipt != nil {
		if !snap.OutcomeReceipt.ValidOperation(out.Intent.RootID, out.Intent.ID, "outcome") {
			return ErrUnavailable
		}
		return s.current(ctx, out.Intent.WriteUntil)
	}
	fresh, err := s.Journal.ClaimOperationWrite(ctx, out.Intent, "outcome")
	if err != nil {
		return ErrUnavailable
	}
	var receipt value.Receipt
	if fresh {
		receipt, err = s.Objects.CreateOperationOutcome(ctx, *snap.Outcome)
	} else {
		receipt, err = s.Objects.FindOperationOutcome(ctx, *snap.Outcome)
	}
	if err != nil || !receipt.ValidOperation(out.Intent.RootID, out.Intent.ID, "outcome") {
		return ErrUnavailable
	}
	if err = s.Acknowledgements.AcknowledgeOperation(ctx, out.Intent, "outcome", receipt); err != nil {
		return ErrUnavailable
	}
	return s.current(ctx, out.Intent.WriteUntil)
}
func (s OperationAuditor) current(ctx context.Context, until time.Time) error {
	if ctx.Err() != nil || !s.Now().Before(until) {
		return ErrUnavailable
	}
	return nil
}

func sameOperationRecord(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}
