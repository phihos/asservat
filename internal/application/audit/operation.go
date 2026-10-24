package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
		return operationStep("start")
	}
	started := time.Now()
	snap, err := s.Journal.ReserveOperation(ctx, in)
	MarkStep(ctx, "begin-reserve", started)
	if err != nil {
		return operationStep("reserve")
	}
	if !sameOperationRecord(snap.Intent, in) || snap.Outcome != nil {
		return operationStep("record")
	}
	if snap.IntentReceipt != nil {
		if !snap.IntentReceipt.ValidOperation(in.RootID, in.ID, "intent") {
			return operationStep("receipt")
		}
		return s.current(ctx, in.RequestUntil)
	}
	started = time.Now()
	fresh, err := s.Journal.ClaimOperationWrite(ctx, in, "intent")
	MarkStep(ctx, "begin-claim", started)
	if err != nil {
		return operationStep("claim")
	}
	var receipt value.Receipt
	started = time.Now()
	if fresh {
		receipt, err = s.Objects.CreateOperationIntent(ctx, in)
	} else {
		receipt, err = s.Objects.FindOperationIntent(ctx, in)
	}
	MarkStep(ctx, "begin-object", started)
	if err != nil || !receipt.ValidOperation(in.RootID, in.ID, "intent") {
		return operationStep("object", err)
	}
	started = time.Now()
	err = s.Acknowledgements.AcknowledgeOperation(ctx, in, "intent", receipt)
	MarkStep(ctx, "begin-ack", started)
	if err != nil {
		return operationStep("acknowledge")
	}
	return s.current(ctx, in.RequestUntil)
}
func (s OperationAuditor) Finish(ctx context.Context, out value.OperationOutcome) error {
	if !s.configured() || ctx == nil || ctx.Err() != nil || !out.Valid() || !s.Now().Before(out.Intent.WriteUntil) {
		return operationStep("start")
	}
	started := time.Now()
	snap, err := s.Journal.FreezeOperationOutcome(ctx, out)
	MarkStep(ctx, "finish-freeze", started)
	if err != nil || snap.Outcome == nil || snap.IntentReceipt == nil || !sameOperationRecord(snap.Intent, out.Intent) || !sameOperationRecord(*snap.Outcome, out) {
		return operationStep("freeze")
	}
	if snap.OutcomeReceipt != nil {
		if !snap.OutcomeReceipt.ValidOperation(out.Intent.RootID, out.Intent.ID, "outcome") {
			return operationStep("receipt")
		}
		return s.current(ctx, out.Intent.WriteUntil)
	}
	started = time.Now()
	fresh, err := s.Journal.ClaimOperationWrite(ctx, out.Intent, "outcome")
	MarkStep(ctx, "finish-claim", started)
	if err != nil {
		return operationStep("claim")
	}
	var receipt value.Receipt
	started = time.Now()
	if fresh {
		receipt, err = s.Objects.CreateOperationOutcome(ctx, *snap.Outcome)
	} else {
		receipt, err = s.Objects.FindOperationOutcome(ctx, *snap.Outcome)
	}
	MarkStep(ctx, "finish-object", started)
	if err != nil || !receipt.ValidOperation(out.Intent.RootID, out.Intent.ID, "outcome") {
		return operationStep("object", err)
	}
	started = time.Now()
	err = s.Acknowledgements.AcknowledgeOperation(ctx, out.Intent, "outcome", receipt)
	MarkStep(ctx, "finish-ack", started)
	if err != nil {
		return operationStep("acknowledge")
	}
	return s.current(ctx, out.Intent.WriteUntil)
}
func (s OperationAuditor) current(ctx context.Context, until time.Time) error {
	if ctx.Err() != nil || !s.Now().Before(until) {
		return operationStep("expired")
	}
	return nil
}

// operationStepError is ErrUnavailable with the closed step where an
// operation audit stopped, and the inner error's own step when it has one
// (for example the object store's seal or put).
type operationStepError struct {
	step  string
	inner error
}

func operationStep(step string, inner ...error) error {
	e := &operationStepError{step: step}
	if len(inner) == 1 {
		e.inner = inner[0]
	}
	return e
}
func (e *operationStepError) Error() string { return ErrUnavailable.Error() }
func (e *operationStepError) Unwrap() error { return ErrUnavailable }
func (e *operationStepError) FixedStep() string {
	var nested interface{ FixedStep() string }
	if e.inner != nil && errors.As(e.inner, &nested) {
		return e.step + "/" + nested.FixedStep()
	}
	return e.step
}

func sameOperationRecord(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}
