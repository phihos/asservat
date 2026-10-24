package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
)

type captureDiagnosticError string

func (e captureDiagnosticError) Error() string     { return "private-provider-detail" }
func (e captureDiagnosticError) FixedStep() string { return string(e) }

type captureDiagnosticObjects struct {
	ClosedOperationObjects
	CaptureOperationReader
	createErr, findErr error
	creates, finds     int
	until              time.Time
	t                  *testing.T
	afterCreate        func(context.Context)
}

func (o *captureDiagnosticObjects) check(ctx context.Context) {
	o.t.Helper()
	if until, ok := ctx.Deadline(); !ok || until.After(o.until) {
		o.t.Fatal("diagnostic changed the original caller deadline", until, o.until)
	}
}
func (o *captureDiagnosticObjects) CreateClosedOperationIntent(ctx context.Context, _ value.OperationIntent) (value.OperationWriteCompletion, error) {
	o.check(ctx)
	o.creates++
	if o.afterCreate != nil {
		o.afterCreate(ctx)
	}
	return value.OperationWriteCompletion{}, o.createErr
}
func (o *captureDiagnosticObjects) FindOperationIntent(ctx context.Context, _ value.OperationIntent) (value.Receipt, error) {
	o.check(ctx)
	o.finds++
	return value.Receipt{}, o.findErr
}

func captureDiagnosticStage(t *testing.T, err error, want string) {
	t.Helper()
	var step interface{ FixedStep() string }
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &step) || step.FixedStep() != want ||
		CaptureOperationFailureStage(err) != want || strings.Contains(err.Error(), "private") {
		t.Fatalf("closed stage lost: want=%q err=%v step=%v", want, err, step)
	}
}

// A refused first writer keeps its claim spent. Diagnostics must distinguish
// that refusal from the two finite missing-object reads without repairing it.
func TestCaptureOperationDiagnosticKeepsPartialClaimAndFiniteReconciliation(t *testing.T) {
	s, f, in := capturePublisher(t)
	until := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	objects := &captureDiagnosticObjects{ClosedOperationObjects: f, CaptureOperationReader: f,
		createErr: captureDiagnosticError("put/http-403"), findErr: captureDiagnosticError("read/http-404"), until: until, t: t}
	s.Writer, s.Reader = objects, objects
	for _, want := range []string{"intent/write/put/http-403/live", "intent/reconcile-read/read/http-404/live", "intent/reconcile-read/read/http-404/live", "intent/reconcile-claim"} {
		_, err := s.AcknowledgedCaptureIntent(ctx, in.ID)
		captureDiagnosticStage(t, err, want)
	}
	if objects.creates != 1 || objects.finds != 2 || !f.snap.IntentStarted || f.reads["intent"] != 2 || f.acks != 0 || f.paired != 0 || len(f.saved) != 0 {
		t.Fatal("diagnostics changed partial claim or finite reconciliation", objects.creates, objects.finds, f.reads, f.acks, f.paired)
	}
}

func TestCaptureOperationDiagnosticUsesOnlyClosedDependencyLabels(t *testing.T) {
	for _, detail := range []string{"credentials-expired", "credentials-verify", "seal", "put/http-503", "private-provider-detail", "put/http-403/private-provider-detail", "put/http-999"} {
		t.Run(detail, func(t *testing.T) {
			s, f, in := capturePublisher(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			objects := &captureDiagnosticObjects{ClosedOperationObjects: f, CaptureOperationReader: f,
				createErr: captureDiagnosticError(detail), until: until, t: t}
			s.Writer = objects
			want := "intent/write"
			switch detail {
			case "credentials-expired", "credentials-verify", "seal", "put/http-503":
				want += "/" + detail
			}
			want += "/live"
			_, err := s.AcknowledgedCaptureIntent(ctx, in.ID)
			captureDiagnosticStage(t, err, want)
			if objects.creates != 1 || f.acks != 0 || f.paired != 0 {
				t.Fatal("diagnostic added effects")
			}
		})
	}
	if CaptureOperationFailureStage(captureDiagnosticError("seal")) != "unavailable" {
		t.Fatal("untrusted error supplied the publication stage")
	}
}

func TestCaptureOperationDiagnosticObservesOriginalCallState(t *testing.T) {
	for _, state := range []string{"canceled", "deadline"} {
		t.Run(state, func(t *testing.T) {
			s, f, in := capturePublisher(t)
			timeout := time.Second
			if state == "deadline" {
				timeout = 30 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			until, _ := ctx.Deadline()
			objects := &captureDiagnosticObjects{ClosedOperationObjects: f, CaptureOperationReader: f,
				createErr: captureDiagnosticError("seal"), until: until, t: t,
				afterCreate: func(call context.Context) {
					if state == "canceled" {
						cancel()
					}
					<-call.Done()
				}}
			s.Writer = objects
			_, err := s.AcknowledgedCaptureIntent(ctx, in.ID)
			captureDiagnosticStage(t, err, "intent/write/seal/"+state)
			if objects.creates != 1 || objects.finds != 0 || f.acks != 0 || f.paired != 0 || !f.snap.IntentStarted {
				t.Fatal("call-state diagnostic changed effects")
			}
		})
	}
}
