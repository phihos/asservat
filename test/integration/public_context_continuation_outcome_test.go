package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/presentation"
)

// Fixture-only observation of the ORIGINAL continuation. Its reply/error remain
// unchanged for the existing assertions. Monotonic times describe this Call,
// not SQL/identity expiry; completion is recorded before the channel send.
type publicJourneyContinuationOutcome struct {
	reply              presentation.OperationReply
	err                error
	started, completed time.Time
	callerDone         bool
}

func recordPublicJourneyContinuation(ctx context.Context, call func() (presentation.OperationReply, error)) publicJourneyContinuationOutcome {
	started := time.Now()
	reply, err := call()
	completed := time.Now()
	return publicJourneyContinuationOutcome{reply, err, started, completed, ctx.Err() != nil}
}

// Closed labels only. Never render arbitrary error strings, response fields,
// identifiers, evidence, tokens or deadlines. This is not a schema validator.
// retryLater marks the RetryLater reply of a session still preparing.
func (o publicJourneyContinuationOutcome) labels() (reason, status, state string, retryLater bool) {
	reason, status, state = journeyDownloadReasonName(journeyDownloadReason(o.err)), "unknown", "unknown"
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			State string `json:"state"`
			Code  string `json:"code"`
		} `json:"data"`
	}
	if len(o.reply.Body) > 64<<10 || json.Unmarshal(o.reply.Body, &envelope) != nil {
		return
	}
	switch envelope.Status {
	case "ok", "error":
		status = envelope.Status
	}
	if envelope.Data.State == "Ready" {
		state = envelope.Data.State
	}
	retryLater = envelope.Status == "error" && envelope.Data.Code == "RetryLater"
	return
}

func (o publicJourneyContinuationOutcome) report(t *testing.T, cleanupStarted time.Time) {
	t.Helper()
	reason, status, state, retryLater := o.labels()
	t.Logf("journey original continuation reason=%s reply-status=%s state=%s retry-later=%t caller-done-at-return=%t completed-before-cleanup=%t call-elapsed=%s cleanup-cancel-after=%s", reason, status, state, retryLater, o.callerDone, o.completed.Before(cleanupStarted), o.completed.Sub(o.started), cleanupStarted.Sub(o.started))
}

func TestPublicJourneyContinuationOutcomePreservesOriginalResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	want := presentation.OperationReply{Body: []byte(`{"status":"error","data":{"code":"RetryLater","message":"still preparing","retryable":true}}`), ValidUntil: time.Now().Add(time.Second)}
	cause := &journeyDownloadPrivateError{} // Error/Unwrap must never be called.
	calls := 0
	got := recordPublicJourneyContinuation(ctx, func() (presentation.OperationReply, error) {
		calls++
		return want, cause
	})
	if calls != 1 || got.err != cause || &got.reply.Body[0] != &want.Body[0] || got.reply.ValidUntil != want.ValidUntil || got.callerDone || got.completed.Before(got.started) {
		t.Fatal("original result, body ownership, call count or timing changed")
	}
	reason, status, state, retryLater := got.labels()
	if reason != "other" || status != "error" || state != "unknown" || !retryLater {
		t.Fatal("closed result classification differs")
	}
	got.reply.Body = []byte(`{"status":"ok","data":{"state":"Ready"}}`)
	if _, status, state, retryLater = got.labels(); status != "ok" || state != "Ready" || retryLater {
		t.Fatal("closed Ready classification differs")
	}
	for _, raw := range []string{`{"status":"secret","data":{"state":"secret"}}`, `{"status":`, strings.Repeat("secret", 12<<10)} {
		got.reply.Body = []byte(raw)
		_, status, state, _ = got.labels()
		if status != "unknown" || state != "unknown" {
			t.Fatal("unrecognized response content became diagnostic output")
		}
	}
}

func TestPublicJourneyContinuationOutcomeDistinguishesCleanupCancellation(t *testing.T) {
	for _, completeBeforeCleanup := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		entered, returned := make(chan struct{}), make(chan struct{})
		done := make(chan publicJourneyContinuationOutcome, 1)
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			out := recordPublicJourneyContinuation(ctx, func() (presentation.OperationReply, error) {
				close(entered)
				if !completeBeforeCleanup {
					<-ctx.Done()
					return presentation.OperationReply{}, ctx.Err()
				}
				return presentation.OperationReply{}, artifact.ErrDownloadUnavailable
			})
			close(returned) // Prove original completion before send/cleanup.
			done <- out
		}()
		<-entered
		if completeBeforeCleanup {
			<-returned
		}
		cleanupStarted := time.Now()
		cancel() // Same cancel-then-join order as the actual failure cleanup.
		out := <-done
		<-joined
		<-returned
		if out.completed.Before(cleanupStarted) != completeBeforeCleanup || out.callerDone == completeBeforeCleanup {
			t.Fatal("cleanup cancellation was attributed to the original call")
		}
		if completeBeforeCleanup && out.err != artifact.ErrDownloadUnavailable || !completeBeforeCleanup && out.err != context.Canceled {
			t.Fatal("original completion result changed")
		}
	}
}
