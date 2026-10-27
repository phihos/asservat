package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
)

type timingPreview struct {
	*contextOperationFixture
	expire bool
	calls  int
}

func (f *timingPreview) Preview(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent) (captureapp.ContextPreviewResult, error) {
	f.calls++
	started := time.Now()
	if f.expire {
		<-ctx.Done()
	}
	// The existing recorder is bounded to 64 fixed private stage marks.
	for range 65 {
		auditapp.MarkStep(ctx, "p-target", started)
	}
	return f.contextOperationFixture.Preview(ctx, source, intent)
}

func TestAuditedFailureTimingPrecedesBlockedFinish(t *testing.T) {
	for _, mode := range []string{"service-error", "expired-operation", "success"} {
		t.Run(mode, func(t *testing.T) {
			s, f, gate := auditedFixture(t)
			preview := &timingPreview{contextOperationFixture: f, expire: mode == "expired-operation"}
			s.inner.(*InvestigationOperations).captures.captures = preview
			if mode == "service-error" {
				f.err = errors.New("private provider error must not enter timing")
			}
			ctx := t.Context()
			if preview.expire {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var unblock sync.Once
			gate.onFinish = func() { close(entered); <-release }
			type sample struct{ event, line string }
			samples := make(chan sample, 3)
			s.Timing = func(event, line string) { samples <- sample{event, line} }
			name, input := "preview_capture", wirePreview
			if mode == "success" {
				name, input = "request_capture", wireRequest
			}
			var reply OperationReply
			var callErr error
			go func() { defer close(done); reply, callErr = s.Call(ctx, f, name, []byte(input)) }()
			t.Cleanup(func() {
				unblock.Do(func() { close(release) })
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("audit call failed to join after finish release")
				}
			})
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("finish not reached")
			}
			early := mode != "success"
			select {
			case got := <-samples:
				if !early || got.event != "normal/service-failed" || !strings.Contains(got.line, " call@") || !strings.Contains(got.line, "p-target@") || strings.Contains(got.line, "finish") || strings.Contains(got.line, "private") || strings.Contains(got.line, "api") || len(got.line) > 2048 || strings.Count(got.line, "p-target@") != 64 {
					t.Fatal("unbounded, late or unexpected failure timing", got)
				}
			default:
				if early {
					t.Fatal("failure timing unavailable while Finish is blocked")
				}
			}
			select {
			case <-done:
				t.Fatal("timing changed blocked Finish flow")
			default:
			}
			unblock.Do(func() { close(release) })
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("call did not join Finish")
			}
			final := <-samples
			if final.event != "normal" || !strings.Contains(final.line, " finish@") {
				t.Fatal("original final timing lost", final)
			}
			select {
			case extra := <-samples:
				t.Fatal("duplicate timing", extra)
			default:
			}
			if preview.calls+f.requests != 1 || len(gate.intents) != 1 || len(gate.outcomes) != 1 {
				t.Fatal("diagnostic redispatched service or audit", preview.calls, len(gate.intents), len(gate.outcomes))
			}
			if preview.expire {
				if callErr == nil {
					t.Fatal("expired operation result changed", callErr, gate.outcomes[0].Status)
				}
				return
			}
			var envelope OperationEnvelope
			if callErr != nil || json.Unmarshal(reply.Body, &envelope) != nil || (mode == "success" && envelope.Status != "ok") || (mode == "service-error" && envelope.Status != "error") {
				t.Fatal("timing changed public result", callErr, envelope.Status)
			}
		})
	}
}
