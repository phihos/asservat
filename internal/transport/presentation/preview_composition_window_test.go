package presentation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type previewWindowResolver func(context.Context, string) (identity.Identity, error)

func (f previewWindowResolver) Resolve(ctx context.Context, token string) (identity.Identity, error) {
	return f(ctx, token)
}

type stagedRepeatHistory struct {
	*historyFixture
	clock           *time.Time
	afterHistory    func()
	slowObservation bool
}

func (h *stagedRepeatHistory) PreviewRepeat(ctx context.Context, current identities.CurrentIdentity, id string, sharing *value.ContextSharing) (app.ContextPreviewResult, value.CaptureSettings, error) {
	// Synthetic regional adapters model the observed sequential history, target
	// and recorder work. The production audit and request identity own the outer
	// window; each adapter retains its original five-second observation cap.
	for index, cost := range []time.Duration{3 * time.Second, 2 * time.Second, time.Second} {
		until := h.clock.Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
		if h.slowObservation && index == 0 {
			cost = 6 * time.Second
		}
		*h.clock = h.clock.Add(cost)
		if !h.clock.Before(until) {
			return app.ContextPreviewResult{}, value.CaptureSettings{}, identity.ErrDenied
		}
		if index == 0 && h.afterHistory != nil {
			h.afterHistory()
		}
		if _, err := current.ResolveIdentity(ctx); err != nil {
			return app.ContextPreviewResult{}, value.CaptureSettings{}, err
		}
	}
	result, settings, err := h.historyFixture.PreviewRepeat(ctx, current, id, sharing)
	// The assessment is created after these observations, as in production.
	result.Assessment.GeneratedAt = *h.clock
	result.Assessment.ValidUntil = h.clock.Add(5 * time.Second)
	return result, settings, err
}

func TestRepeatPreviewComposesObservationsWithoutRenewingIdentity(t *testing.T) {
	for _, mode := range []string{"success", "initial-expiry", "identity-change", "owner-cancelled", "observation-expiry"} {
		t.Run(mode, func(t *testing.T) {
			base, f, h := historyOperations(t)
			audited, _, gate := auditedFixture(t)
			start := time.Now().UTC().Truncate(time.Microsecond)
			f.i.VerifiedAt = start
			f.i.ValidUntil = start.Add(time.Minute)
			h.accepted = start.Add(-time.Hour)
			h.untilList = start.Add(time.Minute)
			now := start
			clock := func() time.Time { return now }
			base.config.Now = clock
			audited.config.Now = clock
			f.metadataUntil = start.Add(time.Minute)
			owner, cancel := context.WithCancel(t.Context())
			defer cancel()
			changed := false
			resolver := previewWindowResolver(func(ctx context.Context, _ string) (identity.Identity, error) {
				i := f.i
				i.VerifiedAt = now
				i.ValidUntil = start.Add(time.Minute)
				if mode == "initial-expiry" {
					i.ValidUntil = start.Add(4 * time.Second)
				}
				if changed {
					i.Groups = []string{"different-team"}
				}
				return i, ctx.Err()
			})
			current, _, err := identities.NewBearerRequestWithin(owner, resolver, "synthetic", clock, identity.CapturePreviewRequestWindow)
			if err != nil {
				t.Fatal(err)
			}
			staged := &stagedRepeatHistory{historyFixture: h, clock: &now, slowObservation: mode == "observation-expiry"}
			staged.afterHistory = func() {
				if mode == "identity-change" {
					changed = true
				}
				if mode == "owner-cancelled" {
					cancel()
				}
			}
			base.history = staged
			combined, err := NewInvestigationOperations(base, nil)
			if err != nil {
				t.Fatal(err)
			}
			audited.inner = combined
			reply, err := audited.Call(owner, current, "preview_capture", []byte(`{"history_capture_id":"`+historyCapture+`"}`))
			if mode == "success" {
				if err != nil || len(reply.Body) == 0 {
					t.Fatalf("six-second composition refused: %v elapsed=%v", err, now.Sub(start))
				}
				if len(gate.intents) != 1 || !gate.intents[0].RequestUntil.Equal(start.Add(identity.CapturePreviewRequestWindow)) {
					t.Fatal("wrong outer composition bound", gate.intents)
				}
			} else if err == nil {
				var out OperationEnvelope
				if json.Unmarshal(reply.Body, &out) != nil || out.Status == "ok" {
					t.Fatalf("expired/changed authority delivered: %s", reply.Body)
				}
			} else if len(reply.Body) != 0 {
				t.Fatal("failed identity returned a body")
			}

		})
	}
}
