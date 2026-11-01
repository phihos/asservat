package capture

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type overlapGrants struct {
	*fakeGrants
	demanded <-chan struct{}
	refusal  error
	after    func(context.Context)
}

func (g overlapGrants) Covering(ctx context.Context, current identities.CurrentIdentity, capture string, digest artifact.Digest, target authorization.Target) (authorization.Grant, time.Time, error) {
	select {
	case <-ctx.Done():
		return authorization.Grant{}, time.Time{}, ctx.Err()
	case <-g.demanded:
	}
	if g.after != nil {
		g.after(ctx)
	}
	if g.refusal != nil {
		return g.grant, time.Time{}, g.refusal
	}
	return g.fakeGrants.Covering(ctx, current, capture, digest, target)
}

func recordingOverlapFixture(t *testing.T) (*retainedRecording, value.ContextPreview, *fakeGrants) {
	t.Helper()
	base := newInvestigationFixture()
	f := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	base.svc.Previews, base.svc.Admission, base.svc.Recorders = f, f, availableRecording{base}
	policy := identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}
	base.svc.Approvals = fixedApprovalSettings{policy: policy}
	grants := &fakeGrants{}
	base.svc.Grants = grants
	preview, err := base.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(networkComposition()))
	if err != nil || !preview.Recordable {
		t.Fatal("preview", err)
	}
	p := preview.Preview
	if _, err = f.request(t, p, "review"); !errors.Is(err, authorization.ErrApprovalRequired) {
		t.Fatal("review", err)
	}
	grants.covering = nil
	grants.grant.ExpiresAt = f.now.Add(90 * time.Second)
	return f, p, grants
}

// The channel dependency is test-induced: it proves scheduling, not actual
// installed grant latency or the cause of a historical native refusal. No sleeps.
func TestRecordingStorageHintOverlapsGrantBeforeFreshConsumption(t *testing.T) {
	for _, mode := range []string{"current", "expired-approved", "pending", "denied", "grant-error", "original-cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, p, grants := recordingOverlapFixture(t)
			if mode == "expired-approved" {
				p.CreatedAt = p.CreatedAt.Add(-10 * time.Minute)
				p.Deadline = p.Deadline.Add(-10 * time.Minute)
				f.previews[p.ID] = p.Clone()
				if p.Current(f.now) || !ValidContextPreview(p) {
					t.Fatal("invalid expired fixture")
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			original, _ := ctx.Deadline()
			demanded, joined := make(chan struct{}), make(chan struct{})
			var fresh atomic.Bool
			var demands atomic.Int32
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				out, err := f.ContextStorage(ctx, target)
				if !fresh.Load() {
					out.Binding.ObservedAt = f.now.Add(-31 * time.Second)
					out.Binding.FreshUntil = f.now.Add(-time.Second)
					return out, value.ErrStorageBindingExpired
				}
				return out, err
			})
			refuse := mode == "pending" || mode == "denied" || mode == "grant-error" || mode == "original-cancel"
			f.svc.Refresh = consumptionRefreshFunc(func(call context.Context, _ targets.Request) error {
				if demands.Add(1) != 1 {
					t.Error("second demand")
				}
				if end, _ := call.Deadline(); end.After(original) {
					t.Error("hint extended original request")
				}
				fresh.Store(true)
				close(demanded)
				if refuse {
					<-call.Done()
				}
				close(joined)
				return nil
			})
			gate := overlapGrants{fakeGrants: grants, demanded: demanded, after: func(call context.Context) {
				if end, _ := call.Deadline(); !end.Equal(original) {
					t.Error("grant received renewed request deadline")
				}
				if mode == "original-cancel" {
					cancel()
				}
			}}
			switch mode {
			case "pending":
				gate.refusal = authorization.ApprovalPendingError{GrantID: grants.grant.ID}
			case "denied":
				gate.refusal = authorization.ErrGrantDenied
			case "grant-error":
				gate.refusal = value.ErrUnavailable
			}
			f.svc.Grants = gate
			_, err := f.svc.Request(ctx, f.source(t, ctx), p.ID, "start")
			if demands.Load() != 1 {
				t.Fatal("grant waited without the single original demand", err, demands.Load())
			}
			select {
			case <-joined:
			default:
				t.Fatal("request returned with hint still running")
			}
			if !refuse {
				if !errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 {
					t.Fatal("overlapped grant did not reach admission", err)
				}
				if !f.seen[0].Plan.Input.Deadline.Equal(grants.grant.ExpiresAt) {
					t.Fatal("grant deadline changed")
				}
			} else if err == nil || len(f.seen) != 0 {
				t.Fatal("unavailable approval admitted", err)
			}
		})
	}
}

func TestRecordingStorageHintRetainsOriginalConsumptionBounds(t *testing.T) {
	for _, mode := range []string{"request", "identity", "recovery", "grant"} {
		t.Run(mode, func(t *testing.T) {
			f, p, grants := recordingOverlapFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			bound, _ := ctx.Deadline()
			source := f.source(t, ctx)
			if mode != "request" {
				bound = f.now.Add(1400 * time.Millisecond)
			}
			switch mode {
			case "identity":
				source = &shortenedContinuationIdentity{source: source, until: bound}
			case "recovery":
				f.svc.Recovery = consumptionRecovery{f.investigationFixture, bound}
			case "grant":
				grants.grant.ExpiresAt = bound
			}
			demanded := make(chan struct{})
			var fresh atomic.Bool
			var demands atomic.Int32
			var lastDeadline atomic.Value
			f.svc.Storage = consumptionStorageFunc(func(call context.Context, target authorization.Target) (ContextStorageObservation, error) {
				end, _ := call.Deadline()
				lastDeadline.Store(end)
				out, err := f.ContextStorage(call, target)
				if !fresh.Load() {
					out.Binding.ObservedAt = f.now.Add(-31 * time.Second)
					out.Binding.FreshUntil = f.now.Add(-time.Second)
					return out, value.ErrStorageBindingExpired
				}
				return out, err
			})
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error {
				demands.Add(1)
				fresh.Store(true)
				close(demanded)
				return nil
			})
			f.svc.Grants = overlapGrants{fakeGrants: grants, demanded: demanded}
			_, err := f.svc.Request(ctx, source, p.ID, "bounded")
			if demands.Load() != 1 || lastDeadline.Load() == nil {
				t.Fatal("bounded overlap omitted its original readiness owner", err, demands.Load())
			}
			if mode == "request" {
				if !errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 {
					t.Fatal("original request did not reach admission", err)
				}
			} else if err == nil || len(f.seen) != 0 {
				// These shorter original facts cannot fit the recording. Keeping
				// them short must refuse, never renew them to make it admissible.
				t.Fatal("short original authority reached admission", err)
			}
			if lastDeadline.Load().(time.Time).After(bound) {
				t.Fatal("independent consumption escaped original cutoff", mode, lastDeadline.Load(), bound)
			}
		})
	}
}

func TestStorageHintAcceptedReplayStartsNoWait(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	first, err := f.request(t, p, "accepted")
	if err != nil {
		t.Fatal(err)
	}
	delete(f.previews, p.ID)
	f.missing = true
	var reads, demands atomic.Int32
	f.svc.Storage = consumptionStorageFunc(func(context.Context, authorization.Target) (ContextStorageObservation, error) {
		reads.Add(1)
		return ContextStorageObservation{}, value.ErrUnavailable
	})
	f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error { demands.Add(1); return value.ErrUnavailable })
	replay, err := f.request(t, p, "accepted")
	if err != nil || !replay.Replay || replay.CaptureID != first.CaptureID || reads.Load() != 0 || demands.Load() != 0 {
		t.Fatal("accepted replay consulted readiness", err, reads.Load(), demands.Load())
	}
}

func TestRecordingStorageHintSkipsKnownChangedPreview(t *testing.T) {
	for _, mode := range []string{"epoch", "rules"} {
		t.Run(mode, func(t *testing.T) {
			f, p, _ := recordingOverlapFixture(t)
			if mode == "epoch" {
				p.IssuerEpoch = "ffffffff-ffff-4fff-8fff-ffffffffffff"
			} else {
				p.AssessmentRulesDigest[0] ^= 1
			}
			f.previews[p.ID] = p.Clone()
			var reads, demands atomic.Int32
			f.svc.Storage = consumptionStorageFunc(func(context.Context, authorization.Target) (ContextStorageObservation, error) {
				reads.Add(1)
				return ContextStorageObservation{}, value.ErrUnavailable
			})
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error { demands.Add(1); return nil })
			_, err := f.request(t, p, "changed")
			if err == nil || len(f.seen) != 0 || reads.Load() != 0 || demands.Load() != 0 {
				t.Fatal("changed preview started storage or admission", err, reads.Load(), demands.Load())
			}
		})
	}
}
