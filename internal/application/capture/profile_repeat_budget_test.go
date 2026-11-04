package capture

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	access "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Reuse the existing real history/repeat/compiler/eligibility service fixture.
// Each actually invoked synthetic read mints only its own original five-second
// observation; the clock advances with real blocking work, never a frozen now.
type repeatBudgetPorts struct {
	*investigationFixture
	now                                func() time.Time
	mode                               string
	readyAt                            atomic.Int64
	demands, recoveries, recorderReads atomic.Int32
}

func (p *repeatBudgetPorts) snapshot() *investigationFixture {
	return &investigationFixture{now: p.now(), actor: p.actor, audience: p.audience, cap: p.cap, store: p.store, target: p.target, epoch: p.epoch, policyGeneration: p.policyGeneration}
}
func (p *repeatBudgetPorts) ResolveWorkload(ctx context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	f := p.snapshot()
	if err := repeatReadinessPause(ctx, 800*time.Millisecond); err != nil {
		return targets.PodResolution{}, err
	}
	return f.ResolveWorkload(ctx, r)
}
func (p *repeatBudgetPorts) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return p.snapshot().ResolvePod(ctx, r)
}
func (p *repeatBudgetPorts) ResolveProfileRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	p.recorderReads.Add(1)
	f := p.snapshot()
	if p.mode == "target-old" {
		f.now = p.investigationFixture.now
	}
	if p.mode == "target-replaced" {
		f.target.Request.PodUID, f.target.Pin.UID = "replacement", "replacement"
	}
	if err := repeatReadinessPause(ctx, 350*time.Millisecond); err != nil {
		return targets.PodResolution{}, err
	}
	if p.mode == "unsupported-late" || p.mode == "unsupported-warm" {
		return targets.PodResolution{}, targets.ErrUnsupported
	}
	return f.ResolvePod(ctx, r)
}
func (p *repeatBudgetPorts) ProfileRecorder(ctx context.Context, r targets.PodResolution) error {
	_, err := p.ResolveProfileRecorder(ctx, r.Request)
	return err
}
func (p *repeatBudgetPorts) PacketRecorder(context.Context, targets.PodResolution) error {
	return targets.ErrUnsupported
}
func (p *repeatBudgetPorts) ResolvePacketRecorder(context.Context, targets.Request) (targets.PodResolution, error) {
	return targets.PodResolution{}, targets.ErrUnsupported
}
func (p *repeatBudgetPorts) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	n := p.recoveries.Add(1)
	f := p.snapshot()
	if n == 2 && p.mode == "recovery-old" {
		f.now = p.investigationFixture.now
	}
	out, err := f.RecoveryState(ctx)
	if n == 2 {
		switch p.mode {
		case "recovery-epoch":
			out.IssuerEpoch = fixtureID(999)
		case "recovery-uid":
			out.Revision.UID = "changed"
		case "recovery-generation":
			out.Revision.Generation++
		case "recovery-digest":
			out.Revision.Digest[0]++
		}
	}
	return out, err
}
func (p *repeatBudgetPorts) Permissions(ctx context.Context, t authorization.Target) (authorization.Projection, error) {
	f := p.snapshot()
	if p.mode == "labels-policy-old" {
		f.now = p.investigationFixture.now
	}
	return f.Permissions(ctx, t)
}
func (p *repeatBudgetPorts) ContextCapability(ctx context.Context, t authorization.Target) (planning.ContextCapability, error) {
	return p.snapshot().ContextCapability(ctx, t)
}
func (p *repeatBudgetPorts) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	f := p.snapshot()
	if p.mode == "retention-old" {
		f.now = p.investigationFixture.now
	}
	return f.Resolve(ctx, in)
}
func (p *repeatBudgetPorts) ContextProcessingCoverage(ctx context.Context, in value.ProcessingCoverageRequest, r artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	out, err := p.snapshot().ContextProcessingCoverage(ctx, in, r)
	if until, ok := ctx.Deadline(); ok {
		out.FreshUntil = identity.Earlier(out.FreshUntil, until)
	}
	return out, err
}
func (p *repeatBudgetPorts) ContextStorage(ctx context.Context, t authorization.Target) (ContextStorageObservation, error) {
	f := p.snapshot()
	out, err := f.ContextStorage(ctx, t)
	if ready := p.readyAt.Load(); p.mode != "unsupported-warm" && (ready == 0 || time.Now().UnixNano() < ready) {
		out.Binding.ObservedAt = f.now.Add(-31 * time.Second)
		out.Binding.FreshUntil = f.now.Add(-time.Second)
		return out, value.ErrStorageBindingExpired
	}
	out.Binding.FreshUntil = out.Binding.ObservedAt.Add(30 * time.Second)
	return out, err
}
func (p *repeatBudgetPorts) DemandCapacityRefresh(context.Context, targets.Request) error {
	p.demands.Add(1)
	p.readyAt.Store(time.Now().Add(4500 * time.Millisecond).UnixNano())
	return nil
}

type repeatBudgetIdentity struct {
	f     *investigationFixture
	now   func() time.Time
	until time.Time
}

func (r repeatBudgetIdentity) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	i, err := (fixtureIdentityResolver{r.f}).Resolve(ctx, "")
	i.VerifiedAt = r.now()
	i.ValidUntil = r.until
	return i, err
}

// Native41879675203: the legitimate original source operation completed4.5s
// after demand. Target/catalog/recorder overhead is independent and does not
// shorten that source observation or become storage authority. The namespace
// heap fixture follows the same shared Go-profile repeat path as runtimeTrace.
func TestProfileRepeatMeasuredReadinessBudget(t *testing.T) {
	for _, mode := range []string{"success", "target-old", "target-replaced", "recovery-old", "recovery-epoch", "recovery-uid", "recovery-generation", "recovery-digest", "labels-policy-old", "retention-old", "parent", "history", "unsupported-late", "unsupported-warm", "late-catalog"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			measuredProfileRepeat(t, mode)
		})
	}
}

func measuredProfileRepeat(t *testing.T, mode string) {
	x, service, reader := namespaceHeapHistory(t)
	f := x.f.investigationFixture
	now := func() time.Time { return time.Now().UTC() }
	start := now()
	p := &repeatBudgetPorts{investigationFixture: f, now: now, mode: mode}
	f.svc.ReportPreviewFailure = func(stage string) { t.Log("preview stage:", stage) }
	f.svc.Now = now
	f.svc.Targets = p
	f.svc.Recorders = p
	f.svc.Recovery = p
	f.svc.Storage = p
	f.svc.Refresh = p
	f.svc.Eligibility = access.Evaluator{Permissions: p, Now: now}
	f.svc.Capabilities = p
	f.svc.Retention = p
	f.svc.Processing = p
	catalog := repeatReadinessCatalog{storedProfileCatalog: x.catalog, delay: 1200 * time.Millisecond}
	if mode == "late-catalog" {
		// Deliberately returns complete valid documents after the supplied
		// classification context expires; the service must enforce its phase.
		catalog.check = func(ctx context.Context) error { <-ctx.Done(); return nil }
	}
	f.svc.Profiles = catalog
	reviews := &repeatReadinessReview{}
	f.svc.Reviews = reviews
	reader.settings.ExpiresAt = start.Add(time.Minute)
	if mode == "history" {
		reader.settings.ExpiresAt = start.Add(2 * time.Second)
	}
	service.Previews = f.svc
	service.Now = now
	window := 15 * time.Second
	if mode == "parent" {
		window = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(t.Context(), window)
	defer cancel()
	current, _, err := identities.NewBearerRequestWithin(ctx, repeatBudgetIdentity{f, now, start.Add(15 * time.Second)}, "synthetic", now, identity.CapturePreviewRequestWindow)
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := service.PreviewRepeat(ctx, current, x.preview.Preview.CaptureID, nil)
	if mode == "unsupported-warm" {
		if !errors.Is(err, value.ErrProfileChanged) || result.Recorder != nil || p.demands.Load() != 0 {
			t.Fatal("warm unsupported history dependency refusal changed", err, p.demands.Load())
		}
		return
	}
	if mode == "late-catalog" && (p.recoveries.Load() != 1 || p.recorderReads.Load() != 0) {
		t.Fatal("expired classification advanced into final observations", p.recoveries.Load(), p.recorderReads.Load())
	}
	if mode != "success" {
		if err == nil || result.Recorder != nil || len(x.f.seen) != 0 || len(x.grants.requests) != 0 {
			t.Fatalf("%s accepted stale/changed original authority", mode)
		}
		if p.demands.Load() > 1 || p.recorderReads.Load() > 1 || p.recoveries.Load() > 2 {
			t.Fatal("refusal retried observations")
		}
		return
	}
	if err != nil || result.Recorder == nil || !result.Recorder.Recordable {
		t.Fatalf("measured4.5s source readiness refused after %s (demands=%d recovery=%d recorder=%d): %v", time.Since(start), p.demands.Load(), p.recoveries.Load(), p.recorderReads.Load(), err)
	}
	if p.demands.Load() != 1 || p.recoveries.Load() != 2 || p.recorderReads.Load() != 1 || reviews.calls.Load() != 1 || len(x.f.seen) != 0 || len(x.grants.requests) != 0 {
		t.Fatal("extra observations, review, acquisition or approval")
	}
	if !result.Preview.Target.Valid() || result.Preview.Target != f.target.Request || result.Preview.Storage != f.store.Selection {
		t.Fatal("original source/target changed")
	}
	t.Logf("completed measured source readiness with advancing clock in %s", time.Since(start))
}
