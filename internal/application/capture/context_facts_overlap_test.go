package capture

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type overlapStorageRead struct {
	*investigationFixture
	entered, release, exited chan struct{}
	reads                    atomic.Int32
}

func newOverlapStorage(f *investigationFixture) *overlapStorageRead {
	return &overlapStorageRead{investigationFixture: f, entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
}

func (s *overlapStorageRead) ContextStorage(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
	if s.reads.Add(1) == 1 {
		close(s.entered)
		defer close(s.exited)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ContextStorageObservation{}, ctx.Err()
		}
	}
	return s.investigationFixture.ContextStorage(ctx, target)
}

type overlapRetentionRead struct {
	*investigationFixture
	entered, release chan struct{}
}

func (r overlapRetentionRead) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	close(r.entered)
	select {
	case <-r.release:
	case <-ctx.Done():
		return privacy.Resolution{}, ctx.Err()
	}
	return r.investigationFixture.Resolve(ctx, in)
}

func overlapSignal(t *testing.T, signal <-chan struct{}, stage string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("%s did not progress independently", stage)
	}
}

func overlapRelease(signal chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(signal) }) }
}

// Both barriers must be entered before either dependency is released. This
// proves actual overlap without relying on scheduler-dependent elapsed times.
func TestContextFactsOverlapStorageHintAndRetention(t *testing.T) {
	f := newInvestigationFixture()
	storage := newOverlapStorage(f)
	retention := overlapRetentionRead{f, make(chan struct{}), make(chan struct{})}
	f.svc.Storage, f.svc.Retention, f.svc.Refresh = storage, retention, &countingRefresh{}
	ctx, cancel := context.WithCancel(t.Context())
	source := f.source(t, ctx)
	releaseStorage, releaseRetention := overlapRelease(storage.release), overlapRelease(retention.release)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := f.svc.Preview(ctx, source, f.intent())
		done <- err
	}()
	defer func() {
		cancel()
		releaseStorage()
		releaseRetention()
		overlapSignal(t, finished, "preview cleanup")
	}()
	overlapSignal(t, storage.entered, "storage readiness")
	overlapSignal(t, retention.entered, "retention")
	releaseRetention()
	releaseStorage()
	if err := <-done; err != nil || storage.reads.Load() != 2 || len(f.previews) != 1 || f.admissions.Load() != 0 {
		t.Fatal("overlapped hint changed authoritative reads or preview effects", err, storage.reads.Load())
	}
	overlapSignal(t, storage.exited, "joined storage hint")
}

// A request can use its already-running hint while resolving the exact Pod.
// The final authoritative read remains mandatory, but a second hint does not.
func TestContextFactsRequestUsesOneStorageHint(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	storage := newOverlapStorage(f)
	f.svc.Storage, f.svc.Refresh = storage, &countingRefresh{}
	ctx, cancel := context.WithCancel(t.Context())
	source := f.source(t, ctx)
	release := overlapRelease(storage.release)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := f.svc.Request(ctx, source, p.ID, "one-hint")
		done <- err
	}()
	defer func() {
		cancel()
		release()
		overlapSignal(t, finished, "request cleanup")
	}()
	overlapSignal(t, storage.entered, "request storage readiness")
	release()
	if err := <-done; err != nil || storage.reads.Load() != 2 || f.admissions.Load() != 1 {
		t.Fatal("request repeated readiness or omitted authoritative storage read", err, storage.reads.Load())
	}
}

type shortOverlapTarget struct{ *investigationFixture }

func (s shortOverlapTarget) ResolveWorkload(ctx context.Context, request targets.WorkloadRequest) (targets.PodResolution, error) {
	out, err := s.investigationFixture.ResolveWorkload(ctx, request)
	out.FreshUntil = s.now.Add(time.Second)
	return out, err
}

func TestContextFactsOverlapRetainsOriginalTargetExpiry(t *testing.T) {
	f := newInvestigationFixture()
	storage := newOverlapStorage(f)
	retention := overlapRetentionRead{f, make(chan struct{}), make(chan struct{})}
	f.svc.Storage, f.svc.Retention, f.svc.Refresh = storage, retention, &countingRefresh{}
	f.svc.Targets = shortOverlapTarget{f}
	var advance atomic.Int64
	f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
	ctx, cancel := context.WithCancel(t.Context())
	source := f.source(t, ctx)
	releaseStorage, releaseRetention := overlapRelease(storage.release), overlapRelease(retention.release)
	finished := make(chan struct{})
	defer func() {
		cancel()
		releaseStorage()
		releaseRetention()
		overlapSignal(t, finished, "expired target cleanup")
	}()
	done := make(chan error, 1)
	go func() {
		defer close(finished)
		_, err := f.svc.Preview(ctx, source, f.intent())
		done <- err
	}()
	overlapSignal(t, storage.entered, "storage readiness")
	overlapSignal(t, retention.entered, "retention")
	advance.Store(int64(2 * time.Second))
	releaseRetention()
	releaseStorage()
	err := <-done
	var failure interface{ FixedStep() string }
	if !errors.Is(err, value.ErrChanged) || !errors.As(err, &failure) || failure.FixedStep() != "facts/current/target" || len(f.previews) != 0 || f.admissions.Load() != 0 || f.targetReads.Load() != 1 {
		t.Fatal("overlap refreshed an expired target or performed an effect", err)
	}
}

type joinedHintStorage struct {
	entered, cancelled, release, exited chan struct{}
	reads                               atomic.Int32
}

func (s *joinedHintStorage) ContextStorage(ctx context.Context, _ authorization.Target) (ContextStorageObservation, error) {
	if s.reads.Add(1) == 1 {
		close(s.entered)
		<-ctx.Done()
		close(s.cancelled)
		<-s.release
		close(s.exited)
	}
	return ContextStorageObservation{}, value.ErrUnavailable
}

type orderedOverlapFailure struct {
	*investigationFixture
	eligible              ContextEligibilityReader
	stage                 string
	err                   error
	entered               <-chan struct{}
	capabilities, retains atomic.Int32
}

func (f *orderedOverlapFailure) gate(ctx context.Context) {
	select {
	case <-f.entered:
	case <-ctx.Done():
	}
}

func (f *orderedOverlapFailure) ContextEligibilityCurrent(ctx context.Context, source identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	if f.stage == "eligibility" {
		f.gate(ctx)
		return authorization.CaptureEligibility{Result: authorization.Result{Reason: "ExplicitDeny"}}
	}
	return f.eligible.ContextEligibilityCurrent(ctx, source, target)
}

func (f *orderedOverlapFailure) ContextCapability(ctx context.Context, target authorization.Target) (planning.ContextCapability, error) {
	f.capabilities.Add(1)
	if f.stage == "capability" {
		f.gate(ctx)
		return planning.ContextCapability{}, f.err
	}
	return f.investigationFixture.ContextCapability(ctx, target)
}

func (f *orderedOverlapFailure) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	f.retains.Add(1)
	f.gate(ctx)
	return privacy.Resolution{}, f.err
}

func TestContextFactsOverlapJoinsEarlyFailuresInAuthorityOrder(t *testing.T) {
	for _, stage := range []string{"eligibility", "capability", "retention"} {
		t.Run(stage, func(t *testing.T) {
			f := newInvestigationFixture()
			storage := &joinedHintStorage{entered: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			cause := errors.New("synthetic-facts-failure")
			reader := &orderedOverlapFailure{investigationFixture: f, eligible: f.svc.Eligibility, stage: stage, err: cause, entered: storage.entered}
			f.svc.Storage, f.svc.Refresh = storage, &countingRefresh{}
			f.svc.Eligibility, f.svc.Capabilities, f.svc.Retention = reader, reader, reader
			ctx, cancel := context.WithCancel(t.Context())
			source := f.source(t, ctx)
			release := overlapRelease(storage.release)
			done, finished := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(finished)
				_, err := f.svc.Preview(ctx, source, f.intent())
				done <- err
			}()
			defer func() {
				cancel()
				release()
				overlapSignal(t, finished, "early failure cleanup")
			}()
			overlapSignal(t, storage.cancelled, "early failure cancellation")
			select {
			case <-done:
				t.Fatal("facts returned before cancelled child work actually finished")
			default:
			}
			release()
			err := <-done
			overlapSignal(t, storage.exited, "cancelled hint exit")
			want, caps, retains := "facts/eligibility/deny", int32(0), int32(0)
			if stage != "eligibility" {
				want, caps = "facts/"+stage, 1
				if !errors.Is(err, cause) {
					t.Fatal("original dependency failure was replaced", err)
				}
			}
			if stage == "retention" {
				want, retains = want+"/other", 1
			}
			var failure interface{ FixedStep() string }
			if !errors.As(err, &failure) || failure.FixedStep() != want || reader.capabilities.Load() != caps || reader.retains.Load() != retains || len(f.previews) != 0 || f.admissions.Load() != 0 {
				t.Fatal("failure reordered authority reads or produced an effect", err)
			}
		})
	}
}
