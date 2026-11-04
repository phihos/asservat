package capture

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func repeatReadinessPause(ctx context.Context, delay time.Duration) error {
	if delay == 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type repeatReadinessTargets struct {
	*investigationFixture
	delay time.Duration
	until time.Time
}

func (r repeatReadinessTargets) ResolveWorkload(ctx context.Context, ref targets.WorkloadRequest) (targets.PodResolution, error) {
	if err := repeatReadinessPause(ctx, r.delay); err != nil {
		return targets.PodResolution{}, err
	}
	target, err := r.investigationFixture.ResolveWorkload(ctx, ref)
	if !r.until.IsZero() {
		target.FreshUntil = r.until
	}
	return target, err
}

type repeatReadinessProfiles struct {
	availableProfile
	delay time.Duration
}

func (r repeatReadinessProfiles) ProfileRecorder(ctx context.Context, target targets.PodResolution) error {
	if err := repeatReadinessPause(ctx, r.delay); err != nil {
		return err
	}
	return r.availableProfile.ProfileRecorder(ctx, target)
}

type repeatReadinessCatalog struct {
	*storedProfileCatalog
	delay time.Duration
	check func(context.Context) error
}

type repeatReadinessReview struct {
	reviewRevocation
	calls atomic.Int32
}

func (r *repeatReadinessReview) ReviewResolved(context.Context, identity.Identity, targets.Request) error {
	r.calls.Add(1)
	return nil
}

func (r repeatReadinessCatalog) ReadCatalogProfiles(ctx context.Context, target targets.PodResolution, refs []planning.ProfileRef) ([]planning.CatalogProfile, error) {
	if err := repeatReadinessPause(ctx, r.delay); err != nil {
		return nil, err
	}
	if r.check != nil {
		if err := r.check(ctx); err != nil {
			return nil, err
		}
	}
	return r.storedProfileCatalog.ReadCatalogProfiles(ctx, target, refs)
}

// These independent staged ports model the observed native phase costs.
// No catalog/recorder port depends on storage completion. The only overlap
// is the existing refresh wait; every original context/fact deadline stays.
func TestProfileRepeatReadinessOverlapsCatalogAndRecorder(t *testing.T) {
	x, service, reader := namespaceHeapHistory(t)
	reader.settings.ExpiresAt = x.f.now.Add(time.Minute)
	f := x.f.investigationFixture
	f.svc.ReportPreviewFailure = func(stage string) { t.Log("preview stage:", stage) }
	reviews := &repeatReadinessReview{}
	f.svc.Reviews = reviews
	f.svc.Targets = repeatReadinessTargets{investigationFixture: f, delay: 1300 * time.Millisecond}
	f.svc.Profiles = repeatReadinessCatalog{storedProfileCatalog: x.catalog, delay: time.Second}
	f.svc.Recorders = repeatReadinessProfiles{availableProfile: availableProfile{availableRecording{f}}, delay: 300 * time.Millisecond}
	var readyAt, demandDeadline atomic.Int64
	var demands, freshReads atomic.Int32
	f.svc.Refresh = consumptionRefreshFunc(func(ctx context.Context, target targets.Request) error {
		if target != f.target.Request {
			t.Error("demand changed original target")
		}
		demands.Add(1)
		deadline, _ := ctx.Deadline()
		demandDeadline.Store(deadline.UnixNano())
		readyAt.Store(time.Now().Add(1800 * time.Millisecond).UnixNano())
		return nil
	})
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		out, err := f.ContextStorage(ctx, target)
		if ready := readyAt.Load(); ready == 0 || time.Now().UnixNano() < ready {
			out.Binding.ObservedAt = f.now.Add(-31 * time.Second)
			out.Binding.FreshUntil = f.now.Add(-time.Second)
			return out, value.ErrStorageBindingExpired
		}
		freshReads.Add(1)
		// Keep the fixture's fact clock and its original proof intervals;
		// only blocking port latency uses the real context/timer clock.
		out.Binding.ObservedAt = f.now
		out.Binding.FreshUntil = out.Binding.ObservedAt.Add(30 * time.Second)
		return out, err
	})
	service.Previews = f.svc
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	originalDeadline, _ := ctx.Deadline()
	started := time.Now()
	result, settings, err := service.PreviewRepeat(ctx, x.f.source(t, ctx), x.preview.Preview.CaptureID, nil)
	if err != nil || result.Recorder == nil || !result.Recorder.Recordable {
		t.Fatalf("late refresh owner missed unchanged readiness cutoff after %s: %v", time.Since(started), err)
	}
	if reviews.calls.Load() != 1 || demands.Load() != 1 || freshReads.Load() < 2 || result.Preview.Storage != f.store.Selection || demandDeadline.Load() != originalDeadline.Add(-storageResponseReserve).UnixNano() || ctx.Err() != nil || !settings.ExpiresAt.Equal(reader.settings.ExpiresAt) || !result.Preview.Intent.RepeatedFrom.ExpiresAt.Equal(reader.settings.ExpiresAt) {
		t.Fatal("repeat reset deadlines, reused hint authority, or duplicated refresh", demands.Load(), freshReads.Load(), time.Unix(0, demandDeadline.Load()))
	}
	if len(x.f.seen) != 0 || len(x.grants.requests) != 0 {
		t.Fatal("passive readiness acquired or requested approval")
	}
	t.Logf("single repeat owner completed after %s with one review/demand and %d independent fresh reads under the original cutoff", time.Since(started), freshReads.Load())
}

func TestProfileRepeatReadinessJoinsCatalogErrorsAndCancellation(t *testing.T) {
	for _, mode := range []string{"catalog-error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			x, service, reader := namespaceHeapHistory(t)
			reader.settings.ExpiresAt = x.f.now.Add(time.Minute)
			f := x.f.investigationFixture
			entered, joined := make(chan struct{}), make(chan struct{})
			var reads atomic.Int32
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, _ authorization.Target) (ContextStorageObservation, error) {
				if reads.Add(1) != 1 {
					t.Error("duplicate owner during failed catalog")
				}
				close(entered)
				defer close(joined)
				<-ctx.Done()
				return ContextStorageObservation{}, ctx.Err()
			})
			f.svc.Refresh = &countingRefresh{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			catalogFailure := errors.New("synthetic catalog failure")
			f.svc.Profiles = repeatReadinessCatalog{storedProfileCatalog: x.catalog, check: func(call context.Context) error {
				select {
				case <-entered:
				case <-call.Done():
					return call.Err()
				}
				if mode == "cancel" {
					cancel()
					return call.Err()
				}
				return catalogFailure
			}}
			service.Previews = f.svc
			_, _, err := service.PreviewRepeat(ctx, x.f.source(t, ctx), x.preview.Preview.CaptureID, nil)
			if err == nil || mode == "catalog-error" && !errors.Is(err, catalogFailure) {
				t.Fatal("catalog failure lost", err)
			}
			select {
			case <-joined:
			default:
				t.Fatal("repeat returned while storage owner still running")
			}
			if len(x.f.seen) != 0 || len(x.grants.requests) != 0 {
				t.Fatal("failed passive repeat acquired")
			}
		})
	}
}

func TestProfileRepeatReadinessKeepsHistoryBoundAndSeparatesHintTarget(t *testing.T) {
	for _, bound := range []string{"history", "target"} {
		t.Run(bound, func(t *testing.T) {
			x, service, reader := namespaceHeapHistory(t)
			f := x.f.investigationFixture
			until := f.now.Add(2 * time.Second)
			reader.settings.ExpiresAt = f.now.Add(time.Minute)
			if bound == "history" {
				reader.settings.ExpiresAt = until
			} else {
				f.svc.Targets = repeatReadinessTargets{investigationFixture: f, until: until}
			}
			entered, joined := make(chan time.Time, 1), make(chan struct{})
			f.svc.Refresh = &countingRefresh{}
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, _ authorization.Target) (ContextStorageObservation, error) {
				deadline, _ := ctx.Deadline()
				entered <- deadline
				defer close(joined)
				<-ctx.Done()
				return ContextStorageObservation{}, ctx.Err()
			})
			stop := errors.New("bound inspected")
			f.svc.Profiles = repeatReadinessCatalog{storedProfileCatalog: x.catalog, check: func(ctx context.Context) error {
				select {
				case got := <-entered:
					want := until
					if bound == "target" {
						// The initial target now scopes the hint's exact identity,
						// not final authority. Only the independent recorder read
						// may supply a fresh target for the final plan.
						want = f.now.Add(5 * time.Second)
					}
					if !got.Equal(want) {
						t.Errorf("%s hint bound: %s want %s", bound, got, want)
					}
				case <-ctx.Done():
					t.Error("early owner did not reach storage")
				}
				return stop
			}}
			service.Previews = f.svc
			_, _, err := service.PreviewRepeat(t.Context(), x.f.source(t, t.Context()), x.preview.Preview.CaptureID, nil)
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			select {
			case <-joined:
			default:
				t.Fatal("bounded owner did not join")
			}
		})
	}
}

func TestProfileRepeatReadinessSkipsReplacedTarget(t *testing.T) {
	for _, pin := range []string{"workload", "pod"} {
		t.Run(pin, func(t *testing.T) {
			x := newStoredProfileReview(t, true)
			f := x.f.investigationFixture
			var reads atomic.Int32
			f.svc.Refresh = &countingRefresh{}
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				reads.Add(1)
				return f.ContextStorage(ctx, target)
			})
			original := f.target.Target()
			if pin == "workload" {
				original.WorkloadUID = "old-workload"
			} else {
				original.PodUID = "old-pod"
			}
			intent := x.preview.Preview.Intent
			intent.RepeatedFrom = &value.HistoryLineage{CaptureID: x.preview.Preview.CaptureID, ExpiresAt: f.now.Add(time.Minute)}
			_, err := f.svc.PreviewCompositionRepeat(t.Context(), x.f.source(t, t.Context()), intent, original)
			if !errors.Is(err, value.ErrTargetReplaced) || reads.Load() != 0 {
				t.Fatal("replaced target started storage work", err, reads.Load())
			}
		})
	}
}
