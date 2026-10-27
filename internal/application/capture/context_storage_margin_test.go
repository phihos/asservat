package capture

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

type marginStorageRead struct {
	*investigationFixture
	reads     atomic.Int32
	advance   *atomic.Int64
	elapsed   time.Duration
	until     time.Time
	finalRead func(context.Context) error
	readAt    int32
}

func (s *marginStorageRead) ContextStorage(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
	n := s.reads.Add(1)
	out, err := s.investigationFixture.ContextStorage(ctx, target)
	out.Binding.FreshUntil = s.until
	readAt := s.readAt
	if readAt == 0 {
		readAt = 2
	}
	if n == readAt {
		// The final read happens only after the early hint has finished.
		// Observe elapsed time without changing the binding's original cutoff.
		s.advance.Store(int64(s.elapsed))
		if s.finalRead != nil {
			if err := s.finalRead(ctx); err != nil {
				return ContextStorageObservation{}, err
			}
		}
	}
	return out, err
}

func TestContextStorageMarginIsRequiredAtAuthoritativeRead(t *testing.T) {
	for _, left := range []time.Duration{50 * time.Millisecond, time.Second} {
		t.Run(left.String(), func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			var advance atomic.Int64
			f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
			storage := &marginStorageRead{investigationFixture: f, advance: &advance,
				elapsed: time.Second - left, until: f.now.Add(time.Second)}
			refresh := &countingRefresh{}
			f.svc.Storage, f.svc.Refresh = storage, refresh
			expectedReads := int32(2)
			if left < time.Second {
				// Without a configured refresher, a thin authoritative
				// result still refuses immediately; there is no early hint.
				f.svc.Refresh = nil
				storage.readAt, expectedReads = 1, 1
			}
			var reports []string
			f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
			accepted, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "original")
			if left == time.Second {
				if err != nil || accepted.CaptureID != p.CaptureID || f.admissions.Load() != 1 || len(reports) != 0 {
					t.Fatal("exact original one-second margin was rejected", err, f.admissions.Load())
				}
			} else {
				var stage interface{ FixedStep() string }
				if !errors.Is(err, value.ErrUnavailable) || !errors.As(err, &stage) || stage.FixedStep() != "facts/storage" ||
					accepted.CaptureID != "" || f.admissions.Load() != 0 || len(f.accepted) != 0 {
					t.Fatal("thin final storage result reached admission", err, accepted.CaptureID, f.admissions.Load())
				}
				if !slices.Equal(reports, []string{"request/facts/storage/margin"}) {
					t.Fatal("request omitted its distinct storage-margin diagnostic", reports)
				}
			}
			if storage.reads.Load() != expectedReads || refresh.demands.Load() != 0 || !storage.until.Equal(f.now.Add(time.Second)) {
				t.Fatal("final margin check repeated readiness, demanded refresh or renewed the binding", storage.reads.Load(), refresh.demands.Load())
			}
		})
	}
}

type marginTargetRead struct{ *investigationFixture }

func (r marginTargetRead) ResolvePod(ctx context.Context, request targets.Request) (targets.PodResolution, error) {
	out, err := r.investigationFixture.ResolvePod(ctx, request)
	out.FreshUntil = r.now.Add(100 * time.Millisecond)
	return out, err
}

func TestContextStorageMarginDoesNotRenewEarlierAuthority(t *testing.T) {
	for _, earlier := range []string{"identity", "target"} {
		t.Run(earlier, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			var advance atomic.Int64
			f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
			storage := &marginStorageRead{investigationFixture: f, advance: &advance,
				elapsed: 200 * time.Millisecond, until: f.now.Add(1200 * time.Millisecond)}
			refresh := &countingRefresh{}
			f.svc.Storage, f.svc.Refresh = storage, refresh
			var reports []string
			f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
			source := f.source(t, t.Context())
			if earlier == "identity" {
				source = &shortenedContinuationIdentity{source: source, until: f.now.Add(100 * time.Millisecond)}
			} else {
				f.svc.Targets = marginTargetRead{f}
			}
			_, err := f.svc.Request(t.Context(), source, p.ID, "original")
			var stage interface{ FixedStep() string }
			if !errors.Is(err, value.ErrChanged) || !errors.As(err, &stage) || stage.FixedStep() != "facts/current/"+earlier ||
				f.admissions.Load() != 0 || len(f.accepted) != 0 || storage.reads.Load() != 2 || refresh.demands.Load() != 0 {
				t.Fatal("storage margin revived earlier authority or repeated readiness", err, f.admissions.Load(), storage.reads.Load(), refresh.demands.Load())
			}
			if !slices.Equal(reports, []string{"request/facts/current/" + earlier}) {
				t.Fatal("request omitted its distinct expired-facts diagnostic", reports)
			}
		})
	}
}

func TestContextStorageMarginCancellationJoinsAuthoritativeRead(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	originalUntil, _ := ctx.Deadline()
	entered, cancelled, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var advance atomic.Int64
	// This short parent skips the hint; its first read is authoritative.
	storage := &marginStorageRead{investigationFixture: f, advance: &advance, until: f.now.Add(time.Second), readAt: 1,
		finalRead: func(call context.Context) error {
			until, ok := call.Deadline()
			if !ok || until.After(originalUntil) {
				t.Error("final read widened the caller deadline")
			}
			close(entered)
			<-call.Done()
			close(cancelled)
			<-release
			close(exited)
			return call.Err()
		}}
	refresh := &countingRefresh{}
	f.svc.Storage, f.svc.Refresh = storage, refresh
	source := f.source(t, ctx)
	done, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		_, err := f.svc.Request(ctx, source, p.ID, "original")
		done <- err
	}()
	unblock := overlapRelease(release)
	defer func() {
		cancel()
		unblock()
		overlapSignal(t, finished, "canceled request cleanup")
	}()
	overlapSignal(t, entered, "authoritative storage read")
	cancel()
	overlapSignal(t, cancelled, "original caller cancellation")
	select {
	case <-done:
		t.Fatal("request returned before canceled storage work joined")
	default:
	}
	unblock()
	err := <-done
	overlapSignal(t, exited, "joined authoritative read")
	if !errors.Is(err, context.Canceled) || storage.reads.Load() != 1 || refresh.demands.Load() != 0 ||
		f.admissions.Load() != 0 || len(f.accepted) != 0 {
		t.Fatal("cancellation performed admission or repeated readiness", err, storage.reads.Load(), refresh.demands.Load())
	}
}
