package capture

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// Actual Request/review/current facts/admission, with synthetic ports. A legal
// 30s observation naturally expires; only an independent read can replace it.
func TestContextStorageRequestExpiredSourceUsesExistingRefresh(t *testing.T) {
	for _, mode := range []string{"fresh", "hint-already-demanded", "expired-revision", "fresh-revision", "expired-pool", "fresh-pool", "hint-failed-demand", "invalid-interval", "wrong-target", "future", "missing-metadata", "generic-changed", "failed-demand", "original-recovery"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			var advance atomic.Int64
			f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
			var reads, demands atomic.Int32
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error {
				demands.Add(1)
				if mode == "failed-demand" || mode == "hint-failed-demand" {
					return value.ErrUnavailable
				}
				return nil
			})
			if mode == "original-recovery" {
				f.svc.Recovery = consumptionRecovery{f, f.now.Add(1500 * time.Millisecond)}
			}
			admit := &consumptionAdmission{investigationFixture: f}
			f.svc.Admission = admit
			var independent ContextStorageObservation
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				out, err := f.ContextStorage(ctx, target)
				n := reads.Add(1)
				if mode == "hint-already-demanded" || mode == "hint-failed-demand" {
					if n == 1 {
						out.Binding.ObservedAt = f.now.Add(-31 * time.Second)
						out.Binding.FreshUntil = f.now.Add(-time.Second)
						return out, value.ErrStorageBindingExpired
					}
					if mode == "hint-already-demanded" {
						n--
					}
				}
				out.Binding.ObservedAt = f.now.Add(-28500 * time.Millisecond)
				out.Binding.FreshUntil = f.now.Add(1500 * time.Millisecond)
				switch n {
				case 1: // Hint is ready with1.5s remaining on its original30s interval.
				case 2:
					advance.Store(int64(1600 * time.Millisecond))
					switch mode {
					case "expired-revision":
						out.Binding.Revision.Generation++
						out.Selection.BindingRevision = out.Binding.Revision
					case "expired-pool":
						out.Selection.PoolRevision++
					case "invalid-interval":
						out.Binding.FreshUntil = out.Binding.ObservedAt
					case "wrong-target":
						out.Binding.WorkloadUID = "replacement"
					case "future":
						out.Binding.ObservedAt = f.now.Add(2 * time.Second)
						out.Binding.FreshUntil = out.Binding.ObservedAt.Add(30 * time.Second)
					case "missing-metadata":
						return ContextStorageObservation{}, value.ErrStorageBindingExpired
					case "generic-changed":
						return ContextStorageObservation{}, value.ErrChanged
					}
					return out, value.ErrStorageBindingExpired
				case 3:
					if demands.Load() != 1 {
						t.Error("independent read without original single demand")
					}
					out.Binding.ObservedAt = f.now.Add(1600 * time.Millisecond)
					out.Binding.FreshUntil = out.Binding.ObservedAt.Add(30 * time.Second)
					if mode == "fresh-revision" {
						out.Binding.Revision.Generation++
						out.Selection.BindingRevision = out.Binding.Revision
					}
					if mode == "fresh-pool" {
						out.Selection.PoolRevision++
					}
					independent = out
				default:
					t.Error("unexpected read")
				}
				return out, err
			})
			accepted, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "expired-source")
			if mode == "fresh" || mode == "hint-already-demanded" {
				wantReads := int32(3)
				if mode == "hint-already-demanded" {
					wantReads = 4
				}
				if err != nil || accepted.CaptureID != p.CaptureID || reads.Load() != wantReads || demands.Load() != 1 || f.admissions.Load() != 1 || admit.got.Storage != independent.Binding {
					t.Fatal("natural expiry bypassed existing owner or changed observation", err, reads.Load(), demands.Load(), f.admissions.Load())
				}
				return
			}
			wantReads, wantDemands := int32(2), int32(0)
			wantCause := value.ErrChanged
			if mode == "fresh-revision" || mode == "fresh-pool" {
				wantReads, wantDemands = 3, 1
			}
			if mode == "failed-demand" || mode == "hint-failed-demand" {
				wantDemands = 1
				wantCause = value.ErrUnavailable
			}
			if !errors.Is(err, wantCause) || reads.Load() != wantReads || demands.Load() != wantDemands || f.admissions.Load() != 0 {
				t.Fatal("expired marker revived invalid/replaced/exhausted authority", err, reads.Load(), demands.Load(), f.admissions.Load())
			}
		})
	}
}

func TestContextStorageExpiredMarkerIsAvailability(t *testing.T) {
	if !errors.Is(value.ErrStorageBindingExpired, value.ErrUnavailable) || errors.Is(value.ErrStorageBindingExpired, value.ErrChanged) {
		t.Fatal("expiry marker changed review")
	}
}

func TestContextStorageExpiredSourceRetainsReadinessCutoffs(t *testing.T) {
	for _, mode := range []string{"tail", "no-refresh", "original-bound-after-demand"} {
		t.Run(mode, func(t *testing.T) {
			f, facts, owner := consumptionFixture(t)
			var advance atomic.Int64
			f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
			var demands, reads int
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error {
				demands++
				advance.Store(int64(100 * time.Millisecond))
				return nil
			})
			ctx := t.Context()
			if mode == "tail" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 750*time.Millisecond)
				defer cancel()
			}
			if mode == "no-refresh" {
				f.svc.Refresh = nil
			}
			if mode == "original-bound-after-demand" {
				owner.until = f.now.Add(100 * time.Millisecond)
			}
			f.svc.Storage = consumptionStorageFunc(func(call context.Context, target authorization.Target) (ContextStorageObservation, error) {
				reads++
				if deadline, ok := call.Deadline(); !ok || deadline.After(owner.until) {
					t.Error("original storage authority extended")
				}
				if deadline, ok := ctx.Deadline(); ok {
					if actual, _ := call.Deadline(); actual.After(deadline) {
						t.Error("caller deadline extended")
					}
				}
				out, _ := f.ContextStorage(call, target)
				out.Binding.ObservedAt = f.now.Add(-31 * time.Second)
				out.Binding.FreshUntil = f.now.Add(-time.Second)
				return out, value.ErrStorageBindingExpired
			})
			_, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
			cause, wantDemands := value.ErrUnavailable, 0
			if mode == "original-bound-after-demand" {
				cause, wantDemands = value.ErrChanged, 1
			}
			if !errors.Is(err, cause) || reads != 1 || demands != wantDemands || f.admissions.Load() != 0 {
				t.Fatal("stale source renewed readiness or authority", err, reads, demands)
			}
		})
	}
}

// The same typed expired read can end at distinct bounded readiness decisions.
// Keep those closed diagnostics separate without changing the returned cause.
func TestContextStorageExpiredReadinessRefusalReason(t *testing.T) {
	for _, mode := range []string{"readiness-tail", "demand-failed", "refresh-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f, facts, owner := consumptionFixture(t)
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error {
				t.Error("refusal issued a new demand")
				return value.ErrUnavailable
			})
			ctx := t.Context()
			if mode == "readiness-tail" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 750*time.Millisecond)
				defer cancel()
			}
			if mode == "demand-failed" {
				owner.demand = storageDemandFailed
			}
			if mode == "refresh-unavailable" {
				f.svc.Refresh = nil
			}
			reads := 0
			f.svc.Storage = consumptionStorageFunc(func(call context.Context, target authorization.Target) (ContextStorageObservation, error) {
				reads++
				out, _ := f.ContextStorage(call, target)
				out.Binding.ObservedAt = f.now.Add(-31 * time.Second)
				out.Binding.FreshUntil = f.now.Add(-time.Second)
				return out, value.ErrStorageBindingExpired
			})
			var got string
			f.svc.ReportPreviewFailure = func(stage string) { got = stage }
			_, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
			f.svc.reportRequestFailure(err)
			if !errors.Is(err, value.ErrStorageBindingExpired) || reads != 1 || got != "request/facts/storage/expired/"+mode {
				t.Fatal("expired read lost its readiness decision or original cause", got, reads, err)
			}
		})
	}
}
