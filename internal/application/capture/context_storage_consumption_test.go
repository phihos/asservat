package capture

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type consumptionStorageFunc func(context.Context, authorization.Target) (ContextStorageObservation, error)

func (f consumptionStorageFunc) ContextStorage(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
	return f(ctx, target)
}

type consumptionFacts struct {
	*investigationFixture
	eligible               ContextEligibilityReader
	eligibility, caps, ret int
	bound                  string
	until                  time.Time
}

func (r *consumptionFacts) ContextEligibilityCurrent(ctx context.Context, source identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	r.eligibility++
	out := r.eligible.ContextEligibilityCurrent(ctx, source, target)
	if r.bound == "eligibility" {
		out.ValidUntil = r.until
	}
	if r.bound == "eligibility-identity" {
		out.VerifiedIdentity.ValidUntil = r.until
	}
	return out
}

func (r *consumptionFacts) ContextCapability(ctx context.Context, target authorization.Target) (planning.ContextCapability, error) {
	r.caps++
	out, err := r.investigationFixture.ContextCapability(ctx, target)
	if r.bound == "capability" {
		out.FreshUntil = r.until
	}
	return out, err
}

func (r *consumptionFacts) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	r.ret++
	out, err := r.investigationFixture.Resolve(ctx, in)
	if r.bound == "retention" {
		out.ValidUntil = r.until
	}
	if r.bound == "retention-proof" {
		out.ValidUntil, out.Proof.ValidUntil = r.until, r.until
	}
	return out, err
}

type consumptionAdmission struct {
	*investigationFixture
	got value.Admission
}

type consumptionRefreshFunc func(context.Context, targets.Request) error

func (f consumptionRefreshFunc) DemandCapacityRefresh(ctx context.Context, target targets.Request) error {
	return f(ctx, target)
}

type consumptionRecovery struct {
	*investigationFixture
	until time.Time
}

func (r consumptionRecovery) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	out, err := r.investigationFixture.RecoveryState(ctx)
	out.FreshUntil = r.until
	return out, err
}

type consumptionTarget struct {
	*investigationFixture
	until time.Time
}

func (r consumptionTarget) ResolvePod(ctx context.Context, target targets.Request) (targets.PodResolution, error) {
	out, err := r.investigationFixture.ResolvePod(ctx, target)
	out.FreshUntil = r.until
	return out, err
}

func TestContextStorageConsumptionRetainsEachAuthorityBound(t *testing.T) {
	for _, bound := range []string{"identity", "recovery", "target", "eligibility", "eligibility-identity", "capability", "retention", "retention-proof"} {
		t.Run(bound, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			until := f.now.Add(1400 * time.Millisecond)
			source := f.source(t, t.Context())
			facts := &consumptionFacts{investigationFixture: f, eligible: f.svc.Eligibility, bound: bound, until: until}
			f.svc.Eligibility, f.svc.Capabilities, f.svc.Retention = facts, facts, facts
			switch bound {
			case "identity":
				source = &shortenedContinuationIdentity{source: source, until: until}
			case "recovery":
				f.svc.Recovery = consumptionRecovery{f, until}
			case "target":
				f.svc.Targets = consumptionTarget{f, until}
			}
			var advance atomic.Int64
			f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
			refresh := &countingRefresh{}
			f.svc.Refresh = refresh
			var reads atomic.Int32
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				out, err := f.ContextStorage(ctx, target)
				out.Binding.FreshUntil = f.now.Add(1200 * time.Millisecond)
				switch reads.Add(1) {
				case 2:
					if deadline, ok := ctx.Deadline(); !ok || deadline.After(until) {
						t.Error("consumption did not inherit original bound", deadline, until)
					}
					advance.Store(int64(1150 * time.Millisecond))
				case 3:
					// An independently fresh B arrives exactly at the
					// earlier authority's original expiry.
					advance.Store(int64(1400 * time.Millisecond))
					out.Binding.ObservedAt = until
					out.Binding.FreshUntil = until.Add(2 * time.Second)
				}
				return out, err
			})
			var reports []string
			f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
			_, err := f.svc.Request(t.Context(), source, p.ID, "expired-"+bound)
			if !errors.Is(err, value.ErrChanged) || reads.Load() != 3 || refresh.demands.Load() != 1 ||
				f.admissions.Load() != 0 || facts.caps != 1 || facts.ret != 1 || facts.eligibility != 1 ||
				!slices.Equal(reports, []string{"request/facts/current"}) {
				t.Fatal("new storage revived an earlier authority", bound, err, reads.Load(), refresh.demands.Load(), reports)
			}
		})
	}
}

// Directly exercise the owned consumption boundary for intervals that would
// otherwise require constructing an already-expired public preview or reason.
func consumptionFixture(t *testing.T) (*investigationFixture, contextFacts, *contextStorageWait) {
	t.Helper()
	f := newInvestigationFixture()
	target, _ := f.ResolvePod(t.Context(), f.target.Request)
	eligible := f.svc.Eligibility.ContextEligibilityCurrent(t.Context(), f.source(t, t.Context()), target.Target())
	capability, _ := f.ContextCapability(t.Context(), target.Target())
	retention, err := f.Resolve(t.Context(), privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 60, AnchorAt: f.now})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	w := &contextStorageWait{done: done, cancel: func() {}, until: f.now.Add(5 * time.Second), selection: f.store.Selection}
	return f, contextFacts{target: target, eligibility: eligible, capability: capability, retention: retention}, w
}

func TestContextStorageConsumptionRetainsPreviewRetentionAndReasonBounds(t *testing.T) {
	for _, bound := range []string{"preview", "retention-expiry", "reason"} {
		t.Run(bound, func(t *testing.T) {
			f, facts, owner := consumptionFixture(t)
			until := f.now.Add(100 * time.Millisecond)
			intent := f.intent()
			switch bound {
			case "preview":
				owner.until = until
			case "retention-expiry":
				facts.retention.ExpiresAt = until
			case "reason":
				intent.Reason = &value.ProtectedReasonRef{ExpiresAt: until}
			}
			var reads atomic.Int32
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				reads.Add(1)
				if deadline, _ := ctx.Deadline(); deadline.After(until) {
					t.Error("consumption widened retained interval")
				}
				out, err := f.ContextStorage(ctx, target)
				out.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
				return out, err
			})
			refresh := &countingRefresh{}
			f.svc.Refresh = refresh
			_, err := f.svc.consumeStorage(t.Context(), facts, intent, owner)
			if !errors.Is(err, context.DeadlineExceeded) || reads.Load() != 1 || refresh.demands.Load() != 1 {
				t.Fatal("consumption read past original interval", bound, err, reads.Load(), refresh.demands.Load())
			}
		})
	}
}

func TestContextStorageConsumptionStopsOnReadFailureOrInvalidSelection(t *testing.T) {
	for _, stage := range []string{"first", "after-wait"} {
		for _, failure := range []string{"adapter", "expired", "invalid", "wrong-root", "wrong-target", "binding-revision", "changed-selection"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				f, facts, owner := consumptionFixture(t)
				refresh := &countingRefresh{}
				f.svc.Refresh = refresh
				cause := errors.New("synthetic-private-storage-failure")
				var reads int
				f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
					reads++
					out, err := f.ContextStorage(ctx, target)
					out.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
					if stage == "after-wait" && reads == 1 {
						return out, err
					}
					switch failure {
					case "adapter":
						return ContextStorageObservation{}, cause
					case "expired":
						out.Binding.FreshUntil = f.now
					case "invalid":
						out.Selection.StoreID = ""
					case "wrong-root":
						out.Binding.RootID = fixtureID(999)
					case "wrong-target":
						out.Binding.WorkloadUID = "replacement"
					case "binding-revision":
						out.Binding.Revision.Generation++
					case "changed-selection":
						out.Selection.PoolRevision++
					}
					return out, err
				})
				_, err := f.svc.consumeStorage(t.Context(), facts, f.intent(), owner)
				wantReads, wantDemands := 1, int32(0)
				if stage == "after-wait" {
					wantReads, wantDemands = 2, 1
				}
				if err == nil || reads != wantReads || refresh.demands.Load() != wantDemands ||
					(failure == "adapter" && !errors.Is(err, cause)) ||
					(failure != "adapter" && !errors.Is(err, value.ErrChanged)) {
					t.Fatal("invalid or failed storage entered another wait", err, reads, refresh.demands.Load())
				}
			})
		}
	}
}

func TestContextStorageConsumptionPreservesDemandOwnership(t *testing.T) {
	for _, state := range []contextStorageDemand{storageDemandUnused, storageDemandAcknowledged, storageDemandFailed} {
		t.Run(string(rune('0'+state)), func(t *testing.T) {
			f, facts, owner := consumptionFixture(t)
			owner.demand = state
			var reads, demands int
			cause := errors.New("synthetic-private-demand-failure")
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error {
				demands++
				return cause
			})
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				reads++
				out, err := f.ContextStorage(ctx, target)
				if reads == 1 {
					out.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
				}
				return out, err
			})
			_, err := f.svc.consumeStorage(t.Context(), facts, f.intent(), owner)
			switch state {
			case storageDemandUnused:
				if !errors.Is(err, cause) || reads != 1 || demands != 1 || owner.demand != storageDemandFailed {
					t.Fatal("failed demand was retried or ignored", err, reads, demands)
				}
			case storageDemandAcknowledged:
				if err != nil || reads != 2 || demands != 0 {
					t.Fatal("consumption repeated its early demand", err, reads, demands)
				}
			case storageDemandFailed:
				if !errors.Is(err, value.ErrUnavailable) || reads != 1 || demands != 0 {
					t.Fatal("consumption repeated a failed early demand", err, reads, demands)
				}
			}
		})
	}
}

func TestContextStorageConsumptionJoinsCancellation(t *testing.T) {
	for _, stage := range []string{"hint", "read", "demand"} {
		t.Run(stage, func(t *testing.T) {
			f, facts, owner := consumptionFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			unblock := overlapRelease(release)
			var reads, demands atomic.Int32
			block := func(call context.Context) {
				close(entered)
				<-call.Done()
				close(cancelled)
				<-release
			}
			if stage == "hint" {
				owner.done = make(chan struct{})
				owner.cancel = cancel
				go func() {
					block(ctx)
					close(owner.done)
				}()
			}
			f.svc.Storage = consumptionStorageFunc(func(call context.Context, target authorization.Target) (ContextStorageObservation, error) {
				reads.Add(1)
				if stage == "read" {
					block(call)
				}
				out, err := f.ContextStorage(call, target)
				if stage == "demand" {
					out.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
				}
				return out, err // even a late positive read cannot survive cancellation
			})
			f.svc.Refresh = consumptionRefreshFunc(func(call context.Context, _ targets.Request) error {
				demands.Add(1)
				block(call)
				return nil // even a late successful demand cannot start more I/O
			})
			done, finished := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(finished)
				_, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
				done <- err
			}()
			defer func() {
				cancel()
				unblock()
				overlapSignal(t, finished, "consumption cleanup")
			}()
			overlapSignal(t, entered, "blocked "+stage)
			cancel()
			overlapSignal(t, cancelled, "cancelled "+stage)
			select {
			case <-done:
				t.Fatal("consumption returned while owned I/O was still running")
			default:
			}
			unblock()
			err := <-done
			wantReads, wantDemands := int32(1), int32(0)
			if stage == "hint" {
				wantReads = 0
			}
			if stage == "demand" {
				wantDemands = 1
			}
			if !errors.Is(err, context.Canceled) || reads.Load() != wantReads || demands.Load() != wantDemands {
				t.Fatal("cancelled consumption started more I/O or returned success", err, reads.Load(), demands.Load())
			}
		})
	}
}

func TestContextStorageConsumptionTimerRetainsCallerDeadline(t *testing.T) {
	f, facts, owner := consumptionFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	original, _ := ctx.Deadline()
	var reads, demands int
	f.svc.Storage = consumptionStorageFunc(func(call context.Context, target authorization.Target) (ContextStorageObservation, error) {
		reads++
		if until, _ := call.Deadline(); !until.Equal(original) {
			t.Error("read replaced original caller deadline")
		}
		out, err := f.ContextStorage(call, target)
		out.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
		return out, err
	})
	f.svc.Refresh = consumptionRefreshFunc(func(call context.Context, _ targets.Request) error {
		demands++
		if until, _ := call.Deadline(); !until.Equal(original) {
			t.Error("demand replaced original caller deadline")
		}
		return nil
	})
	_, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
	if !errors.Is(err, context.DeadlineExceeded) || reads != 1 || demands != 1 {
		t.Fatal("timer outlived caller and read again", err, reads, demands)
	}
}

func TestContextStorageConsumptionPreviewAndDiagnostic(t *testing.T) {
	for _, mode := range []string{"preview", "diagnostic"} {
		for _, initial := range []string{"live", "identity", "recovery"} {
			t.Run(mode+"/"+initial, func(t *testing.T) {
				f := newInvestigationFixture()
				var advance atomic.Int64
				f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
				source := f.source(t, t.Context())
				until := f.now.Add(1400 * time.Millisecond)
				switch initial {
				case "identity":
					source = &shortenedContinuationIdentity{source: source, until: until}
				case "recovery":
					f.svc.Recovery = consumptionRecovery{f, until}
				}
				refresh := &countingRefresh{}
				f.svc.Refresh = refresh
				var reads atomic.Int32
				f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
					out, err := f.ContextStorage(ctx, target)
					out.Binding.FreshUntil = f.now.Add(1200 * time.Millisecond)
					switch reads.Add(1) {
					case 2:
						advance.Store(int64(1150 * time.Millisecond))
					case 3:
						advance.Store(int64(1400 * time.Millisecond))
						out.Binding.ObservedAt, out.Binding.FreshUntil = until, until.Add(2*time.Second)
					}
					return out, err
				})
				var err error
				if mode == "preview" {
					_, err = f.svc.Preview(t.Context(), source, f.intent())
				} else {
					_, err = f.svc.CheckDiagnostic(t.Context(), source, f.intent().Target)
				}
				if (initial == "live" && err != nil) || (initial != "live" && !errors.Is(err, value.ErrChanged)) ||
					reads.Load() != 3 || refresh.demands.Load() != 1 || f.targetReads.Load() != 1 || f.admissions.Load() != 0 {
					t.Fatal("passive consumer lost the phase or original authority bound", err, reads.Load(), refresh.demands.Load())
				}
				if (initial != "live" || mode == "diagnostic") && len(f.previews) != 0 {
					t.Fatal("failed or passive diagnostic wrote a preview")
				}
			})
		}
	}
}

func TestContextStorageConsumptionChangedReviewStopsBeforeDemand(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	f.store.Selection.PoolRevision++
	var advance atomic.Int64
	storage := &marginStorageRead{investigationFixture: f, advance: &advance,
		elapsed: 1150 * time.Millisecond, until: f.now.Add(1200 * time.Millisecond)}
	f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
	refresh := &countingRefresh{}
	f.svc.Storage, f.svc.Refresh = storage, refresh
	var reports []string
	f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
	_, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "changed")
	if !errors.Is(err, value.ErrChanged) || storage.reads.Load() != 2 || refresh.demands.Load() != 0 ||
		f.admissions.Load() != 0 || !slices.Equal(reports, []string{"request/changed/storage"}) {
		t.Fatal("changed review waited or duplicated its diagnostic", err, storage.reads.Load(), refresh.demands.Load(), reports)
	}
}

func TestContextStorageConsumptionSharesActualHintDemand(t *testing.T) {
	for _, mode := range []string{"acknowledged", "failed-fresh", "failed-thin"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			var advance atomic.Int64
			f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
			var reads, demands atomic.Int32
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error {
				demands.Add(1)
				if mode != "acknowledged" {
					return errors.New("synthetic-private-hint-demand-failure")
				}
				return nil
			})
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				n := reads.Add(1)
				if n == 1 {
					return ContextStorageObservation{}, value.ErrChanged // existing cold-start hint
				}
				out, err := f.ContextStorage(ctx, target)
				switch mode {
				case "acknowledged":
					out.Binding.FreshUntil = f.now.Add(1200 * time.Millisecond)
					if n == 3 {
						advance.Store(int64(1150 * time.Millisecond))
					} else if n == 4 {
						advance.Store(int64(1400 * time.Millisecond))
						out.Binding.ObservedAt = f.now.Add(1400 * time.Millisecond)
						out.Binding.FreshUntil = f.now.Add(3400 * time.Millisecond)
					}
				case "failed-thin":
					out.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
				}
				return out, err
			})
			accepted, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, mode)
			if demands.Load() != 1 {
				t.Fatal("hint and consumer did not share one demand", demands.Load())
			}
			if mode == "failed-thin" {
				if !errors.Is(err, value.ErrUnavailable) || reads.Load() != 2 || f.admissions.Load() != 0 {
					t.Fatal("failed early demand restarted polling", err, reads.Load())
				}
				return
			}
			wantReads := int32(2)
			if mode == "acknowledged" {
				wantReads = 4
			}
			if err != nil || accepted.CaptureID != p.CaptureID || f.admissions.Load() != 1 || reads.Load() != wantReads {
				t.Fatal("hint outcome replaced independent final authority", err, reads.Load())
			}
		})
	}
}

func TestContextStorageConsumptionPinsFirstPassiveSelection(t *testing.T) {
	f, facts, owner := consumptionFixture(t)
	owner.selection = value.ContextStorageSelection{} // Preview/CheckDiagnostic
	refresh := &countingRefresh{}
	f.svc.Refresh = refresh
	reads := 0
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		reads++
		out, err := f.ContextStorage(ctx, target)
		if reads == 1 {
			out.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
		} else {
			out.Selection.PoolRevision++
		}
		return out, err
	})
	_, err := f.svc.consumeStorage(t.Context(), facts, f.intent(), owner)
	if !errors.Is(err, value.ErrChanged) || reads != 2 || refresh.demands.Load() != 1 || owner.selection != f.store.Selection {
		t.Fatal("passive consumption adopted a new storage selection", err, reads, owner.selection)
	}
}

func TestContextStorageConsumptionRequestRetainsPreviewDeadline(t *testing.T) {
	f := newInvestigationFixture()
	f.svc.Lifetime = time.Second
	p := f.preview(t)
	var advance atomic.Int64
	f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
	refresh := &countingRefresh{}
	f.svc.Refresh = refresh
	var reads atomic.Int32
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		out, err := f.ContextStorage(ctx, target)
		out.Binding.FreshUntil = f.now.Add(time.Second)
		switch reads.Add(1) {
		case 2:
			if until, _ := ctx.Deadline(); until.After(p.Deadline) {
				t.Error("consumer widened preview deadline")
			}
			advance.Store(int64(950 * time.Millisecond))
		case 3:
			advance.Store(int64(time.Second))
			out.Binding.ObservedAt, out.Binding.FreshUntil = p.Deadline, p.Deadline.Add(2*time.Second)
		}
		return out, err
	})
	_, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "original-preview")
	if !errors.Is(err, value.ErrChanged) || reads.Load() != 3 || refresh.demands.Load() != 1 || f.admissions.Load() != 0 {
		t.Fatal("storage renewal extended review lifetime", err, reads.Load(), refresh.demands.Load())
	}
}

func (a *consumptionAdmission) AdmitReviewedContext(ctx context.Context, id string, in value.Admission) (value.Accepted, error) {
	a.got = in
	return a.investigationFixture.AdmitReviewedContext(ctx, id, in)
}

// The early readiness observation A becomes thin before consumption. A new
// protected read B, not a renewed timestamp on A or refreshed target/facts,
// must supply the admission binding under the still-original authority.
func TestContextStorageConsumptionWaitsForIndependentBinding(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	beforeTargets := f.targetReads.Load()
	var advance atomic.Int64
	f.svc.Now = func() time.Time { return f.now.Add(time.Duration(advance.Load())) }
	facts := &consumptionFacts{investigationFixture: f, eligible: f.svc.Eligibility}
	f.svc.Eligibility, f.svc.Capabilities, f.svc.Retention = facts, facts, facts
	admit := &consumptionAdmission{investigationFixture: f}
	f.svc.Admission = admit
	refresh := &countingRefresh{}
	f.svc.Refresh = refresh
	var reads atomic.Int32
	var consumedAt, renewedAt time.Time
	var independent ContextStorageObservation
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		out, err := f.ContextStorage(ctx, target)
		out.Binding.FreshUntil = f.now.Add(1200 * time.Millisecond)
		switch reads.Add(1) {
		case 1: // readiness A: 1.2 seconds left
		case 2: // authoritative A: only 50 milliseconds left
			advance.Store(int64(1150 * time.Millisecond))
			consumedAt = time.Now()
		case 3:
			renewedAt = time.Now()
			advance.Store(int64(1400 * time.Millisecond))
			out.Binding.ObservedAt = f.now.Add(1400 * time.Millisecond)
			out.Binding.FreshUntil = f.now.Add(3400 * time.Millisecond)
			independent = out
		default:
			t.Error("unexpected storage read")
		}
		return out, err
	})
	accepted, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "consumption")
	if err != nil || accepted.CaptureID != p.CaptureID {
		t.Fatal("early ready binding lost its margin instead of waiting within original bounds", err)
	}
	if reads.Load() != 3 || refresh.demands.Load() != 1 || f.targetReads.Load()-beforeTargets != 1 ||
		facts.caps != 1 || facts.ret != 1 || facts.eligibility != 2 || f.admissions.Load() != 1 {
		t.Fatal("consumption repeated an early hint, authority read, demand or effect", reads.Load(), refresh.demands.Load(), facts, f.admissions.Load())
	}
	if renewedAt.Sub(consumedAt) < 250*time.Millisecond || admit.got.Storage != independent.Binding ||
		!admit.got.Storage.ObservedAt.Equal(f.now.Add(1400*time.Millisecond)) ||
		!admit.got.Storage.FreshUntil.Equal(f.now.Add(3400*time.Millisecond)) {
		t.Fatal("consumption changed cadence or original storage timestamps", renewedAt.Sub(consumedAt), admit.got.Storage)
	}
}
