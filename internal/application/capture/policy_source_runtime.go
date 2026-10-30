package capture

import (
	"context"
	"errors"
	"slices"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// OngoingRecorderObserver amortizes regional exchange cost while retaining
// every exact Pod/source request and its independently returned original bounds.
// There is no implicit single-request fallback or retry after batch refusal.
type OngoingRecorderObserver interface {
	ResolveOngoingRecorders(context.Context, []targets.OngoingRecorderRequest) ([]targets.OngoingRecorderResolution, error)
}

// sourceStage names the bounded step that failed, for the trigger's
// content-free counters. It adds no state or retry.
type sourceStage struct {
	stage string
	err   error
}

func (e sourceStage) Error() string { return e.stage + ": " + e.err.Error() }
func (e sourceStage) Unwrap() error { return e.err }

// FixedStep names this bounded step in the transport's refusal report.
func (e sourceStage) FixedStep() string { return e.stage }

func staged(stage string, err error) error {
	if err == nil {
		return nil
	}
	return sourceStage{stage, err}
}

// StagedSourceError lets a source adapter name its own failing step.
func StagedSourceError(stage string, err error) error { return staged(stage, err) }

// sourceStageOf returns the first labelled source step of err, or "".
func sourceStageOf(err error) string {
	var s sourceStage
	if errors.As(err, &s) {
		return s.stage
	}
	return ""
}

// PolicySourceRuntime maintains ordinary ongoing rings on the existing policy
// poll. It creates no timer, watch, retry queue, capture or disclosure route.
// Metadata uses bounded batches; SQL admission and dispatch remain serialized.
// This is not maximum-replica installed qualification. Original whole-workload
// and current-fact deadlines always win.
type PolicySourceRuntime struct {
	Ledger     PolicySourceLedger
	Dispatcher PolicySourceDispatcher
	Observer   OngoingRecorderObserver
	Recovery   fleetapp.RecoveryReader
	Retention  ContextRetentionResolver
	Settings   ApprovalSettings
	// Storage and Refresh keep the workload's 30-second storage binding fresh
	// through the existing ADR-200 demand lane; nil leaves refresh to discovery.
	Storage ContextStorageReader
	Refresh ContextCapacityRefresh
	Now     func() time.Time
	NewID   func() string
}

// sourceStorageMargin asks for a binding refresh before the next 15-second
// maintenance tick (plus its five-second cohort) could find it expired.
const sourceStorageMargin = 20 * time.Second

// demandStorage records at most one refresh demand per tick when the binding
// is missing or about to expire. It waits for nothing and grants nothing;
// admission still checks the refreshed binding itself.
func (s *PolicySourceRuntime) demandStorage(ctx context.Context, o targets.RestartObservation) {
	if s.Storage == nil || s.Refresh == nil || len(o.Pods) == 0 {
		return
	}
	r := targets.Request{ClusterID: o.ClusterID, Namespace: o.Namespace, Workload: o.Workload, PodName: o.Pods[0].Name, PodUID: o.Pods[0].UID}
	v, err := s.Storage.ContextStorage(ctx, targets.PodResolution{Request: r}.Target())
	if err == nil && !v.Binding.FreshUntil.Before(s.Now().Add(sourceStorageMargin)) {
		return
	}
	_ = s.Refresh.DemandCapacityRefresh(ctx, r)
}

func (s *PolicySourceRuntime) configured() bool {
	return s != nil && s.Ledger != nil && s.Dispatcher != nil && s.Observer != nil && s.Recovery != nil && s.Retention != nil && s.Settings != nil && s.Now != nil && s.NewID != nil
}

func (s *PolicySourceRuntime) Sweep(ctx context.Context) error {
	if !s.configured() || ctx == nil {
		return value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	ended, err := s.Ledger.SweepSources(call)
	if err != nil {
		return err
	}
	var failed error
	for _, row := range ended {
		if call.Err() != nil {
			return errors.Join(failed, call.Err())
		}
		failed = errors.Join(failed, s.Dispatcher.StopSource(call, row.ClusterID, row.Binding))
	}
	return failed
}

// StopPolicy is a restrictive known-negative operation. It neither invents a
// fresh workload proof nor waits for a deleted Pod to reappear before stopping.
func (s *PolicySourceRuntime) StopPolicy(ctx context.Context, policy string) error {
	if !s.configured() || ctx == nil {
		return value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	rows, err := s.Ledger.ListSources(call, policy)
	if err != nil {
		return err
	}
	var failed error
	for _, row := range rows {
		if call.Err() != nil {
			return errors.Join(failed, call.Err())
		}
		if err = s.Ledger.EndSource(call, row.Binding.SourceID); err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		failed = errors.Join(failed, s.Dispatcher.StopSource(call, row.ClusterID, row.Binding))
	}
	return failed
}

func (s *PolicySourceRuntime) Maintain(ctx context.Context, p value.RestartPolicy, a authorization.AcceptedPolicyAuthority, o targets.RestartObservation) error {
	if !s.configured() || ctx == nil || ctx.Err() != nil || !p.Valid() || p.Recorder == nil || p.Recorder.Action.ExecutionMode != "ongoing" || !a.Valid(s.Now()) || !o.Valid(s.Now()) || !o.Answers(p.Request()) || o.ClusterID != a.ClusterID || o.Namespace.UID != a.NamespaceUID || o.Workload.UID != a.WorkloadUID || len(o.Pods) > p.ObservedPods {
		return staged("precheck", value.ErrUnavailable)
	}
	cohortStarted := s.Now().UTC().Truncate(time.Microsecond)
	cohortUntil := identity.Earlier(cohortStarted.Add(5*time.Second), identity.Earlier(o.FreshUntil, a.NotAfter))
	cohort, finish := context.WithDeadline(ctx, cohortUntil)
	defer finish()
	ctx = cohort
	s.demandStorage(ctx, o)
	rows, err := s.Ledger.ListSources(ctx, a.PolicyUID)
	if err != nil {
		return staged("list", err)
	}
	existing := make(map[string]PolicySourceState, len(rows))
	present := make(map[string]bool, len(o.Pods))
	for _, pod := range o.Pods {
		present[pod.UID] = true
	}
	var failed error
	for _, row := range rows {
		if !present[row.Binding.PodUID] || row.Binding.Scope != [32]byte(a.ScopeDigest) || !s.Now().Before(row.HardUntil) {
			if e := s.Ledger.EndSource(ctx, row.Binding.SourceID); e != nil {
				failed = errors.Join(failed, e)
			} else {
				failed = errors.Join(failed, s.Dispatcher.StopSource(ctx, row.ClusterID, row.Binding))
			}
			continue
		}
		existing[row.Binding.PodUID] = row
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil {
		return errors.Join(failed, staged("recovery", err))
	}
	settings, err := s.Settings.IdentityPolicy(ctx, a.Creator.Issuer)
	if err != nil || settings.Validate(s.Now()) != nil || settings.Issuer != a.Creator.Issuer {
		return errors.Join(failed, staged("settings", value.ErrUnavailable))
	}
	// This check interval starts once. Independent regional/retention reads can
	// only shorten it, never freshen a complete workload observation.
	started := cohortStarted
	until := identity.Earlier(cohortUntil, identity.Earlier(o.FreshUntil, identity.Earlier(recovery.FreshUntil, identity.Earlier(settings.FreshUntil, a.NotAfter))))
	call, end := context.WithDeadline(ctx, until)
	defer end()
	type observedSource struct {
		value targets.OngoingRecorderResolution
		err   error
	}
	prefetched := map[string]observedSource{}
	{
		batch := s.Observer
		requests := make([]targets.OngoingRecorderRequest, 0, len(o.Pods))
		for _, pod := range o.Pods {
			old, known := existing[pod.UID]
			if known && !old.EndedAt.IsZero() {
				continue
			}
			request := targets.OngoingRecorderRequest{Target: targets.Request{ClusterID: o.ClusterID, Namespace: o.Namespace, Workload: o.Workload, PodName: pod.Name, PodUID: pod.UID}}
			if known {
				request.SourceID, request.Fence = old.Binding.SourceID, old.Binding.Fence
			}
			requests = append(requests, request)
		}
		for first := 0; first < len(requests); first += targets.OngoingRecorderBatchLimit {
			last := min(first+targets.OngoingRecorderBatchLimit, len(requests))
			values, e := batch.ResolveOngoingRecorders(call, requests[first:last])
			if e == nil && len(values) != last-first {
				e = value.ErrUnavailable
			}
			for i, request := range requests[first:last] {
				result := observedSource{err: e}
				if e == nil {
					result.value = values[i]
				}
				prefetched[request.Target.PodUID] = result
			}
			if call.Err() != nil || !s.Now().Before(until) {
				break
			}
		}
	}
	for _, pod := range o.Pods {
		if call.Err() != nil || !s.Now().Before(until) {
			return errors.Join(failed, staged("deadline", value.ErrUnavailable))
		}
		old, known := existing[pod.UID]
		if known && !old.EndedAt.IsZero() {
			continue
		} // original quarantine owns the slot
		request := targets.OngoingRecorderRequest{Target: targets.Request{ClusterID: o.ClusterID, Namespace: o.Namespace, Workload: o.Workload, PodName: pod.Name, PodUID: pod.UID}}
		if known {
			request.SourceID, request.Fence = old.Binding.SourceID, old.Binding.Fence
		}
		var resolved targets.OngoingRecorderResolution
		var e error
		observed, ok := prefetched[pod.UID]
		if !ok {
			failed = errors.Join(failed, staged("resolve-missing", value.ErrUnavailable))
			continue
		}
		resolved, e = observed.value, observed.err
		if e != nil {
			failed = errors.Join(failed, staged("resolve", e))
			continue
		}
		if !resolved.Recorder.ValidSource(s.Now()) || resolved.Recorder.Target.Request != request.Target {
			failed = errors.Join(failed, staged("resolve-invalid", value.ErrUnavailable))
			continue
		}
		node := *resolved.Recorder.Recorder.Source
		if known && (old.Binding.NodeUID != node.NodeUID || old.Binding.BootID != node.BootID || old.Binding.CollectorPodUID != node.CollectorPodUID || old.Binding.CollectorEpoch != node.CollectorEpoch) {
			if e = s.Ledger.EndSource(call, old.Binding.SourceID); e == nil {
				e = s.Dispatcher.StopSource(call, old.ClusterID, old.Binding)
			}
			failed = errors.Join(failed, e)
			continue
		}
		// Closed and natural-stopped sources cannot be revived. A natural stop
		// keeps its observed grace/history: marking SQL terminal sends no Stop.
		if known && resolved.State != nil && (resolved.State.Closed || resolved.State.Stopped || resolved.State.InputUnknown) {
			failed = errors.Join(failed, s.Ledger.EndSource(call, old.Binding.SourceID))
			continue
		}
		if known && resolved.State == nil && !resolved.ReportedAt.Before(old.StartBy) && identity.Fresh(resolved.ReportedAt, resolved.ReportFreshUntil, s.Now(), collector.StatusStaleAfter) {
			// Unknown original start is never retried under a fresh start window.
			if e = s.Ledger.EndSource(call, old.Binding.SourceID); e == nil {
				e = s.Dispatcher.StopSource(call, old.ClusterID, old.Binding)
			}
			failed = errors.Join(failed, e)
			continue
		}
		ceiling := resolved.Ceilings
		slots := min(int64(p.ObservedPods), ceiling.MaxActiveSources)
		if slots < 1 || ceiling.MaxActiveSources > collector.MaxActiveSources || ceiling.InputBytesPerSecond < 1 || ceiling.InputBytesPerSecond > collector.MaxInputRate || ceiling.InputBurstBytes < 1 || ceiling.InputBurstBytes > collector.MaxInputBurst {
			failed = errors.Join(failed, staged("ceilings", value.ErrCapacity))
			continue
		}
		rate := min(ceiling.InputBytesPerSecond, ceiling.InputBurstBytes) / slots
		if rate < 1 {
			failed = errors.Join(failed, value.ErrCapacity)
			continue
		}
		retention, e := s.Retention.Resolve(call, privacy.Input{Target: resolved.Recorder.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: p.RetentionSeconds, AnchorAt: started})
		if e != nil {
			failed = errors.Join(failed, staged("retention", e))
			continue
		}
		age, ageErr := time.ParseDuration(p.Recorder.Action.RingMaxAge)
		if ageErr != nil {
			return errors.Join(failed, value.ErrInvalid)
		}
		if !retention.Proof.Valid(s.Now()) || retention.Target != resolved.Recorder.Target.Target() || !s.Now().Before(retention.ValidUntil) {
			failed = errors.Join(failed, staged("retention-proof", value.ErrUnavailable))
			continue
		}
		if age > retention.ExpiresAt.Sub(retention.AnchorAt) {
			// A current administrator shortening can make this fixed ring
			// unsupported. Stop its live bytes; do not turn the first packet's
			// expiry into a new lifetime for the continuing source.
			failed = errors.Join(failed, value.ErrChanged)
			if known {
				if e = s.Ledger.EndSource(call, old.Binding.SourceID); e == nil {
					e = s.Dispatcher.StopSource(call, old.ClusterID, old.Binding)
				}
				failed = errors.Join(failed, e)
			}
			continue
		}
		check := PolicySourceCheck{Policy: p, Authority: a, Target: resolved.Recorder.Target, Node: node, Recovery: recovery, Retention: retention, Settings: settings, BytesPerSecond: rate, SourceSlots: slots, ObservedAt: started, ValidUntil: until}
		if !known {
			check.SourceID, check.Fence = s.NewID(), s.NewID()
			check.Initial = true
			// Bound the first tranche by this complete actual candidate cohort
			// and at most one active leaf plus its existing one-second burst.
			// This is prepaid capacity, not a measured traffic prediction.
			fair := a.Limits.MaxObservedBytes / int64(len(o.Pods))
			lead := rate * int64((collector.SourceLeafLifetime+time.Second)/time.Second)
			check.InitialCredit = min(fair, lead)
			if check.InitialCredit < 1 {
				failed = errors.Join(failed, value.ErrCapacity)
				continue
			}
		} else {
			check.SourceID, check.Fence = old.Binding.SourceID, old.Binding.Fence
			check.BytesPerSecond = old.BytesPerSecond
			check.ExpectedCredit = old.Credit
			if resolved.State == nil {
				if s.Now().Before(old.StartBy) {
					check.Initial = true
					check.InitialCredit = old.InitialCredit
					check.ExpectedCredit = 0
				}
				// A pre-start complete report is not proof of absence. After
				// the old start closes, only an existing-source renewal may
				// be delivered; it cannot create a replacement engine.
			} else {
				state := resolved.State
				if state.SourceID != old.Binding.SourceID || state.Fence != old.Binding.Fence || state.Credit < 1 || state.Credit > old.Credit || state.ObservedBytes < 0 || state.ObservedBytes > state.Credit || state.ObservedAt.After(s.Now()) || !s.Now().Before(state.FreshUntil) {
					failed = errors.Join(failed, staged("state", value.ErrUnavailable))
					continue
				}
				// Feedback is authenticated accounting, not current authority. Only
				// measured cumulative consumption can ask for additional prepaid credit.
				remaining := old.Credit - state.ObservedBytes
				threshold := old.BytesPerSecond * int64(collector.SourceLeafLifetime/time.Second)
				if state.ObservedBytes > 0 && remaining < threshold {
					check.AdditionalCredit = threshold - remaining
				}
			}
		}
		admission, e := s.Ledger.AdmitSource(call, check)
		if e != nil {
			if sourceStageOf(e) == "" {
				e = staged("admit", e)
			}
			failed = errors.Join(failed, e)
			if known && (errors.Is(e, value.ErrDenied) || errors.Is(e, value.ErrChanged) || errors.Is(e, value.ErrConflict)) {
				if endErr := s.Ledger.EndSource(call, old.Binding.SourceID); endErr == nil {
					failed = errors.Join(failed, s.Dispatcher.StopSource(call, old.ClusterID, old.Binding))
				} else {
					failed = errors.Join(failed, endErr)
				}
			}
			continue
		}
		if call.Err() != nil || !admission.Permit.Dispatchable(s.Now()) {
			failed = errors.Join(failed, staged("permit", value.ErrUnavailable))
			continue
		}

		source := collector.PacketSource{Permit: admission.Permit, Resources: admission.Resources, Ring: collector.SourceRingLimits{MaxAge: age, MaxBytes: p.Recorder.Action.RingMaxBytes, SegmentBytes: p.Recorder.Action.SegmentBytes, MaxSegments: p.Recorder.Action.MaxSegments, MaxFrozenBytes: p.Recorder.Action.MaxFrozenBytes, MaxConcurrentSnapshots: p.Recorder.Action.MaxConcurrentSnapshots}}
		if p.Recorder.Filter != nil {
			source.Program = slices.Clone(p.Recorder.Filter.Program)
		}
		if !source.Valid() {
			failed = errors.Join(failed, value.ErrChanged)
			continue
		}
		// Signing/delivery retains this same original call and exact committed
		// SourceID/fence/cumulative credit. Unknown delivery never refunds it.
		if e = s.Dispatcher.DispatchSource(call, check.Target, node, source); e != nil && sourceStageOf(e) == "" {
			e = staged("dispatch", e)
		}
		failed = errors.Join(failed, e)
	}
	return failed
}
