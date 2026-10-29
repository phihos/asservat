package capture

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Controlled scheduling only: accepted authority, SQL and node effects are
// explicit doubles, not production grants. A regional query slot takes 300ms;
// it never extends the original complete workload observation's five seconds.
// No provider, collector, wall-clock sleep or incident capture runs here.
type sourceCohortFixture struct {
	t                                 *testing.T
	f                                 *investigationFixture
	settings                          *teamRecordingSettings
	authority                         authorization.AcceptedPolicyAuthority
	policy                            value.RestartPolicy
	runtime                           *PolicySourceRuntime
	base, tickStart, tickEnd          time.Time
	queryCost                         time.Duration
	rows                              map[string]PolicySourceState
	nodePermits                       map[string]collector.SourcePermit
	nodeMeters                        map[string]*collector.SourceMeter
	firstDispatch                     map[string]time.Time
	dispatches, ended, stops, queries int
	admissions                        []PolicySourceCheck
	hideExistingStatus                bool
	naturalStopped                    bool
	confirmAbsent                     bool
	batchCalls                        int
	actualReplicas                    int
	wirePerDispatch                   int64
}

func newSourceCohortFixture(t *testing.T, replicas int) *sourceCohortFixture {
	t.Helper()
	f, accepted, settings, _ := newTeamRecordingFixture(t)
	p, err := compileSpec(t, restartSpec())
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := compiler.CompileOngoingPolicyRecorder(*networkComposition(), &stubFilters{})
	if err != nil {
		t.Fatal(err)
	}
	p.ClusterID, p.Namespace = accepted.authority.ClusterID, f.target.Request.Namespace.Name
	p.WorkloadKind, p.WorkloadName = f.target.Request.Workload.Kind, f.target.Request.Workload.Name
	p.Recorder, p.ObservedPods, p.RetentionSeconds = &recorder, replicas, 60
	if !p.Valid() || p.Recorder.Action.ExecutionMode != "ongoing" {
		t.Fatal("invalid ongoing cohort fixture")
	}
	// Ten 16MiB rings and ten 1MiB/s slices fit each 256MiB/16MiB/s
	// node in the twenty-replica case; no capacity denial explains its tail.
	if replicas > targets.MaxRestartPods || int64(min(replicas, 10))*recorder.Action.SegmentBytes*int64(recorder.Action.MaxSegments) > 256<<20 {
		t.Fatal("cohort no longer fits the explicit two-node ring envelope")
	}
	s := &sourceCohortFixture{t: t, f: f, settings: settings, authority: accepted.authority, policy: p, base: f.now, queryCost: 300 * time.Millisecond, actualReplicas: replicas, wirePerDispatch: 1000, rows: map[string]PolicySourceState{}, nodePermits: map[string]collector.SourcePermit{}, nodeMeters: map[string]*collector.SourceMeter{}, firstDispatch: map[string]time.Time{}}
	s.runtime = &PolicySourceRuntime{Ledger: s, Dispatcher: s, Observer: s, Recovery: f, Retention: f, Settings: settings, Now: func() time.Time { return f.now }, NewID: func() string { return fixtureID(1000 + int(f.newIDs.Add(1))) }}
	return s
}

func (s *sourceCohortFixture) maintain(tick int) error {
	s.tickStart = s.base.Add(time.Duration(tick) * value.TriggerPollInterval)
	s.tickEnd = s.tickStart.Add(5 * time.Second)
	s.f.now = s.tickStart
	s.settings.policy.ObservedAt, s.settings.policy.FreshUntil = s.tickStart, s.tickEnd
	o := targets.RestartObservation{ClusterID: s.authority.ClusterID, Namespace: s.f.target.Request.Namespace, Workload: s.f.target.Request.Workload, ObservedAt: s.tickStart, FreshUntil: s.tickEnd, Pods: []targets.PodRestarts{}}
	for n := 0; n < s.actualReplicas; n++ {
		o.Pods = append(o.Pods, targets.PodRestarts{Name: fmt.Sprintf("api-%02d", n), UID: fixtureID(200 + n)})
	}
	if !o.Valid(s.f.now) || !o.Answers(s.policy.Request()) {
		s.t.Fatal("invalid original workload observation")
	}
	ctx, cancel := context.WithTimeout(s.t.Context(), 90*time.Second)
	defer cancel()
	return s.runtime.Maintain(ctx, s.policy, s.authority, o)
}

func (s *sourceCohortFixture) bound(ctx context.Context) bool {
	end, ok := ctx.Deadline()
	if !ok || end.After(s.tickEnd) {
		s.t.Fatalf("source operation extended original workload proof: %v %v", ok, end)
	}
	return ctx.Err() == nil && s.f.now.Before(end)
}
func (s *sourceCohortFixture) ResolveOngoingRecorder(ctx context.Context, r targets.OngoingRecorderRequest) (targets.OngoingRecorderResolution, error) {
	s.queries++
	began := s.f.now
	s.f.now = s.f.now.Add(s.queryCost)
	return s.resolveResult(ctx, r, began)
}

func (s *sourceCohortFixture) resolveResult(ctx context.Context, r targets.OngoingRecorderRequest, began time.Time) (targets.OngoingRecorderResolution, error) {
	if !s.bound(ctx) {
		return targets.OngoingRecorderResolution{}, value.ErrUnavailable
	}
	p := s.f.target
	p.Request = r.Target
	p.Pin.Namespace, p.Pin.NamespaceUID, p.Pin.Name, p.Pin.UID = r.Target.Namespace.Name, r.Target.Namespace.UID, r.Target.PodName, r.Target.PodUID
	p.ObservedAt, p.FreshUntil = began, s.tickEnd
	n := 0
	for i := 0; i < s.actualReplicas; i++ {
		if r.Target.PodUID == fixtureID(200+i) {
			n = i / 10
			break
		}
	}
	source := &targets.PacketSourceObservation{PodUID: r.Target.PodUID, NodeUID: fixtureID(400 + n), BootID: fixtureID(500 + n), CollectorPodUID: fixtureID(600 + n), CollectorEpoch: fixtureID(700 + n), ObservedAt: s.f.now, FreshUntil: s.tickEnd}
	out := targets.OngoingRecorderResolution{Recorder: targets.RecorderResolution{Target: p, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: source}}, Ceilings: targets.RecorderSourceCeilings{MaxActiveSources: 16, InputBytesPerSecond: 16 << 20, InputBurstBytes: 16 << 20, RingBytes: 256 << 20, FrozenBytes: 256 << 20}}
	out.ReportedAt = s.tickStart
	if s.hideExistingStatus && !s.confirmAbsent {
		out.ReportedAt = s.base
	}
	out.ReportFreshUntil = out.ReportedAt.Add(collector.StatusStaleAfter)
	if permit, ok := s.nodePermits[r.SourceID]; ok && !s.hideExistingStatus {
		out.State = &targets.RecorderSourceState{SourceID: permit.Binding.SourceID, Fence: permit.Binding.Fence, IssuedAt: permit.IssuedAt, LeafUntil: permit.LeafUntil, Credit: permit.Credit, ObservedBytes: s.nodeMeters[r.SourceID].ObservedBytes(), ObservedAt: s.tickStart, FreshUntil: s.tickStart.Add(collector.StatusStaleAfter), Stopped: s.naturalStopped}
	}
	if !out.Recorder.ValidSource(s.f.now) {
		s.t.Fatal("invalid current regional fixture result")
	}
	return out, nil
}
func (s *sourceCohortFixture) ListSources(context.Context, string) ([]PolicySourceState, error) {
	out := make([]PolicySourceState, 0, len(s.rows))
	for _, row := range s.rows {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Binding.SourceID < out[j].Binding.SourceID })
	return out, nil
}
func (s *sourceCohortFixture) AdmitSource(ctx context.Context, in PolicySourceCheck) (PolicySourceAdmission, error) {
	if !s.bound(ctx) || in.ValidUntil.After(s.tickEnd) {
		return PolicySourceAdmission{}, value.ErrUnavailable
	}
	s.admissions = append(s.admissions, in)
	resource := collector.SourceResources{PolicyUID: "accepted-resource-policy"}
	row, known := s.rows[in.Node.PodUID]
	if !known {
		if !in.Initial {
			return PolicySourceAdmission{}, value.ErrConflict
		}
		b := collector.SourceBinding{RootID: s.f.svc.RootID, PolicyUID: s.authority.PolicyUID, AcceptanceID: fixtureID(800), SourceID: in.SourceID, Fence: in.Fence, ActionID: s.policy.Recorder.Action.ID, PodUID: in.Node.PodUID, NodeUID: in.Node.NodeUID, BootID: in.Node.BootID, CollectorPodUID: in.Node.CollectorPodUID, CollectorEpoch: in.Node.CollectorEpoch, Scope: [32]byte(s.authority.ScopeDigest), ExpectationDigest: [32]byte(s.policy.Recorder.Digest), ResourceDigest: deliveryapp.SourceResourcesDigest(resource)}
		row = PolicySourceState{Binding: b, ClusterID: s.authority.ClusterID, NamespaceUID: s.authority.NamespaceUID, WorkloadUID: s.authority.WorkloadUID, StartedAt: s.f.now, HardUntil: s.authority.NotAfter, StartBy: s.tickEnd, InitialLeafUntil: s.f.now.Add(collector.SourceLeafLifetime), Credit: in.InitialCredit, InitialCredit: in.InitialCredit, BytesPerSecond: in.BytesPerSecond}
	} else if !row.EndedAt.IsZero() || row.Binding.SourceID != in.SourceID || row.Binding.Fence != in.Fence {
		return PolicySourceAdmission{}, value.ErrConflict
	}
	issued := s.f.now
	leaf := issued.Add(collector.SourceLeafLifetime)
	if in.Initial {
		issued = row.StartedAt
		leaf = row.InitialLeafUntil
	}
	permit := collector.SourcePermit{Binding: row.Binding, StartedAt: row.StartedAt, HardUntil: row.HardUntil, StartBy: row.StartBy, IssuedAt: issued, DispatchUntil: s.tickEnd, LeafUntil: leaf, Credit: row.Credit, BytesPerSecond: row.BytesPerSecond}
	if !permit.Dispatchable(s.f.now) {
		return PolicySourceAdmission{}, value.ErrUnavailable
	}
	s.rows[in.Node.PodUID] = row
	return PolicySourceAdmission{Permit: permit, Resources: resource, First: !known}, nil
}
func (s *sourceCohortFixture) DispatchSource(ctx context.Context, _ targets.PodResolution, _ targets.PacketSourceObservation, source collector.PacketSource) error {
	if !s.bound(ctx) || !source.Valid() {
		return value.ErrUnavailable
	}
	p := source.Permit
	if meter, ok := s.nodeMeters[p.Binding.SourceID]; ok {
		if err := meter.Renew(p, s.f.now); err != nil {
			return err
		}
	} else {
		meter, err := collector.NewSourceMeter(p, s.f.now)
		if err != nil {
			return err
		}
		s.nodeMeters[p.Binding.SourceID] = meter
	}
	// Use the actual cumulative domain meter for one content-free wire debit
	// per maintained source. A renewal cannot reset its counters or tokens.
	if s.wirePerDispatch > 0 {
		if err := s.nodeMeters[p.Binding.SourceID].Charge(s.wirePerDispatch, s.f.now); err != nil {
			return err
		}
	}
	s.nodePermits[p.Binding.SourceID] = p
	s.dispatches++
	if _, seen := s.firstDispatch[p.Binding.PodUID]; !seen {
		s.firstDispatch[p.Binding.PodUID] = s.f.now
	}
	return nil
}
func (s *sourceCohortFixture) EndSource(_ context.Context, id string) error {
	s.ended++
	for pod, row := range s.rows {
		if row.Binding.SourceID == id {
			row.EndedAt = s.f.now
			s.rows[pod] = row
		}
	}
	return nil
}
func (s *sourceCohortFixture) StopSource(_ context.Context, _ string, _ collector.SourceBinding) error {
	s.stops++
	return nil
}
func (s *sourceCohortFixture) SweepSources(context.Context) ([]PolicySourceState, error) {
	return nil, nil
}

// The production batch query amortizes one regional exchange across
// at most the shared reply-bound number of exact requests. It does not make local API/SQL work free; this
// fixture isolates the remote round-trip cost that caused the serial RED.
func (s *sourceCohortFixture) ResolveOngoingRecorders(ctx context.Context, requests []targets.OngoingRecorderRequest) ([]targets.OngoingRecorderResolution, error) {
	if len(requests) < 1 || len(requests) > targets.OngoingRecorderBatchLimit {
		s.t.Fatal("unbounded source batch", len(requests))
	}
	s.batchCalls++
	began := s.f.now
	s.f.now = s.f.now.Add(s.queryCost)
	values := make([]targets.OngoingRecorderResolution, 0, len(requests))
	for _, r := range requests {
		s.queries++
		value, err := s.resolveResult(ctx, r, began)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func TestPolicySourceCohortEventuallyVisitsAllAuthorizedReplicas(t *testing.T) {
	f := newSourceCohortFixture(t, 20)
	// Twenty replicas fit two independent16-source node ceilings. The policy's
	// incident target remains triggeringPod/maxPods1; source coverage is separate.
	for tick := 0; tick < 4; tick++ {
		err := f.maintain(tick)
		t.Logf("tick=%d queries=%d batches=%d distinctDispatched=%d dispatches=%d admissions=%d result=%v", tick, f.queries, f.batchCalls, len(f.firstDispatch), f.dispatches, len(f.admissions), err)
		if err != nil || f.dispatches != (tick+1)*20 || f.batchCalls != (tick+1)*((20+targets.OngoingRecorderBatchLimit-1)/targets.OngoingRecorderBatchLimit) || f.ended != 0 || f.stops != 0 {
			t.Fatal("bounded source cohort lost maintenance/continuity", tick, err, f.dispatches, f.batchCalls, f.ended, f.stops)
		}
		for sourceID, meter := range f.nodeMeters {
			if meter.ObservedBytes() != int64(tick+1)*1000 {
				t.Fatal("source input counter reset across renewal", sourceID, meter.ObservedBytes())
			}
		}
		for _, admission := range f.admissions[tick*20:] {
			if admission.Initial != (tick == 0) || admission.AdditionalCredit != 0 {
				t.Fatal("quiet maintenance restarted source or blindly bought another input slice", tick, admission.Initial, admission.AdditionalCredit)
			}
		}
	}
	if len(f.firstDispatch) != 20 {
		t.Fatalf("stable cohort starved authorized replicas across four fresh policy cycles: reached=%d want20; querycost=300ms and original proof interval=5s", len(f.firstDispatch))
	}
}

func TestPolicySourcePreArmReportAbsenceDoesNotStopHealthySource(t *testing.T) {
	f := newSourceCohortFixture(t, 1)
	if err := f.maintain(0); err != nil || f.dispatches != 1 {
		t.Fatal("initial source", err, f.dispatches)
	}
	first := f.admissions[0]
	// At the next policy tick, the node's15s status POST may still be in
	// flight. Its retained complete pre-arm report has no source row; the
	// original local source is healthy and its30s leaf is still current.
	f.hideExistingStatus = true
	err := f.maintain(1)
	t.Logf("preArmReportAbsent result=%v ended=%d stopMessages=%d dispatches=%d", err, f.ended, f.stops, f.dispatches)
	if f.ended != 0 || f.stops != 0 {
		t.Fatal("absence from an older pre-arm node report was treated as a current negative")
	}
	if len(f.admissions) != 2 || f.admissions[1].Initial || f.admissions[1].AdditionalCredit != 0 || f.admissions[1].ExpectedCredit != first.InitialCredit {
		t.Fatal("unknown status did not retain an existing-only quiet renewal without new credit")
	}
}

var _ PolicySourceLedger = (*sourceCohortFixture)(nil)
var _ PolicySourceDispatcher = (*sourceCohortFixture)(nil)
var _ OngoingRecorderObserver = (*sourceCohortFixture)(nil)

func TestPolicySourceNaturalStopDoesNotEraseItsRetainedGrace(t *testing.T) {
	f := newSourceCohortFixture(t, 1)
	if err := f.maintain(0); err != nil || f.dispatches != 1 {
		t.Fatal("initial source", err, f.dispatches)
	}
	f.naturalStopped = true
	err := f.maintain(1)
	if err != nil || f.ended != 1 || f.stops != 0 || f.dispatches != 1 || len(f.admissions) != 1 {
		t.Fatal("natural source stop was renewed or explicit Stop erased its retained ring grace", err, f.ended, f.stops, f.dispatches, len(f.admissions))
	}
}

func TestPolicySourceCurrentReportAbsenceEndsOriginalSource(t *testing.T) {
	f := newSourceCohortFixture(t, 1)
	if err := f.maintain(0); err != nil || f.dispatches != 1 {
		t.Fatal("initial source", err, f.dispatches)
	}
	f.hideExistingStatus, f.confirmAbsent = true, true
	f.nodePermits = map[string]collector.SourcePermit{}
	err := f.maintain(1)
	if err != nil || f.ended != 1 || f.stops != 1 || f.dispatches != 1 || len(f.admissions) != 1 {
		t.Fatal("complete post-start report absence did not close original identity", err, f.ended, f.stops, f.dispatches, len(f.admissions))
	}
}

func TestPolicySourceActualCohortFundsFirstMaintenancePeriod(t *testing.T) {
	f := newSourceCohortFixture(t, 20)
	// The normal observation ceiling can be128 even when only20 Pods exist.
	// The accepted1GiB input pool can prepay their first maintenance interval.
	f.policy.ObservedPods = targets.MaxRestartPods
	f.wirePerDispatch = 0
	if err := f.maintain(0); err != nil || f.dispatches != 20 {
		t.Fatal("initial actual cohort", err, f.dispatches)
	}
	for sourceID, meter := range f.nodeMeters {
		permit := meter.Permit()
		if permit.BytesPerSecond != 1<<20 {
			t.Fatal("unexpected reference input-rate slice", permit.BytesPerSecond)
		}
		for second := 1; second <= int(value.TriggerPollInterval/time.Second); second++ {
			if err := meter.Charge(permit.BytesPerSecond, permit.IssuedAt.Add(time.Duration(second)*time.Second)); err != nil {
				t.Fatalf("source %s exhausted initialcredit=%d atsecond%d beforefirst15smaintenance despite20-Pod fairshare funding: %v", sourceID, permit.Credit, second, err)
			}
		}
	}
}

func TestPolicySourceQuietRenewalDoesNotBuyUnusedCredit(t *testing.T) {
	for _, replicas := range []int{20, targets.MaxRestartPods} {
		t.Run(fmt.Sprint(replicas), func(t *testing.T) {
			f := newSourceCohortFixture(t, replicas)
			f.policy.ObservedPods = targets.MaxRestartPods
			f.wirePerDispatch = 0
			if err := f.maintain(0); err != nil || f.dispatches != replicas {
				t.Fatal("initial quiet cohort", err, f.dispatches)
			}
			initial := len(f.admissions)
			if err := f.maintain(1); err != nil || f.dispatches != 2*replicas {
				t.Fatal("quiet renewal", err, f.dispatches)
			}
			for _, in := range f.admissions[initial:] {
				if in.Initial || in.AdditionalCredit != 0 {
					t.Fatal("quiet zero-input source bought unused input or restarted", in.Initial, in.AdditionalCredit)
				}
			}
			for _, meter := range f.nodeMeters {
				if meter.ObservedBytes() != 0 {
					t.Fatal("quiet source invented measured input")
				}
			}
		})
	}
}

// Preserve the fixture's current exact proof while resolving a real administrator
// maximum/deletion budget; the requested retention remains sixty seconds.
type sourceCohortShortRetention struct{ f *investigationFixture }

func (s sourceCohortShortRetention) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	base, err := s.f.Resolve(ctx, in)
	if err != nil {
		return privacy.Resolution{}, err
	}
	set := privacy.PolicySet{Target: in.Target, Revision: base.Proof.Policy, Complete: true, ObservedAt: s.f.now, FreshUntil: base.Proof.ValidUntil, Proof: base.Proof, Policies: []privacy.Policy{{Revision: base.Proof.Policy, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 10, MaximumSeconds: 40, DeletionBudgetSeconds: 20}}}
	return privacy.Resolve(set, in, s.f.now)
}

func TestPolicySourceEffectiveRetentionShorteningStopsKnownRing(t *testing.T) {
	f := newSourceCohortFixture(t, 1)
	if err := f.maintain(0); err != nil || f.dispatches != 1 {
		t.Fatal("initial source", err, f.dispatches)
	}
	f.runtime.Retention = sourceCohortShortRetention{f.f}
	err := f.maintain(1)
	if !errors.Is(err, value.ErrChanged) || f.ended != 1 || f.stops != 1 || f.dispatches != 1 || len(f.admissions) != 1 {
		t.Fatal("administrator content-age shortening did not stop original ring before further admission", err, f.ended, f.stops, f.dispatches, len(f.admissions))
	}
}
