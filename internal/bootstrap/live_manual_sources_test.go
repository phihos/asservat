package bootstrap

import (
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"fmt"
	"testing"
	"time"
)

type manualCatalogFacts struct {
	rows                                        []executionapp.LiveManualWork
	recovery                                    artifact.RecoveryProof
	reads, recoveries, holderBatches, nodeReads int
	holder                                      reportedTargets
	afterNode                                   func()
	captured                                    []collector.LiveRead
	now                                         time.Time
	nodeDuration                                time.Duration
}

func (f *manualCatalogFacts) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	f.recoveries++
	return f.recovery, nil
}
func (f *manualCatalogFacts) LiveManualTarget(context.Context, string) (authorization.Target, error) {
	e := f.rows[0].Work.Accepted.Expectation
	return authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}, nil
}
func (f *manualCatalogFacts) ReadLiveManualWork(context.Context, []string, artifact.RecoveryProof) ([]executionapp.LiveManualWork, error) {
	f.reads++
	return append([]executionapp.LiveManualWork(nil), f.rows...), nil
}
func (f *manualCatalogFacts) ListLiveManualWork(context.Context, authorization.WorkloadTarget, string, int, artifact.RecoveryProof) ([]executionapp.LiveManualWork, string, error) {
	f.reads++
	return append([]executionapp.LiveManualWork(nil), f.rows...), "", nil
}
func (f *manualCatalogFacts) ResolveManualLive(ctx context.Context, in []targets.ManualLiveTarget) ([]targets.ManualLiveResolution, error) {
	f.holderBatches++
	return f.holder.ResolveManualLive(ctx, in)
}

// These three methods satisfy the existing regional node holder interface.
func (f *manualCatalogFacts) NodeByName(string) (delivery.NodeView, bool) {
	return delivery.NodeView{}, false
}
func (f *manualCatalogFacts) EnqueuePacket(string, collector.PacketCapture, time.Time) (collector.Work, error) {
	return collector.Work{}, live.ErrDenied
}
func (f *manualCatalogFacts) NodeByUID(id string) (delivery.NodeView, bool) {
	i := collector.Identity{NodeUID: regionalObservationID(70), BootID: regionalObservationID(71), PodUID: regionalObservationID(72), Epoch: regionalObservationID(73)}
	return delivery.NodeView{Identity: i, Current: true, Report: &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Adapter: collector.AdapterAvailable, Prerequisites: true, LiveProjections: []string{live.Packet}}}}}, id == i.NodeUID
}
func (f *manualCatalogFacts) ReadLive(ctx context.Context, r collector.LiveRead) (live.NodeReply, error) {
	// Per-test fixture calls may fan out at 16 sources. The mutex already held by
	// the caller does not serialize engine work; independent state is immutable.
	f.holder.recordings.mu.Lock()
	f.nodeReads++
	f.captured = append(f.captured, r)
	f.holder.recordings.mu.Unlock()
	m := *r.Manual
	m.StartedAt = f.now.Add(-time.Second)
	duration := f.nodeDuration
	if duration == 0 {
		duration = 10 * time.Second
	}
	m.HardUntil = m.StartedAt.Add(duration)
	if f.afterNode != nil {
		f.afterNode()
	}
	return live.NodeReply{Manual: &m, SourceID: m.CaptureID, Fence: m.WorkID, BootID: m.BootID, Clock: "monotonic", Sample: 1, Rows: []live.StampedRow{}}, ctx.Err()
}
func newManualCatalogFacts(t *testing.T, count int) (liveManualCatalog, *manualCatalogFacts) {
	t.Helper()
	base, _, _ := newRegionalObservationFixture(t)
	now := base.now
	f := &manualCatalogFacts{now: now, recovery: base.recovery}
	holder := NewConnectorRecordings(f, fakePodNodes{}, func() time.Time { return now }, func(string) {})
	f.holder = reportedTargets{recordings: holder}
	for n := 0; n < count; n++ {
		w := base.work
		e := w.Accepted.Expectation
		e.CaptureUID = regionalObservationID(100 + n)
		e.ActionID = "a111111111111111111111111"
		e.NativeType = artifact.PCAPNGArtifact
		e.Registration.NativeLimit = artifact.RecordingNativeLimit
		e.Registration.Location.AttemptID = regionalObservationID(200 + n)
		e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte(`{}`), DurationMillis: 10000, MaxBytes: 64 << 10, Snaplen: artifact.RecordingSnaplen}
		if e.Validate() != nil {
			t.Fatal("synthetic accepted finite metadata expectation invalid")
		}
		w.Accepted.Expectation = e
		w.Accepted.CaptureID = e.CaptureUID
		w.Accepted.Deadline = now.Add(time.Minute)
		process := base.process.Binding
		r := execution.APIExecution{RootID: base.receiver.Channel.RootID, Process: process, ExpectationDigest: evidence.ContextExpectationDigest(e), ObjectUID: regionalObservationID(300 + n), Phase: "started", StartedAt: now.Add(-2 * time.Second), Binding: execution.Binding{ExecutionClass: artifact.ContextAPIExecution, ExecutorPodUID: process.PodUID, ExecutorAccountUID: process.AccountUID, OperationID: regionalObservationID(400 + n), CaptureID: e.CaptureUID, ActionID: e.ActionID, AttemptID: e.Registration.Location.AttemptID, ClusterID: e.Registration.Location.ClusterID, IssuerEpoch: process.IssuerEpoch, PodUID: e.PodUID, CollectorEpoch: process.ProcessEpoch, ScopeDigest: e.PlanDigest, AuthorityDigest: artifact.Digest{1}, BudgetDigest: artifact.Digest{2}, AuditDigest: w.IntentDigest, NativeBytes: e.Registration.NativeLimit, NotBefore: now.Add(-3 * time.Second), NotAfter: now.Add(-time.Second)}}
		if !r.Valid() {
			t.Fatal("synthetic original execution invalid", r)
		}
		f.rows = append(f.rows, executionapp.LiveManualWork{Work: w, Execution: r, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)})
		holder.held[e.CaptureUID] = &heldRecording{expectation: e, digest: r.ExpectationDigest, nodeUID: regionalObservationID(70), workID: regionalObservationID(500 + n), queued: now.Add(-2 * time.Second), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	}
	return liveManualCatalog{root: base.receiver.Channel.RootID, works: f, recovery: f, holders: f, now: func() time.Time { return now }}, f
}
func TestLiveManualCatalogUsesOriginalStartedHolderAndBatchesAtOneAndSixteen(t *testing.T) {
	for _, count := range []int{1, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, f := newManualCatalogFacts(t, count)
			ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
			defer cancel()
			refs := make([]live.SourceReference, count)
			for n, r := range f.rows {
				e := r.Work.Accepted.Expectation
				refs[n] = live.SourceReference{ID: e.CaptureUID, Kind: "manualSession", Target: authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}}
			}
			for phase := 1; phase <= 2; phase++ {
				out, e := s.read(ctx, refs)
				if e != nil || len(out) != count {
					t.Fatal(out, e)
				}
				for _, r := range out {
					if r.Source.Binding != (collector.SourceBinding{}) || r.Source.Manual == nil || r.Source.ID() != r.Source.Manual.CaptureID || r.Source.Manual.ObservationKind != "" || !r.Source.Manual.StartedAt.Equal(f.now.Add(-time.Second)) || !r.Source.HardUntil.Equal(f.now.Add(9*time.Second)) {
						t.Fatal("invented session or preparation bound used", r)
					}
				}
				if f.reads != phase || f.recoveries != phase || f.holderBatches != phase || f.nodeReads != phase*count {
					t.Fatal("nonbatched manual authority", f.reads, f.recoveries, f.holderBatches, f.nodeReads)
				}
			}
			t.Logf("%d sources/two phases: SQL batch=%d recovery=%d regional batch=%d node reads=%d; no new collection or old human identity", count, f.reads, f.recoveries, f.holderBatches, f.nodeReads)
		})
	}
}
func TestLiveManualCatalogRefusesReplacementAndStoppedHolder(t *testing.T) {
	for _, mode := range []string{"cancelled", "finished", "wrong-scope", "wrong-attempt", "wrong-original-permit", "after-node-cancel", "source-expired"} {
		t.Run(mode, func(t *testing.T) {
			s, f := newManualCatalogFacts(t, 1)
			id := f.rows[0].Work.Accepted.CaptureID
			p := f.holder.recordings.held[id]
			switch mode {
			case "cancelled":
				p.cancelRequested = true
			case "finished":
				p.outcome.State = evidence.RecordingStored
			case "wrong-scope":
				p.expectation.PlanDigest = artifact.Digest{99}
			case "wrong-attempt":
				p.expectation.Registration.Location.AttemptID = regionalObservationID(999)
			case "wrong-original-permit":
				f.rows[0].Observation = &collector.ObservationBinding{}
			case "after-node-cancel":
				f.afterNode = func() { f.holder.recordings.mu.Lock(); p.cancelRequested = true; f.holder.recordings.mu.Unlock() }
			case "source-expired":
				f.rows[0].FreshUntil = f.now
			}
			ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
			defer cancel()
			out, e := s.records(ctx, f.rows)
			if e == nil && len(out) != 0 {
				t.Fatal("foreign/ended source became visible", out)
			}
			if mode != "after-node-cancel" && f.nodeReads != 0 {
				t.Fatal("node contacted after known refusal")
			}
		})
	}
}

var _ authapp.LiveSourceCatalog = liveCatalog{}

func TestLiveManualSensitivePermitScopeIsDistinctFromCaptureScope(t *testing.T) {
	s, f := newManualCatalogFacts(t, 1)
	w := &f.rows[0]
	e := &w.Work.Accepted.Expectation
	e.NativeType, e.DataClass = artifact.RawPCAPNGArtifact, "raw"
	e.Recording.Profile = "rawPackets"
	e.Recording.Snaplen = 96
	e.Recording.Filter = &artifact.RecordingFilter{Expression: "tcp", Program: []artifact.FilterInstruction{{Code: 6, K: 96}}}
	if e.Validate() != nil {
		t.Fatal("synthetic original raw recording invalid")
	}
	w.Execution.ExpectationDigest = evidence.ContextExpectationDigest(*e)
	b := collector.ObservationBinding{Scope: [32]byte{99}, ProgramDigest: [32]byte{2}, ExpectationDigest: [32]byte(w.Execution.ExpectationDigest), AccountingRule: collector.ObservationAccountingRule(), SessionID: regionalObservationID(600), Fence: regionalObservationID(601), CaptureID: e.CaptureUID, ActionID: e.ActionID, PodUID: e.PodUID, NodeUID: regionalObservationID(70), BootID: regionalObservationID(71), CollectorPodUID: regionalObservationID(72), CollectorEpoch: regionalObservationID(73)}
	if !b.Valid() || b.Scope == [32]byte(w.Work.Accepted.ScopeDigest) {
		t.Fatal("fixture must use real separate digest purposes")
	}
	w.Observation = &b
	p := f.holder.recordings.held[e.CaptureUID]
	p.expectation = *e
	p.digest = w.Execution.ExpectationDigest
	ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
	defer cancel()
	out, err := s.records(ctx, f.rows)
	if err != nil || len(out) != 1 || out[0].Source.Manual.ObservationSessionID != b.SessionID || out[0].Source.Manual.ObservationFence != b.Fence || out[0].Source.Manual.Scope != [32]byte(w.Work.Accepted.ScopeDigest) {
		t.Fatal("original permit scope incorrectly equated to accepted capture plan scope", out, err)
	}
}

func TestLiveManualInitialHolderCannotWidenAcceptedDuration(t *testing.T) {
	s, f := newManualCatalogFacts(t, 1)
	f.nodeDuration = 11 * time.Second // original accepted duration is ten seconds
	ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
	defer cancel()
	out, err := s.records(ctx, f.rows)
	if err == nil && len(out) != 0 {
		t.Fatal("node holder widened accepted finite duration", out)
	}
	if f.nodeReads != 1 {
		t.Fatal("regression must reach initial passive node observation", f.nodeReads)
	}
}
