package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/application/evidence"
	planner "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type argumentCancelQueue struct {
	expectedRecordingNodes
	stops       int
	stoppedWork string
}

func (q *argumentCancelQueue) EnqueuePacketCancel(_ context.Context, _, _, work string, _ time.Time) (collector.Work, error) {
	q.stops++
	q.stoppedWork = work
	return collector.Work{ID: "22222222-2222-4222-8222-222222222222"}, nil
}
func argumentStop(e artifact.ContextExpectation) collector.RecordingStop {
	return collector.RecordingStop{RootID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: e.CaptureUID, WriterEpoch: e.CaptureUID, ExpectationDigest: evidence.ContextExpectationDigest(e), WriteUntil: e.Registration.WriteUntil}
}
func argumentCollect(e artifact.ContextExpectation) fleet.APIContextWork {
	return fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
}
func TestRegionalArgumentStopNeedsOriginalResult(t *testing.T) {
	for _, mode := range []string{"started", "before-start", "unknown-start"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			e, source, permit := regionalArgumentFixture(now)
			e.Registration.Location.ClusterID = e.CaptureUID
			permit.Binding.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
			q := &argumentCancelQueue{}
			var nodes recordingNodes = q
			if mode == "unknown-start" {
				nodes = &uncertainArgumentNodes{}
			}
			h := NewConnectorRecordings(nodes, nil, func() time.Time { return now }, func(string) {})
			p := h.Prepare(&objectstore.PreparedArtifact{}, e)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if mode != "before-start" {
				_, err := p.StartArgumentRecording(ctx, artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}, now, now.Add(time.Second), source, permit)
				if (err != nil) != (mode == "unknown-start") {
					t.Fatal(err)
				}
			}
			stop := argumentStop(e)
			err := h.CancelRecording(ctx, stop)
			if (err != nil) != (mode == "unknown-start") {
				t.Fatal("stop", err)
			}
			if c, err := h.Collect(argumentCollect(e)); err != nil || c.State != evidence.RecordingPending {
				t.Fatal("request invented joined proof", c, err)
			}
			if mode == "before-start" {
				if _, err := p.StartArgumentRecording(ctx, artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}, now, now.Add(time.Second), source, permit); err == nil {
					t.Fatal("late start escaped stop")
				}
				return
			}
			if mode == "unknown-start" {
				if len(h.held) != 1 || h.held[e.CaptureUID].resultJoined {
					t.Fatal("unknown effect lost")
				}
				return
			}
			if q.stops != 1 || q.stoppedWork != h.held[e.CaptureUID].workID {
				t.Fatal("wrong stop target")
			}
			if err := h.CancelRecording(ctx, stop); err != nil || q.stops != 1 {
				t.Fatal("stop replay", err)
			}
			r := collector.PacketResult{WorkID: q.stoppedWork, CaptureID: e.CaptureUID, NativeType: artifact.SyscallArgumentsArtifact, Failure: collector.ReasonCaptureFailed}
			node := collector.Identity{NodeUID: source.NodeUID, BootID: source.BootID, PodUID: source.CollectorPodUID, Epoch: source.CollectorEpoch}
			wrong := node
			wrong.Epoch = "replacement"
			if err := h.DeliverPacket(ctx, wrong, r, bytes.NewReader(nil)); err == nil {
				t.Fatal("replacement result accepted")
			}
			if c, _ := h.Collect(argumentCollect(e)); c.State != evidence.RecordingPending {
				t.Fatal("wrong result terminated")
			}
			if err := h.DeliverPacket(ctx, node, r, bytes.NewReader(nil)); err != nil {
				t.Fatal(err)
			}
			c, err := h.Collect(argumentCollect(e))
			if err != nil || c.State != evidence.RecordingCancelled || c.RecordingCancellation == nil || !c.Valid(e.Registration) || c.ProfileCancellation != nil {
				t.Fatal("missing distinct joined proof", c, err)
			}
			first := *c.RecordingCancellation
			now = now.Add(time.Second)
			replay, err := h.Collect(argumentCollect(e))
			if err != nil || replay.RecordingCancellation == nil || *replay.RecordingCancellation != first {
				t.Fatal("cancellation proof renewed", replay, err)
			}
			changed := stop
			changed.WriterEpoch = "33333333-3333-4333-8333-333333333333"
			if err := h.CancelRecording(ctx, changed); err == nil {
				t.Fatal("replacement writer accepted")
			}
		})
	}
}

// The fixture uses the real encrypted producer and backend request boundary;
// synthetic accepted source identity does not claim native BPF qualification.
func argumentWriterHolder(t *testing.T, handler http.Handler) (*ConnectorRecordings, artifact.ContextExpectation, collector.Identity, collector.PacketResult, []byte) {
	t.Helper()
	e, s, header, footer := argumentFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	header.StartedAt, footer.EndedAt = now.Add(37*time.Nanosecond), now.Add(91*time.Nanosecond)
	var native bytes.Buffer
	enc := json.NewEncoder(&native)
	if err := enc.Encode(header); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(footer); err != nil {
		t.Fatal(err)
	}
	h := NewConnectorRecordings(&argumentCancelQueue{}, nil, time.Now, func(string) {})
	source := targets.PacketSourceObservation{PodUID: s.PodUID, NodeUID: s.NodeUID, BootID: s.BootID, CollectorPodUID: s.CollectorPodUID, CollectorEpoch: s.CollectorEpoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	h.held[e.CaptureUID] = &heldRecording{expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: preparedSnapshot(t, e, handler), nodeUID: s.NodeUID, workID: e.CaptureUID, queued: now, expires: e.Registration.WriteUntil.Add(recordingRetain), argumentSource: &source, outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	return h, e, collector.Identity{NodeUID: s.NodeUID, BootID: s.BootID, PodUID: s.CollectorPodUID, Epoch: s.CollectorEpoch}, collector.PacketResult{WorkID: e.CaptureUID, CaptureID: e.CaptureUID, NativeType: e.NativeType, CapturedBytes: int64(native.Len()), StartedAt: header.StartedAt, EndedAt: footer.EndedAt}, native.Bytes()
}
func TestRegionalArgumentStopActiveWriterKeepsStoredWins(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "stored", false: "unknown-backend"}[success], func(t *testing.T) {
			barrier := newFIFOStoreBarrier(t)
			h, e, node, result, native := argumentWriterHolder(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				barrier.signal.Do(func() { close(barrier.entered) })
				<-barrier.release
				if !success {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				snapshotPUT(t, w, r, barrier.puts.Add(1))
			}))
			done := make(chan error, 1)
			go func() { done <- h.DeliverPacket(t.Context(), node, result, bytes.NewReader(native)) }()
			awaitFIFO(t, barrier.entered)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := h.CancelRecording(ctx, argumentStop(e)); err != nil {
				t.Fatal(err)
			}
			if c, _ := h.Collect(argumentCollect(e)); c.State != evidence.RecordingPending {
				t.Fatal("writer was not joined", c)
			}
			barrier.open()
			select {
			case err := <-done:
				if (err == nil) != success {
					t.Fatal("store result", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not return")
			}
			want := evidence.RecordingCancelled
			if success {
				want = evidence.RecordingStored
			}
			if c, err := h.Collect(argumentCollect(e)); err != nil || c.State != want {
				t.Fatal("stored-wins or join lost", c, err)
			}
		})
	}
}
func TestRegionalArgumentStopCancelsUnreadWait(t *testing.T) {
	h, e, node, result, _ := argumentWriterHolder(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("cancelled wait reached backend") }))
	h.storing = maxStoringBytes
	body := &unreadArgumentBody{}
	done := make(chan error, 1)
	go func() { done <- h.DeliverPacket(t.Context(), node, result, body) }()
	waitPacketStorePending(t, h, e.CaptureUID, done)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := h.CancelRecording(ctx, argumentStop(e)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled wait succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not join")
	}
	if body.read {
		t.Fatal("queued body was read")
	}
	h.mu.Lock()
	h.releaseStoreLocked(maxStoringBytes)
	h.mu.Unlock()
	if c, err := h.Collect(argumentCollect(e)); err != nil || c.State != evidence.RecordingCancelled {
		t.Fatal(c, err)
	}
}

type unreadArgumentBody struct{ read bool }

func (b *unreadArgumentBody) Read([]byte) (int, error) { b.read = true; return 0, io.EOF }

func TestRegionalArgumentStopWaitsForResultHandlerJoin(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e, source, permit := regionalArgumentFixture(now)
	e.Registration.Location.ClusterID = e.CaptureUID
	permit.Binding.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
	q := &argumentCancelQueue{}
	h := NewConnectorRecordings(q, nil, func() time.Time { return now }, func(string) {})
	p := h.Prepare(&objectstore.PreparedArtifact{}, e)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := p.StartArgumentRecording(ctx, artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}, now, now.Add(time.Second), source, permit); err != nil {
		t.Fatal(err)
	}
	stop := argumentStop(e)
	for _, mode := range []string{"attempt", "digest", "cluster", "write-end", "cancelled"} {
		wrong := stop
		call := ctx
		switch mode {
		case "attempt":
			wrong.AttemptID = e.CaptureUID
		case "digest":
			wrong.ExpectationDigest[0]++
		case "cluster":
			wrong.ClusterID = stop.AttemptID
		case "write-end":
			wrong.WriteUntil = wrong.WriteUntil.Add(time.Second)
		case "cancelled":
			var end context.CancelFunc
			call, end = context.WithCancel(ctx)
			end()
		}
		if err := h.CancelRecording(call, wrong); err == nil || q.stops != 0 {
			t.Fatal("invalid stop reached node", mode, err)
		}
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	body := &argumentJoinReader{Reader: reader, entered: make(chan struct{})}
	r := collector.PacketResult{WorkID: q.work[0].ID, CaptureID: e.CaptureUID, NativeType: artifact.SyscallArgumentsArtifact, Failure: collector.ReasonCaptureFailed}
	node := collector.Identity{NodeUID: source.NodeUID, BootID: source.BootID, PodUID: source.CollectorPodUID, Epoch: source.CollectorEpoch}
	done := make(chan error, 1)
	go func() { done <- h.DeliverPacket(ctx, node, r, body) }()
	awaitFIFO(t, body.entered)
	if err := h.CancelRecording(ctx, stop); err != nil {
		t.Fatal(err)
	}
	if c, _ := h.Collect(argumentCollect(e)); c.State != evidence.RecordingPending {
		t.Fatal("result header claimed handler joined", c)
	}
	writer.Close()
	awaitFIFOResult(t, done)
	if c, err := h.Collect(argumentCollect(e)); err != nil || c.State != evidence.RecordingCancelled {
		t.Fatal(c, err)
	}
}

type argumentJoinReader struct {
	io.Reader
	entered chan struct{}
	once    sync.Once
}

func (r *argumentJoinReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.Reader.Read(p)
}

func argumentFixture(t *testing.T) (artifact.ContextExpectation, artifact.ArgumentSourceProvenance, artifact.ArgumentHeader, artifact.ArgumentFooter) {
	t.Helper()
	in, now := publicArgumentPlanInput(t, []string{"write"})
	plan, err := planner.CompileRecorder(in, newPublicRecorderCompiler(), now)
	if err != nil {
		t.Fatal(err)
	}
	recording, action, err := planner.RecordingFor(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := artifact.Digest{1}
	anchor := now.Add(-time.Minute)
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, NativeType: artifact.SyscallArgumentsArtifact, Recording: &recording, CaptureUID: runtimeID, PodUID: runtimeID, Namespace: "synthetic", NamespaceUID: runtimeID, WorkloadUID: runtimeID, ActionID: action, CaseID: runtimeID, OccurrenceID: runtimeID, CollectorVersion: "synthetic", CollectorImageDigest: digest, RecipeDigest: plan.RecipeDigest, PlanDigest: plan.ScopeDigest, DataClass: "raw", PurposeRef: "diagnostics", TriggeredAt: anchor,
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: runtimeID, ArtifactID: runtimeID, AttemptID: runtimeID}, StoreID: runtimeID, AllocationID: runtimeID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.RecordingNativeLimit, AnchorAt: anchor, WriteUntil: now.Add(time.Minute), ExpiresAt: anchor.Add(180 * time.Second), DeleteBy: anchor.Add(240 * time.Second)},
		Audience:     []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.synthetic.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: runtimeID, BasisDigest: digest}}, RequestedAgeSeconds: 180, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: digest}}}
	if err = e.Validate(); err != nil {
		t.Fatal("accepted argument expectation", err)
	}
	// The source is independent of the native bytes and remains historical:
	// its original observation session is not another collection lease.
	source := artifact.ArgumentSourceProvenance{PodUID: e.PodUID, NodeUID: runtimeID, BootID: runtimeID, CollectorPodUID: runtimeID, CollectorEpoch: runtimeID, SessionID: runtimeID, Fence: runtimeID, StartedAt: now.Add(-time.Minute), StartBy: now.Add(-59 * time.Second), Until: now.Add(-57 * time.Second)}
	a := recording.Arguments
	h := artifact.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: e.PodUID, NodeUID: source.NodeUID, BootID: source.BootID, CollectorPodUID: source.CollectorPodUID, SourceEpoch: source.CollectorEpoch, SessionID: source.SessionID, Fence: source.Fence, EngineDigest: hex.EncodeToString(a.ProgramDigest[:]), DefinitionDigest: hex.EncodeToString(a.DefinitionDigest[:]), AccountingRule: hex.EncodeToString(a.AccountingRule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: source.StartedAt}
	f := artifact.ArgumentFooter{Record: "footer", EndedAt: source.Until, Outcome: "completed", CoverageUnknown: true}
	return e, source, h, f
}
