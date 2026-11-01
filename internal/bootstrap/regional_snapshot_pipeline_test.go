package bootstrap

import (
	"asservat.local/asservat/internal/adapters/gadget"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type snapshotTestKeys struct{}

func (snapshotTestKeys) Seal(_ context.Context, key, _ []byte) (artifact.SealedKey, error) {
	return artifact.SealedKey{Reference: "synthetic/wrap", Ciphertext: base64.StdEncoding.EncodeToString(key)}, nil
}

type snapshotNoMultipart struct{ t *testing.T }

func (j snapshotNoMultipart) AdvanceStreaming(context.Context, artifact.StreamingPlan, artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	j.t.Error("small snapshot invoked multipart journal")
	return artifact.StreamingState{}, false, artifact.ErrInvalid
}

func snapshotExpected(t *testing.T, x collector.SourceSnapshot) artifact.ContextExpectation {
	t.Helper()
	q, b := x.Request, x.Binding
	d := artifact.Digest{1}
	id := b.SourceID
	binding, _ := json.Marshal(b)
	scope := []byte(`{"schemaVersion":"source-window/v1"}`)
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, NativeType: artifact.PCAPNGArtifact, Snapshot: &q, SourceSnapshotManifest: &artifact.SourceSnapshotManifest{CanonicalScope: scope, Binding: binding}, CaptureUID: x.CaptureID, PodUID: b.PodUID, Namespace: "app", NamespaceUID: id, WorkloadUID: id, ActionID: b.ActionID, CaseID: id, OccurrenceID: id, CollectorVersion: "synthetic", CollectorImageDigest: d, RecipeDigest: d, PlanDigest: artifact.Digest(sha256.Sum256(scope)), DataClass: "metadata", PurposeRef: "snapshot-pipeline-test", TriggeredAt: q.T0,
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: x.AttemptID}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: q.MaxBytes, AnchorAt: artifact.SourceSnapshotAnchor(q), WriteUntil: q.ProcessingUntil, ExpiresAt: artifact.SourceSnapshotAnchor(q).Add(120 * time.Second), DeleteBy: artifact.SourceSnapshotAnchor(q).Add(180 * time.Second)},
		Audience:     []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: id, BasisDigest: d}}, RequestedAgeSeconds: 120, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: d}},
		Lifecycle: &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: q.SourceID, SourceStartedAt: q.SourceStartedAt, SnapshotID: q.SnapshotID, RequestedBefore: q.Before, After: q.After, HistoryCoverage: "unknown", WindowCoverage: "unknown", GapReasons: []string{"unknownLoss"}}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	return e
}
func preparedSnapshot(t *testing.T, e artifact.ContextExpectation, handler http.Handler) *objectstore.PreparedArtifact {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	store, err := objectstore.New(server.URL, "us-east-1", "synthetic", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	custody, err := store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := objectstore.NewArtifactProducer(custody, snapshotTestKeys{}, snapshotNoMultipart{t}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := producer.Prepare(t.Context(), e, "")
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}
func snapshotPUT(t *testing.T, w http.ResponseWriter, r *http.Request, n int32) {
	t.Helper()
	if r.Method != http.MethodPut || r.Header.Get("If-None-Match") != "*" {
		t.Error("unbounded synthetic writer")
	}
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("ETag", fmt.Sprintf(`"synthetic-%d"`, n))
	w.Header().Set("x-amz-version-id", fmt.Sprintf("synthetic-%d", n))
	w.WriteHeader(http.StatusOK)
}

// Synthetic packet/clock/authority and local TLS S3 replies exercise the actual
// node owner, regional holder and encrypted producer. This does not qualify
// native clock mapping, Kubernetes collection or SQL completion authority.
func TestRegionalSnapshotNodeNanosecondStopReachesRealStore(t *testing.T) {
	var holder *ConnectorRecordings
	var source *packetSource
	delivered := make(chan struct {
		result collector.PacketResult
		err    error
	}, 1)
	natural := make(chan struct{})
	n, actualSource, clock, x := sourceSnapshotPipelineFixture(t, func(ctx context.Context, _ string, r collector.PacketResult, native []byte) error {
		err := holder.DeliverPacket(ctx, collector.Identity{NodeUID: xNode(source), BootID: source.meter.Permit().Binding.BootID, PodUID: source.meter.Permit().Binding.CollectorPodUID, Epoch: source.meter.Permit().Binding.CollectorEpoch}, r, bytes.NewReader(native))
		delivered <- struct {
			result collector.PacketResult
			err    error
		}{r, err}
		return err
	}, natural)
	source = actualSource
	stopped := clock.now().Add(37 * time.Nanosecond)
	clock.set(stopped)
	close(natural)
	for {
		source.mu.Lock()
		done := source.engineExited
		source.mu.Unlock()
		if done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	clock.set(x.Request.T0.Add(time.Millisecond))
	x.Request.T0 = clock.now()
	x.Request.IssuedAt = clock.now()
	e := snapshotExpected(t, x)
	x.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
	var puts atomic.Int32
	prepared := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
	nodes := &snapshotRecordingQueue{}
	holder = NewConnectorRecordings(nodes, nil, clock.now, func(string) {})
	output := holder.Prepare(prepared, e)
	ctx, cancel := context.WithDeadline(t.Context(), x.Request.StartBy)
	defer cancel()
	if _, err := output.StartSourceSnapshot(ctx, x); err != nil {
		t.Fatal(err)
	}
	work := collector.Work{ID: x.Request.SnapshotID, Sequence: 1, Kind: collector.WorkPacketSourceSnapshot, NotAfter: x.Request.StartBy, Snapshot: &x}
	if r := n.decide(t.Context(), x.Binding.CollectorEpoch, work); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	select {
	case got := <-delivered:
		if got.err != nil || !got.result.EndedAt.Equal(stopped) || puts.Load() != 4 {
			t.Fatal("node stop lost in actual holder/producer pipeline", got.result.EndedAt, stopped, got.err, puts.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual snapshot producer did not join")
	}
	out, err := holder.Collect(fleet.APIContextWork{CaptureID: x.CaptureID, AttemptID: x.AttemptID, ExpectationDigest: artifact.Digest(x.ExpectationDigest)})
	if err != nil || out.State != evidence.RecordingStored || out.SnapshotCoverage == nil || !out.SnapshotCoverage.SourceStoppedAt.Equal(stopped) {
		t.Fatal(out, err)
	}
}
func xNode(s *packetSource) string { return s.meter.Permit().Binding.NodeUID }

func sourceSnapshotPipelineFixture(t *testing.T, upload packetUploader, natural ...<-chan struct{}) (*nodeSources, *packetSource, *packetRingClock, collector.SourceSnapshot) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := &packetRingClock{at: now}
	p := sourceOwnerPermit(now)
	p.Binding.AudienceDigest = [32]byte{7}
	p.Binding.ActionID = "a0123456789abcdef01234567"
	budget, err := collector.NewBudget(collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: 2, InputBytesPerSecond: 2 << 20, InputBurstBytes: 2 << 20}, RingBytes: 4096, FrozenBytes: 2 * 65536}, now)
	if err != nil {
		t.Fatal(err)
	}
	mu := &sync.Mutex{}
	ready := make(chan struct{})
	engine := func(ctx context.Context, _ string, _ int, emit func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		frame := syntheticTCP(80, "synthetic")
		emit(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: now})
		close(ready)
		var stop <-chan struct{}
		if len(natural) > 0 {
			stop = natural[0]
		}
		select {
		case <-ctx.Done():
			return gadget.CaptureStats{}, ctx.Err()
		case <-stop:
			return gadget.CaptureStats{}, nil
		}
	}
	limits := sourceOwnerLimits()
	limits.MaxFrozenBytes = 65536
	source, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, limits, nil, engine, clock.now, budget, mu)
	if err != nil {
		t.Fatal(err)
	}
	<-ready
	n := &nodeSources{sources: map[string]*packetSource{p.Binding.SourceID: source}, now: clock.now, budget: budget, budgetMu: mu, version: "synthetic", takeUpload: func(context.Context, int64) bool { return true }, upload: upload, identity: func() collector.Identity {
		return collector.Identity{NodeUID: p.Binding.NodeUID, BootID: p.Binding.BootID, PodUID: p.Binding.CollectorPodUID, Epoch: p.Binding.CollectorEpoch}
	}}
	t.Cleanup(n.Close)
	q := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(deliveryapp.SourceBindingDigest(p.Binding)), SourceID: p.Binding.SourceID, Fence: p.Binding.Fence, SnapshotID: p.Binding.SourceID, SourceStartedAt: p.StartedAt, SourceHardUntil: p.HardUntil, T0: now, IssuedAt: now, StartBy: now.Add(5 * time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	x := collector.SourceSnapshot{Binding: p.Binding, CaptureID: p.Binding.SourceID, AttemptID: p.Binding.SourceID, WriterPodUID: p.Binding.SourceID, WriterEpoch: p.Binding.SourceID, ExpectationDigest: [32]byte{5}, Request: q}
	return n, source, clock, x
}
