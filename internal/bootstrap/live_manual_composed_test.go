package bootstrap

import (
	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type manualActualNode struct {
	*manualCatalogFacts
	node     *nodePackets
	budget   *nodeLiveBudget
	commands atomic.Int64
}

func (n *manualActualNode) ReadLive(ctx context.Context, r collector.LiveRead) (v.NodeReply, error) {
	end, ok := ctx.Deadline()
	if !ok {
		return v.NodeReply{}, v.ErrInvalid
	}
	w := collector.Work{ID: regionalObservationID(900 + int(n.commands.Add(1))), Sequence: 1, Kind: collector.WorkLiveRead, NotAfter: end, Live: &r}
	return n.node.readManualLive(ctx, w, n.budget)
}
func (n *manualActualNode) ReadLiveBatch(ctx context.Context, r []collector.LiveRead) ([]v.NodeReply, error) {
	return n.holder.ReadLiveProjections(ctx, r)
}

func TestLiveManualComposedExistingPacketExecutionToActualNodeProjection(t *testing.T) {
	catalog, f := newManualCatalogFacts(t, 1)
	catalog.now = time.Now
	f.holder.recordings.now = time.Now
	now := time.Now()
	id := collector.Identity{NodeUID: regionalObservationID(70), BootID: regionalObservationID(71), PodUID: regionalObservationID(72), Epoch: regionalObservationID(73)}
	budget, e := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, now)
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var starts atomic.Int32
	engine := make(chan func(gadget.Frame), 1)
	acquisition, stop := context.WithCancel(t.Context())
	node := &nodePackets{available: true, identity: func() collector.Identity { return id }, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(context.Context, string, collector.PacketResult, []byte) error { return nil }, engine: func(ctx context.Context, pod string, snap int, callback func(gadget.Frame)) (gadget.CaptureStats, error) {
		starts.Add(1)
		if snap != packets.Snaplen || pod != f.rows[0].Work.Accepted.Expectation.PodUID {
			t.Error("viewer changed original acquisition")
		}
		engine <- callback
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}}
	defer func() { stop(); node.wg.Wait() }()
	accepted := f.rows[0].Work.Accepted.Expectation
	held := f.holder.recordings.held[accepted.CaptureUID]
	original := collector.Work{ID: held.workID, Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: now.Add(time.Second), Packet: &collector.PacketCapture{CaptureID: accepted.CaptureUID, PodUID: accepted.PodUID, Duration: time.Duration(accepted.Recording.DurationMillis) * time.Millisecond, MaxBytes: accepted.Recording.MaxBytes}}
	if r := node.start(acquisition, id.Epoch, original); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	add := <-engine
	processing := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 2, MemoryBytes: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	actual := &manualActualNode{manualCatalogFacts: f, node: node, budget: processing}
	f.holder.recordings.nodes = actual
	call, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	records, e := catalog.records(call, f.rows)
	if e != nil || len(records) != 1 || processing.held != 0 || starts.Load() != 1 {
		t.Fatal("passive original holder inspection", records, e, processing.held, starts.Load())
	}
	source := records[0].Source
	reader := liveProjectionReader{remote: actual, now: time.Now}
	positions, e := reader.Head(call, []v.Source{source}, v.Packet)
	if e != nil || processing.held != 0 {
		t.Fatal("head allocated or replaced source", e)
	}
	initial, e := reader.Read(call, []v.Source{source}, v.Packet, positions, 20, 4096, 0)
	if e != nil || len(initial.Rows) != 0 || processing.held != 1 {
		t.Fatal("activate metadata only", initial, e)
	}
	stamp, e := sampleLiveClock("monotonic")
	if e != nil {
		t.Fatal(e)
	}
	raw := syntheticTCP(8080, "SYNTHETIC-PRIVATE-MANUAL-BODY")
	add(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic", DirectionKnown: true})
	got, e := reader.Read(call, []v.Source{source}, v.Packet, initial.Positions, 20, 4096, 0)
	if e != nil || len(got.Rows) != 1 || got.Rows[0].Packet == nil || got.Rows[0].Packet.RemotePort != 8080 || !got.Rows[0].ObservedAt.Before(time.Now()) || got.Rows[0].ExpiresAt.After(source.HardUntil) {
		t.Fatal("composed original finite projection", got, e)
	}
	if strings.Contains(string(func() []byte { b, _ := json.Marshal(got); return b }()), "PRIVATE-MANUAL-BODY") || starts.Load() != 1 {
		t.Fatal("payload or new acquisition in live result")
	}
	originalEnd := source.Manual.HardUntil
	stop()
	node.wg.Wait()
	after, e := catalog.records(call, f.rows)
	if e != nil || len(after) != 0 || processing.held != 0 || starts.Load() != 1 || !source.Manual.HardUntil.Equal(originalEnd) {
		t.Fatal("joined source became live/replaced/renewed", after, e, processing.held)
	}
	t.Log("actual accepted-work catalog/regional-holder/node start+callback/read/clock-placement composition; synthetic authority/registry/engine, no network/SQL/installed claim; one original acquisition, passive heads, payload excluded and engine join clears cohort")
}
