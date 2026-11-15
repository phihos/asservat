package delivery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

const (
	boot   = "11111111-1111-4111-8111-111111111111"
	epochA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	epochB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

var allKinds = []collector.WorkKind{collector.WorkLiveRead, collector.WorkArmSource, collector.WorkStopSource, collector.WorkSnapshot, collector.WorkPeerGeneration, collector.WorkPacketCapture,
	collector.WorkProfileCapture, collector.WorkCancelProfileCapture, collector.WorkCancelSourceSnapshot, collector.WorkSyscallCapture, collector.WorkPacketSource, collector.WorkStopPacketSource,
	collector.WorkPacketSourceSnapshot, collector.WorkCancelPacketCapture}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newChannel(t *testing.T) (*NodeChannel, *clock, *[]NodeView) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	var mu sync.Mutex
	changes := &[]NodeView{}
	ch, err := NewNodeChannel(clk.now, func(v NodeView) { mu.Lock(); *changes = append(*changes, v); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	return ch, clk, changes
}

// enroll connects collector Pod "pod-"+epoch[:1] of node-uid as generation epoch.
func enroll(t *testing.T, ch *NodeChannel, epoch string) (NodePeer, uint64) {
	t.Helper()
	p, stream, err := ch.Connect(collector.Identity{NodeName: "node-a", NodeUID: "node-uid", PodName: "collector-x", PodUID: "pod-" + epoch[:1], BootID: boot, Epoch: epoch, Runtime: "containerd://2.1.0"}, allKinds)
	if err != nil {
		t.Fatal(err)
	}
	return p, stream
}

// sourceConnect connects the fixed source-test collector as generation epoch.
func sourceConnect(ch *NodeChannel, epoch string) (collector.Identity, error) {
	id := collector.Identity{NodeName: "node", NodeUID: "11111111-1111-4111-8111-111111111111", PodName: "collector", PodUID: "22222222-2222-4222-8222-222222222222", BootID: boot, Epoch: epoch}
	_, _, err := ch.Connect(id, allKinds)
	return id, err
}

// Poll is the test view of Next: queued work after after, or an empty answer
// when none arrives within hold.
func (c *NodeChannel) Poll(ctx context.Context, p NodePeer, _ string, after uint64, hold time.Duration) ([]collector.Work, error) {
	c.mu.Lock()
	var stream uint64
	if e := c.nodes[p.NodeUID]; e != nil {
		stream = e.stream
	}
	c.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, max(hold, time.Millisecond))
	defer cancel()
	w, err := c.Next(bounded, p, stream, after)
	if errors.Is(err, ErrNodeUnavailable) && ctx.Err() == nil {
		return []collector.Work{}, nil
	}
	return w, err
}

func report(at time.Time) collector.Report {
	f := collector.Facts{Kernel: collector.KernelVersion{Major: 6, Minor: 8, Patch: 0}}
	return collector.Report{ObservedAt: at, Facts: f, Mechanisms: collector.Assess(f)}
}

func TestConnectFromAnotherPodReplacesTheEarlierStream(t *testing.T) {
	ch, clk, changes := newChannel(t)
	old, oldStream := enroll(t, ch, epochA)
	if _, err := ch.Enqueue("node-uid", collector.WorkSnapshot, clk.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() {
		_, err := ch.Next(context.Background(), old, oldStream, 1)
		ended <- err
	}()
	time.Sleep(20 * time.Millisecond)
	fresh, _ := enroll(t, ch, epochB)
	select {
	case err := <-ended:
		if !errors.Is(err, ErrNodeUnauthenticated) {
			t.Fatalf("replaced stream: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replacement did not end the earlier stream")
	}
	if err := ch.Report(old, report(clk.now())); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatal("replaced Pod reported")
	}
	nodes := ch.Nodes()
	if len(nodes) != 1 || nodes[0].Identity.Epoch != epochB || nodes[0].Identity.PodUID != fresh.PodUID || nodes[0].Queued != 0 || len(*changes) != 2 {
		t.Fatalf("nodes: %+v changes %d", nodes, len(*changes))
	}
}

func TestReconnectFromTheSamePodKeepsQueueAndGeneration(t *testing.T) {
	ch, clk, _ := newChannel(t)
	p, first := enroll(t, ch, epochA)
	w, err := ch.Enqueue("node-uid", collector.WorkSnapshot, clk.now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Report(p, report(clk.now())); err != nil || !ch.Nodes()[0].Current {
		t.Fatalf("report: %v", err)
	}
	ch.Disconnect(p, first)
	if ch.Nodes()[0].Current {
		t.Fatal("a closed stream stayed current")
	}
	again, second, err := ch.Connect(collector.Identity{NodeName: "node-a", NodeUID: "node-uid", PodUID: p.PodUID, Epoch: epochB}, allKinds)
	if err != nil {
		t.Fatal(err)
	}
	if again != p || second == first || ch.Nodes()[0].Identity.Epoch != epochA {
		t.Fatalf("reconnect: %+v %d %+v", again, second, ch.Nodes()[0].Identity)
	}
	ch.Disconnect(p, first)
	if !ch.Nodes()[0].Current {
		t.Fatal("an old stream's close ended the new stream")
	}
	got, err := ch.Next(context.Background(), p, second, 0)
	if err != nil || len(got) != 1 || got[0].ID != w.ID {
		t.Fatalf("resent work: %+v %v", got, err)
	}
	if _, err := ch.Next(context.Background(), p, first, 0); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatal("an old stream still receives work")
	}
}

func TestNextDeliversQueuedWorkAndWakesOnEnqueue(t *testing.T) {
	ch, clk, _ := newChannel(t)
	p, stream := enroll(t, ch, epochA)
	result := make(chan []collector.Work, 1)
	go func() {
		w, _ := ch.Next(context.Background(), p, stream, 0)
		result <- w
	}()
	time.Sleep(20 * time.Millisecond)
	w, err := ch.Enqueue("node-uid", collector.WorkSnapshot, clk.now().Add(time.Minute))
	if err != nil || w.Sequence != 1 {
		t.Fatalf("enqueue: %+v %v", w, err)
	}
	select {
	case got := <-result:
		if len(got) != 1 || got[0].ID != w.ID {
			t.Fatalf("woken stream: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enqueue did not wake the stream")
	}
	if got, _ := ch.Poll(context.Background(), p, "", 1, 0); len(got) != 0 {
		t.Fatal("work at or below After was repeated")
	}
	if _, err := ch.Enqueue("node-uid", "exec", clk.now().Add(time.Minute)); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("open work kind")
	}
	if _, err := ch.Enqueue("other", collector.WorkStopSource, clk.now().Add(time.Minute)); err == nil {
		t.Fatal("work for an unknown node")
	}
	for i := 1; i < collector.MaxQueuedWork; i++ {
		if _, err := ch.Enqueue("node-uid", collector.WorkStopSource, clk.now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ch.Enqueue("node-uid", collector.WorkStopSource, clk.now().Add(time.Minute)); !errors.Is(err, ErrNodeLimit) {
		t.Fatal("queue bound")
	}
	// Receipts answer work; expired work is dropped as well.
	r := report(clk.now())
	r.Receipts = []collector.Receipt{{WorkID: w.ID, Sequence: 1, Outcome: collector.OutcomeRefused, Reason: collector.ReasonRecorderNotImplemented}}
	if err := ch.Report(p, r); err != nil || ch.Nodes()[0].Queued != collector.MaxQueuedWork-1 {
		t.Fatalf("receipt did not remove its work: %v", err)
	}
	clk.add(time.Minute)
	if err := ch.Report(p, report(clk.now())); err != nil || ch.Nodes()[0].Queued != 0 {
		t.Fatalf("expired work kept: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ch.Next(ctx, p, stream, 0); !errors.Is(err, ErrNodeUnavailable) {
		t.Fatal("cancelled stream")
	}
}

func TestOnlyAnnouncedKindsAreQueued(t *testing.T) {
	ch, clk, _ := newChannel(t)
	if _, _, err := ch.Connect(collector.Identity{NodeName: "node-a", NodeUID: "node-uid", PodUID: "pod", Epoch: epochA}, []collector.WorkKind{collector.WorkStopSource}); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.Enqueue("node-uid", collector.WorkSnapshot, clk.now().Add(time.Minute)); !errors.Is(err, ErrNodeUnavailable) {
		t.Fatalf("unannounced kind: %v", err)
	}
	if _, err := ch.Enqueue("node-uid", collector.WorkStopSource, clk.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestReportValidationAndCurrency(t *testing.T) {
	ch, clk, _ := newChannel(t)
	p, stream := enroll(t, ch, epochA)
	if err := ch.Report(p, collector.Report{}); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("report without time")
	}
	observed := clk.now()
	if err := ch.Report(p, report(observed)); err != nil {
		t.Fatal(err)
	}
	clk.add(time.Hour)
	v := ch.Nodes()[0]
	if !v.Current || !v.ReportedAt.Equal(clk.now()) || !v.Report.ObservedAt.Equal(clk.now()) {
		t.Fatalf("an open stream's report is current: %+v", v)
	}
	ch.Disconnect(p, stream)
	if v := ch.Nodes()[0]; v.Current || !v.ReportedAt.Equal(observed) {
		t.Fatalf("closed stream: %+v", v)
	}
	bad := report(clk.now())
	bad.Receipts = []collector.Receipt{{WorkID: "w", Outcome: "maybe"}}
	if err := ch.Report(p, bad); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("open outcome")
	}
}

func TestReceiptMustMatchSequenceAndWorkID(t *testing.T) {
	ch, clk, _ := newChannel(t)
	p, _ := enroll(t, ch, epochA)
	w, err := ch.Enqueue("node-uid", collector.WorkSnapshot, clk.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r := report(clk.now())
	r.Receipts = []collector.Receipt{{WorkID: "bbbbbbbb-0000-4000-8000-000000000000", Sequence: w.Sequence, Outcome: collector.OutcomeRefused}}
	if err := ch.Report(p, r); err != nil || ch.Nodes()[0].Queued != 1 {
		t.Fatalf("a receipt with another work ID removed the item: %v", err)
	}
	r.Receipts = []collector.Receipt{{WorkID: w.ID, Sequence: w.Sequence + 1, Outcome: collector.OutcomeRefused}}
	if err := ch.Report(p, r); err != nil || ch.Nodes()[0].Queued != 1 {
		t.Fatalf("a receipt with another sequence removed the item: %v", err)
	}
	r.Receipts = []collector.Receipt{{WorkID: w.ID, Sequence: w.Sequence, Outcome: collector.OutcomeRefused}}
	if err := ch.Report(p, r); err != nil || ch.Nodes()[0].Queued != 0 {
		t.Fatalf("matching receipt: %v", err)
	}
}
