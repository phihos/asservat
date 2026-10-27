package delivery

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

const (
	boot   = "11111111-1111-4111-8111-111111111111"
	epochA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	epochB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

type fakeAttester struct {
	mu      sync.Mutex
	pod     string
	err     error
	calls   int
	block   chan struct{}
	started chan struct{}
}

func (a *fakeAttester) PrecheckNode(token []byte) error {
	if string(token) == "garbage" {
		return ErrNodeDenied
	}
	return nil
}

func (a *fakeAttester) AttestNode(_ context.Context, token []byte, bootID string) (collector.Identity, error) {
	a.mu.Lock()
	a.calls++
	block, started := a.block, a.started
	a.mu.Unlock()
	if block != nil {
		started <- struct{}{}
		<-block
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return collector.Identity{}, a.err
	}
	return collector.Identity{NodeName: "node-a", NodeUID: "node-uid", PodName: "collector-x", PodUID: a.pod, BootID: bootID, Runtime: "containerd://2.1.0"}, nil
}

type fakeIssuer struct{ n atomic.Int64 }

func (i *fakeIssuer) IssueNode(csr []byte, id collector.Identity, notAfter time.Time) ([]byte, [32]byte, error) {
	n := i.n.Add(1)
	der := []byte{byte(n), byte(n >> 8), 'c', 'e', 'r', 't'}
	return der, sha256.Sum256(der), nil
}

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

func newChannel(t *testing.T) (*NodeChannel, *fakeAttester, *clock, *[]NodeView) {
	t.Helper()
	att := &fakeAttester{pod: "pod-1"}
	clk := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	var mu sync.Mutex
	changes := &[]NodeView{}
	ch, err := NewNodeChannel(att, &fakeIssuer{}, clk.now, func(v NodeView) { mu.Lock(); *changes = append(*changes, v); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	return ch, att, clk, changes
}

func enroll(t *testing.T, ch *NodeChannel, epoch string) (NodePeer, [32]byte) {
	t.Helper()
	der, notAfter, id, err := ch.Enroll(context.Background(), "10.0.0.1", []byte("token"), []byte("csr"), boot, epoch)
	if err != nil || id.Epoch != epoch || notAfter.IsZero() {
		t.Fatalf("enroll: %v %+v", err, id)
	}
	d := sha256.Sum256(der)
	p, err := ch.Peer(d)
	if err != nil || p.Epoch != epoch || p.NodeUID != "node-uid" {
		t.Fatalf("peer: %v %+v", err, p)
	}
	return p, d
}

func report(seq uint64, at time.Time) collector.Report {
	f := collector.Facts{Kernel: collector.KernelVersion{Major: 6, Minor: 8, Patch: 0}}
	return collector.Report{Sequence: seq, ObservedAt: at, Facts: f, Mechanisms: collector.Assess(f)}
}

func TestEnrollValidatesInputAndAttestation(t *testing.T) {
	ch, att, _, _ := newChannel(t)
	ctx := context.Background()
	for _, c := range []struct{ token, csr, boot, epoch string }{{"", "c", boot, epochA}, {"t", "", boot, epochA}, {"t", "c", "boot", epochA}, {"t", "c", boot, "EPOCH"}} {
		if _, _, _, err := ch.Enroll(ctx, "10.0.0.1", []byte(c.token), []byte(c.csr), c.boot, c.epoch); !errors.Is(err, ErrNodeInvalid) {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	att.err = ErrNodeDenied
	if _, _, _, err := ch.Enroll(ctx, "10.0.0.1", []byte("t"), []byte("c"), boot, epochA); !errors.Is(err, ErrNodeDenied) {
		t.Fatalf("attestation failure: %v", err)
	}
	if len(ch.Nodes()) != 0 {
		t.Fatal("a denied enrollment registered a node")
	}
	if _, err := ch.Peer([32]byte{1}); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatal("unknown certificate authenticated")
	}
}

func TestRestartReplacesTheEarlierProcess(t *testing.T) {
	ch, att, _, changes := newChannel(t)
	old, oldCert := enroll(t, ch, epochA)
	done := make(chan error, 1)
	go func() {
		_, err := ch.Poll(context.Background(), old, epochA, 0, collector.PollHold)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	att.mu.Lock()
	att.pod = "pod-2"
	att.mu.Unlock()
	fresh, _ := enroll(t, ch, epochB)
	select {
	case err := <-done:
		if !errors.Is(err, ErrNodeUnauthenticated) {
			t.Fatalf("replaced poll: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced process's poll did not end")
	}
	if _, err := ch.Peer(oldCert); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatal("the replaced process still authenticates")
	}
	if err := ch.Report(old, epochA, report(1, time.Now())); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatalf("replaced report: %v", err)
	}
	if err := ch.Report(fresh, epochA, report(1, time.Now())); !errors.Is(err, ErrNodeConflict) {
		t.Fatalf("epoch mismatch: %v", err)
	}
	nodes := ch.Nodes()
	if len(nodes) != 1 || nodes[0].Identity.Epoch != epochB || nodes[0].Identity.PodUID != "pod-2" || len(*changes) != 2 {
		t.Fatalf("one current generation per node: %+v (changes %d)", nodes, len(*changes))
	}
}

func TestRenewalKeepsOneEarlierCertificateUntilExpiry(t *testing.T) {
	ch, _, clk, _ := newChannel(t)
	_, first := enroll(t, ch, epochA)
	clk.add(19 * time.Minute)
	_, second := enroll(t, ch, epochA)
	if _, err := ch.Peer(first); err != nil {
		t.Fatal("overlap: the earlier certificate is valid until its own expiry")
	}
	clk.add(time.Minute)
	if _, err := ch.Peer(first); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatal("an expired certificate authenticated")
	}
	_, third := enroll(t, ch, epochA)
	for _, d := range [][32]byte{second, third} {
		if _, err := ch.Peer(d); err != nil {
			t.Fatal(err)
		}
	}
	enroll(t, ch, epochA)
	if _, err := ch.Peer(second); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatal("more than two certificates kept per process")
	}
}

func TestPollDeliversQueuedWorkAndWakesOnEnqueue(t *testing.T) {
	ch, _, clk, _ := newChannel(t)
	p, _ := enroll(t, ch, epochA)
	got, err := ch.Poll(context.Background(), p, epochA, 0, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty poll: %v %v", got, err)
	}
	result := make(chan []collector.Work, 1)
	go func() {
		w, _ := ch.Poll(context.Background(), p, epochA, 0, collector.PollHold)
		result <- w
	}()
	time.Sleep(20 * time.Millisecond)
	w, err := ch.Enqueue("node-uid", collector.WorkSnapshot, clk.now().Add(time.Minute))
	if err != nil || w.Sequence != 1 || !validID(w.ID) {
		t.Fatalf("enqueue: %+v %v", w, err)
	}
	select {
	case got := <-result:
		if len(got) != 1 || got[0].ID != w.ID {
			t.Fatalf("woken poll: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enqueue did not wake the poll")
	}
	if got, _ := ch.Poll(context.Background(), p, epochA, 1, 0); len(got) != 0 {
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
	if got, _ := ch.Poll(context.Background(), p, epochA, 0, 0); len(got) != collector.MaxWorkPerPoll {
		t.Fatalf("one poll returns at most %d items, got %d", collector.MaxWorkPerPoll, len(got))
	}
	// Receipts answer work; expired work is dropped as well.
	r := report(1, clk.now())
	r.Receipts = []collector.Receipt{{WorkID: w.ID, Sequence: 1, Outcome: collector.OutcomeRefused, Reason: collector.ReasonRecorderNotImplemented}}
	if err := ch.Report(p, epochA, r); err != nil {
		t.Fatal(err)
	}
	if ch.Nodes()[0].Queued != collector.MaxQueuedWork-1 {
		t.Fatal("receipt did not remove its work")
	}
	clk.add(time.Minute)
	if err := ch.Report(p, epochA, report(2, clk.now())); err != nil || ch.Nodes()[0].Queued != 0 {
		t.Fatalf("expired work kept: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ch.Poll(ctx, p, epochA, 0, time.Second); !errors.Is(err, ErrNodeUnavailable) {
		t.Fatal("cancelled poll")
	}
	if _, err := ch.Poll(context.Background(), p, epochA, 0, collector.PollHold+1); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("unbounded hold")
	}
}

func TestReportOrderingSpacingAndCurrency(t *testing.T) {
	ch, _, clk, changes := newChannel(t)
	p, _ := enroll(t, ch, epochA)
	if err := ch.Report(p, epochA, report(0, clk.now())); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("sequence zero")
	}
	if err := ch.Report(p, epochA, report(1, clk.now())); err != nil {
		t.Fatal(err)
	}
	clk.add(500 * time.Millisecond)
	if err := ch.Report(p, epochA, report(2, clk.now())); !errors.Is(err, ErrNodeRateLimited) {
		t.Fatalf("spacing: %v", err)
	}
	clk.add(time.Second)
	if err := ch.Report(p, epochA, report(1, clk.now())); !errors.Is(err, ErrNodeConflict) {
		t.Fatal("sequence did not grow")
	}
	if err := ch.Report(p, epochA, report(2, clk.now())); err != nil {
		t.Fatal(err)
	}
	if n := len(*changes); n != 2 {
		t.Fatalf("an unchanged assessment is not a change: %d", n)
	}
	v := ch.Nodes()[0]
	if !v.Current || v.Reports != 2 || v.Report.Sequence != 2 {
		t.Fatalf("view %+v", v)
	}
	clk.add(collector.StatusStaleAfter + time.Second)
	if ch.Nodes()[0].Current {
		t.Fatal("a node without a report for three intervals is not current")
	}
	bad := report(3, clk.now())
	bad.Receipts = []collector.Receipt{{Outcome: "done"}}
	if err := ch.Report(p, epochA, bad); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("open receipt outcome")
	}
}

func TestEnrollmentIsBoundedBeforeAnyAPICall(t *testing.T) {
	ch, att, clk, _ := newChannel(t)
	ctx := context.Background()
	enrollFrom := func(source, token string) error {
		_, _, _, err := ch.Enroll(ctx, source, []byte(token), []byte("csr"), boot, epochA)
		return err
	}
	// A token failing the cheap precheck costs no attestation and no budget.
	for i := 0; i < 50; i++ {
		if err := enrollFrom("10.0.0.9", "garbage"); !errors.Is(err, ErrNodeDenied) {
			t.Fatal(err)
		}
	}
	if att.calls != 0 {
		t.Fatalf("precheck failures reached the attester %d times", att.calls)
	}
	// Per source: a burst of 3, then one per 5 seconds.
	for i := 0; i < enrollSourceBurst; i++ {
		if err := enrollFrom("10.0.0.9", "token"); err != nil {
			t.Fatalf("burst %d: %v", i, err)
		}
	}
	if err := enrollFrom("10.0.0.9", "token"); !errors.Is(err, ErrNodeRateLimited) || att.calls != enrollSourceBurst {
		t.Fatalf("source over its burst: %v (attestations %d)", err, att.calls)
	}
	clk.add(enrollSourceEvery)
	if err := enrollFrom("10.0.0.9", "token"); err != nil {
		t.Fatalf("after the source interval: %v", err)
	}
	// Globally: the bucket refilled to its burst during the 5 seconds and the
	// last enrollment took one; the rest go to other sources, then 5 per second.
	for i := 0; i < enrollBurst-1; i++ {
		if err := enrollFrom("10.1.0."+string(rune('a'+i)), "token"); err != nil {
			t.Fatalf("global burst %d: %v", i, err)
		}
	}
	if err := enrollFrom("10.2.0.1", "token"); !errors.Is(err, ErrNodeRateLimited) {
		t.Fatalf("global burst exhausted: %v", err)
	}
	clk.add(time.Second)
	for i := 0; i < enrollRate; i++ {
		if err := enrollFrom("10.3.0."+string(rune('a'+i)), "token"); err != nil {
			t.Fatalf("global refill %d: %v", i, err)
		}
	}
	if err := enrollFrom("10.4.0.1", "token"); !errors.Is(err, ErrNodeRateLimited) {
		t.Fatal("global rate exceeded")
	}
}

func TestEnrollmentInFlightBound(t *testing.T) {
	ch, att, clk, _ := newChannel(t)
	att.mu.Lock()
	att.block, att.started = make(chan struct{}), make(chan struct{}, enrollInFlight)
	att.mu.Unlock()
	done := make(chan error, enrollInFlight)
	for i := 0; i < enrollInFlight; i++ {
		go func(i int) {
			_, _, _, err := ch.Enroll(context.Background(), "10.5.0."+string(rune('a'+i)), []byte("token"), []byte("csr"), boot, epochA)
			done <- err
		}(i)
		<-att.started
	}
	if _, _, _, err := ch.Enroll(context.Background(), "10.6.0.1", []byte("token"), []byte("csr"), boot, epochA); !errors.Is(err, ErrNodeRateLimited) {
		t.Fatalf("ninth concurrent attestation: %v", err)
	}
	close(att.block)
	for i := 0; i < enrollInFlight; i++ {
		<-done
	}
	att.mu.Lock()
	att.block = nil
	att.mu.Unlock()
	clk.add(time.Second)
	if _, _, _, err := ch.Enroll(context.Background(), "10.6.0.1", []byte("token"), []byte("csr"), boot, epochA); err != nil {
		t.Fatalf("slot released: %v", err)
	}
}

func TestReceiptMustMatchSequenceAndWorkID(t *testing.T) {
	ch, _, clk, _ := newChannel(t)
	p, _ := enroll(t, ch, epochA)
	w, err := ch.Enqueue("node-uid", collector.WorkSnapshot, clk.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r := report(1, clk.now())
	r.Receipts = []collector.Receipt{{WorkID: "bbbbbbbb-0000-4000-8000-000000000000", Sequence: w.Sequence, Outcome: collector.OutcomeRefused}}
	if err := ch.Report(p, epochA, r); err != nil || ch.Nodes()[0].Queued != 1 {
		t.Fatalf("a receipt with another work ID removed the item: %v", err)
	}
	clk.add(time.Second)
	r = report(2, clk.now())
	r.Receipts = []collector.Receipt{{WorkID: w.ID, Sequence: w.Sequence + 1, Outcome: collector.OutcomeRefused}}
	if err := ch.Report(p, epochA, r); err != nil || ch.Nodes()[0].Queued != 1 {
		t.Fatalf("a receipt with another sequence removed the item: %v", err)
	}
	clk.add(time.Second)
	r = report(3, clk.now())
	r.Receipts = []collector.Receipt{{WorkID: w.ID, Sequence: w.Sequence, Outcome: collector.OutcomeRefused}}
	if err := ch.Report(p, epochA, r); err != nil || ch.Nodes()[0].Queued != 0 {
		t.Fatalf("matching receipt: %v", err)
	}
}
