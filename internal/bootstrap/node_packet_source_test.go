package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/collector"
)

func sourceOwnerPermit(now time.Time) collector.SourcePermit {
	id := "11111111-1111-4111-8111-111111111111"
	return collector.SourcePermit{Binding: collector.SourceBinding{RootID: id, PolicyUID: "policy", AcceptanceID: id, SourceID: id, Fence: id, ActionID: "packets", PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}, StartedAt: now, HardUntil: now.Add(2 * time.Hour), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 1 << 20, BytesPerSecond: 1 << 20}
}
func sourceOwnerBudget(t *testing.T, now time.Time) (*collector.Budget, *sync.Mutex) {
	t.Helper()
	b, err := collector.NewBudget(collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: 2, InputBytesPerSecond: 2 << 20, InputBurstBytes: 2 << 20}, RingBytes: 4096, FrozenBytes: 4096}, now)
	if err != nil {
		t.Fatal(err)
	}
	return b, &sync.Mutex{}
}
func sourceOwnerLimits() packets.RingLimits {
	return packets.RingLimits{MaxAge: time.Second, MaxBytes: 1024, SegmentBytes: 256, MaxSegments: 4, MaxFrozenBytes: 4096, MaxConcurrentSnapshots: 2}
}

func TestPacketSourceQuietExpiryAndStaleTimerJoinBeforeRelease(t *testing.T) {
	now := time.Now().UTC()
	clock := &packetRingClock{at: now}
	p := sourceOwnerPermit(now)
	b, bmu := sourceOwnerBudget(t, now)
	started, cancelled, join := make(chan struct{}), make(chan struct{}), make(chan struct{})
	engine := func(ctx context.Context, pod string, snap int, _ func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		end, _ := ctx.Deadline()
		if !end.Equal(p.HardUntil) || pod != p.Binding.PodUID || snap != packets.Snaplen {
			t.Error("changed engine hard bound/source")
		}
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-join
		return gadget.CaptureStats{}, ctx.Err()
	}
	s, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, engine, clock.now, b, bmu)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	next := p
	clock.set(now.Add(15 * time.Second))
	next.IssuedAt = clock.now()
	next.DispatchUntil = next.IssuedAt.Add(5 * time.Second)
	next.LeafUntil = next.IssuedAt.Add(30 * time.Second)
	if err = s.Renew(next); err != nil {
		t.Fatal(err)
	}
	clock.set(p.LeafUntil)
	s.onTimer() // queued callback for the obsolete leaf
	select {
	case <-cancelled:
		t.Fatal("stale timer killed renewed source")
	default:
	}
	bmu.Lock()
	count, _, _ := b.SourceUsage()
	reserved := b.Usage(clock.now()).RingReserved
	bmu.Unlock()
	if count != 1 || reserved != 1024 {
		t.Fatal("renewal duplicated/released reservation", count, reserved)
	}
	clock.set(next.LeafUntil)
	s.onTimer()
	<-cancelled
	if !s.ring.State().Closed || s.ring.State().Stopped {
		t.Fatal("expiry did not erase, or fabricated natural stop")
	}
	bmu.Lock()
	count, _, _ = b.SourceUsage()
	bmu.Unlock()
	if count != 1 {
		t.Fatal("released before engine joined")
	}
	close(join)
	<-s.done
	bmu.Lock()
	count, rate, burst := b.SourceUsage()
	reserved = b.Usage(clock.now()).RingReserved
	bmu.Unlock()
	if count != 0 || rate != 0 || burst != 0 || reserved != 0 {
		t.Fatal("joined source leaked capacity")
	}
	if err = s.Renew(next); !errors.Is(err, collector.ErrObservationLeaseExpired) {
		t.Fatal("revived closed owner", err)
	}
	_ = s.Close() // idempotent, no second release
}

func TestPacketSourceQuietRingExpiryAndWireDebitBeforeDiscard(t *testing.T) {
	now := time.Now().UTC()
	clock := &packetRingClock{at: now}
	p := sourceOwnerPermit(now)
	b, bmu := sourceOwnerBudget(t, now)
	started := make(chan struct{})
	engine := func(ctx context.Context, _ string, _ int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		frame := syntheticTCP(80, "sensitive-payload")
		deliver(gadget.Frame{Data: frame, Wire: 1000, At: now})
		clear(frame)
		close(started)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	s, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, engine, clock.now, b, bmu)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	<-started
	s.mu.Lock()
	charged := s.meter.ObservedBytes()
	s.mu.Unlock()
	if charged != 1000 || s.ring.State().Packets.Retained != 1 {
		t.Fatal("wire not prepaid")
	}
	if !s.ring.NextExpiry().Equal(now.Add(time.Second + time.Nanosecond)) {
		t.Fatal("wrong quiet expiry", s.ring.NextExpiry())
	}
	clock.set(now.Add(time.Second + time.Nanosecond))
	s.onTimer()
	if state := s.ring.State(); state.Closed || state.HistoryEvicted != 1 || state.LiveBytes != 1024 {
		t.Fatal("quiet bytes not evicted under same reservation", state)
	}
	if !s.ring.NextExpiry().IsZero() {
		t.Fatal("expired history left repeated timer")
	}
	// A malformed observation still pays its original wire cost before the
	// sanitizer refuses and joins acquisition. No second frame is retained.
	s.add(gadget.Frame{Data: []byte{1, 2}, Wire: 1, At: clock.now()})
	<-s.done
	s.mu.Lock()
	charged = s.meter.ObservedBytes()
	unknown := s.inputUnknown
	s.mu.Unlock()
	if charged != 1001 || !unknown || !s.ring.State().Closed {
		t.Fatal("discard skipped debit or unknown-input closure", charged, unknown)
	}
}

func TestPacketSourceNaturalStopRetainsBoundedHistoryButCannotRenew(t *testing.T) {
	now := time.Now().UTC()
	clock := &packetRingClock{at: now}
	p := sourceOwnerPermit(now)
	b, bmu := sourceOwnerBudget(t, now)
	s, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		return gadget.CaptureStats{}, nil
	}, clock.now, b, bmu)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Synchronize with the actual engine completion without sleeping.
	for {
		s.mu.Lock()
		ended := s.engineExited
		s.mu.Unlock()
		if ended {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if state := s.ring.State(); !state.Stopped || state.Closed {
		t.Fatal("natural stop not retained", state)
	}
	if err = s.Renew(p); !errors.Is(err, collector.ErrObservationLeaseExpired) {
		t.Fatal("renewed stopped source", err)
	}
	clock.set(p.LeafUntil)
	s.onTimer()
	<-s.done
	if !s.ring.State().Closed {
		t.Fatal("natural history exceeded leaf")
	}
}

func TestPacketSourceCopiedWindowKeepsIndependentFrozenReservation(t *testing.T) {
	now := time.Now().UTC()
	clock := &packetRingClock{at: now}
	p := sourceOwnerPermit(now)
	b, bmu := sourceOwnerBudget(t, now)
	ready := make(chan struct{})
	s, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, func(ctx context.Context, _ string, _ int, add func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		frame := syntheticTCP(80, "secret-user-data")
		add(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: now})
		clear(frame)
		close(ready)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}, clock.now, b, bmu)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	<-ready
	processing, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	copy, err := s.BeginWindow(processing, packets.RingWindow{From: now, Until: now}, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if err = copy.Complete(now); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	bmu.Lock()
	sources, _, _ := b.SourceUsage()
	usage := b.Usage(now)
	bmu.Unlock()
	if sources != 0 || usage.RingReserved != 0 || usage.FrozenReserved != 1024 {
		t.Fatal("source shutdown released independent copied window", sources, usage)
	}
	var packet packets.RingPacket
	if err = copy.Next(&packet); err != nil || packet.Wire == 0 || bytes.Contains(packet.Header[:packet.Length], []byte("secret-user-data")) {
		t.Fatal("copied sanitized window changed on source close", packet, err)
	}
	if coverage := copy.Coverage(); coverage.Complete || !coverage.ObservedUntil.IsZero() {
		t.Fatal("invented quiet continuity", coverage)
	}
	if err = copy.Close(); err != nil {
		t.Fatal(err)
	}
	bmu.Lock()
	usage = b.Usage(now)
	bmu.Unlock()
	if usage.FrozenReserved != 0 {
		t.Fatal("closed copy leaked global frozen reservation")
	}
}

func TestPacketSourceRejectsUnknownTimestampAfterWireDebit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := sourceOwnerPermit(now)
	b, bmu := sourceOwnerBudget(t, now)
	ready := make(chan struct{})
	emitUnknown := make(chan struct{})
	engine := func(ctx context.Context, _ string, _ int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		close(ready)
		<-emitUnknown
		deliver(gadget.Frame{TimestampUnknown: true, Data: []byte{1, 2}, Wire: 100, At: now})
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	s, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, engine, func() time.Time { return now }, b, bmu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	<-ready
	close(emitUnknown)
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("unknown timestamp did not stop source")
	}
	s.mu.Lock()
	observed := s.meter.ObservedBytes()
	unknown := s.inputUnknown
	closed := s.closed
	s.mu.Unlock()
	if observed != 100 || !unknown || !closed || s.ring.State().LiveBytes != 0 {
		t.Fatal("unknown frame retained or observation refunded", observed, unknown, closed, s.ring.State())
	}
}

func TestPacketSourceUnknownNoticeInvalidatesAdmittedSnapshotCoverage(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := sourceOwnerPermit(now)
	b, bmu := sourceOwnerBudget(t, now)
	ready := make(chan struct{})
	engine := func(ctx context.Context, _ string, _ int, _ func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		close(ready)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	s, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, engine, func() time.Time { return now }, b, bmu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	<-ready
	// Explicit synthetic attachment observation; production owner does not assert
	// qualified quiet coverage. Exercise existing Ring semantics independently.
	if err = s.ring.ObservedThrough(now); err != nil {
		t.Fatal(err)
	}
	processing, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	snapshot, err := s.BeginWindow(processing, packets.RingWindow{From: now, Until: now}, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if !snapshot.HistoryCoverage().Complete {
		t.Fatal("baseline did not establish synthetic quiet precopy")
	}
	s.notice(gadget.InputNotice{})
	if err = snapshot.Complete(now); err != nil {
		t.Fatal(err)
	}
	if c := snapshot.Coverage(); c.Complete || !c.InputUnknown {
		t.Fatal("unknown input became complete saved evidence", c)
	}
}
