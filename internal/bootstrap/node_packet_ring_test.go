package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/collector"
)

type packetRingClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *packetRingClock) now() time.Time   { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *packetRingClock) set(at time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.at = at }

func packetRingFixture(t testing.TB, ctx context.Context, start time.Time, segment int64) *packets.Ring {
	t.Helper()
	until, _ := ctx.Deadline()
	r, err := packets.NewRing(ctx, packets.RingBounds{StartedAt: start, Until: until}, packets.RingLimits{MaxAge: 30 * time.Second, MaxBytes: segment * 4, SegmentBytes: segment, MaxSegments: 4, MaxFrozenBytes: 4096, MaxConcurrentSnapshots: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestPacketRingEngineCopiesOriginalWindowAndLatePre(t *testing.T) {
	for _, evict := range []bool{false, true} {
		t.Run(map[bool]string{false: "late-pre", true: "uncopied-late-pre-evicted"}[evict], func(t *testing.T) {
			start := time.Now().UTC().Truncate(time.Microsecond)
			ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
			defer cancel()
			clock := &packetRingClock{at: start}
			segment := int64(256)
			if evict {
				segment = 128
			}
			ring := packetRingFixture(t, ctx, start, segment)
			ready, proceed, post, finish := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			engine := func(call context.Context, pod string, snap int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
				if pod != "exact-pod" || snap != packets.Snaplen {
					t.Error("engine binding changed")
				}
				frame := syntheticTCP(80, "secret-payload")
				emit := func(at, observed time.Time) {
					clock.set(observed)
					deliver(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: at})
				}
				emit(start.Add(time.Second), start.Add(time.Second))
				close(ready)
				<-proceed
				emit(start.Add(1500*time.Millisecond), start.Add(3*time.Second))
				if evict {
					for i := 0; i < 5; i++ {
						emit(start.Add(time.Duration(5+i)*time.Second), start.Add(time.Duration(5+i)*time.Second))
					}
				} else {
					emit(start.Add(3*time.Second), start.Add(4*time.Second))
					emit(start.Add(5*time.Second), start.Add(5*time.Second))
				}
				clear(frame)
				close(post)
				<-finish
				return gadget.CaptureStats{}, nil
			}
			done := make(chan error, 1)
			go func() { _, err := runPacketRingEngine(ctx, engine, "exact-pod", ring, clock.now); done <- err }()
			<-ready
			processing, stopProcessing := context.WithDeadline(t.Context(), start.Add(time.Minute))
			defer stopProcessing()
			clock.set(start.Add(2 * time.Second))
			window, err := ring.BeginWindowSnapshot(processing, packets.RingWindow{From: start, Until: start.Add(4 * time.Second)}, start.Add(2*time.Second), clock.now(), 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer window.Close()
			close(proceed)
			<-post
			if err = window.Complete(clock.now()); err != nil {
				t.Fatal(err)
			}
			coverage := window.Coverage()
			if coverage.Complete || !coverage.ObservedUntil.IsZero() || coverage.InputUnknown != evict || ring.State().FrozenBytes != 1024 {
				t.Fatal("invented health/coverage or grew snapshot", coverage, ring.State())
			}
			close(finish)
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if err = ring.Close(); err != nil {
				t.Fatal(err)
			}
			var packet packets.RingPacket
			count := 0
			for {
				err = window.Next(&packet)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				if packet.Length != 54 || packet.Wire != uint32(len(syntheticTCP(80, "secret-payload"))) || packet.At.Before(start) || packet.At.After(start.Add(4*time.Second)) || bytes.Contains(packet.Header[:packet.Length], []byte("secret-payload")) {
					t.Fatal("borrowed/unsanitized/replacement packet", packet)
				}
			}
			want := 3
			if evict {
				want = 1
			}
			if count != want {
				t.Fatal("original arrival cut omitted/duplicated records", count, want)
			}
			stopProcessing()
			if !errors.Is(window.Next(&packet), packets.ErrRingClosed) {
				t.Fatal("processing cancellation accepted output")
			}
		})
	}
}

func TestPacketRingEngineQuietReturnDoesNotAssertHealth(t *testing.T) {
	start := time.Now().UTC()
	ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
	defer cancel()
	ring := packetRingFixture(t, ctx, start, 256)
	engine := func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		return gadget.CaptureStats{}, nil
	}
	if _, err := runPacketRingEngine(ctx, engine, "pod", ring, func() time.Time { return start }); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ring.Snapshot(packets.RingWindow{From: start, Until: start}, start, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if c := snapshot.Coverage(); c.Complete || !c.ObservedUntil.IsZero() {
		t.Fatal("quiet engine return invented coverage", c)
	}
}

func TestPacketRingEngineActiveCloseCancelsAndJoins(t *testing.T) {
	start := time.Now().UTC()
	ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
	defer cancel()
	ring := packetRingFixture(t, ctx, start, 256)
	ready, next := make(chan struct{}), make(chan struct{})
	joined := false
	engine := func(call context.Context, _ string, _ int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		frame := syntheticTCP(80, "")
		deliver(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: start})
		close(ready)
		<-next
		deliver(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: start})
		<-call.Done()
		joined = true
		return gadget.CaptureStats{}, call.Err()
	}
	done := make(chan error, 1)
	go func() {
		_, err := runPacketRingEngine(ctx, engine, "pod", ring, func() time.Time { return start })
		done <- err
	}()
	<-ready
	ring.Close()
	close(next)
	if err := <-done; !errors.Is(err, packets.ErrRingClosed) || !errors.Is(err, context.Canceled) || !joined || ring.State().Packets.Seen != 1 || ring.State().LiveBytes != 0 {
		t.Fatal("closed ring accepted callbacks or lost join", err, joined, ring.State())
	}
}

func TestPacketRingEngineNoticeCancelsAndPreservesUnknown(t *testing.T) {
	for _, lost := range []uint64{0, 7} {
		t.Run(map[bool]string{false: "unknown", true: "lost"}[lost > 0], func(t *testing.T) {
			start := time.Now().UTC().Truncate(time.Microsecond)
			ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
			defer cancel()
			clock := &packetRingClock{at: start}
			ring := packetRingFixture(t, ctx, start, 256)
			joined := false
			engine := func(call context.Context, _ string, _ int, deliver func(gadget.Frame), notice func(gadget.InputNotice)) (gadget.CaptureStats, error) {
				clock.set(start.Add(time.Second))
				frame := syntheticTCP(80, "x")
				deliver(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: clock.now()})
				notice(gadget.InputNotice{LostSamples: lost})
				<-call.Done()
				deliver(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: clock.now()})
				joined = true
				return gadget.CaptureStats{LostSamples: lost}, call.Err()
			}
			stats, err := runPacketRingEngine(ctx, engine, "pod", ring, clock.now)
			if !errors.Is(err, ErrObservationClosed) || !errors.Is(err, context.Canceled) || stats.LostSamples != lost || !joined || ring.State().Packets.Retained != 1 {
				t.Fatal("unknown/cancel/join lost", stats, err, joined, ring.State())
			}
			snapshot, err := ring.Snapshot(packets.RingWindow{From: start, Until: clock.now()}, clock.now(), 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer snapshot.Close()
			if !snapshot.Coverage().InputUnknown || snapshot.Coverage().Complete {
				t.Fatal("known gap hidden", snapshot.Coverage())
			}
		})
	}
}

func TestPacketRingEngineFinalLossSurvivesExpiredMemory(t *testing.T) {
	start := time.Now().UTC()
	ctx, cancel := context.WithDeadline(t.Context(), start.Add(20*time.Millisecond))
	defer cancel()
	ring := packetRingFixture(t, ctx, start, 256)
	engine := func(call context.Context, _ string, _ int, _ func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		<-call.Done()
		return gadget.CaptureStats{LostSamples: 9}, call.Err()
	}
	stats, err := runPacketRingEngine(ctx, engine, "pod", ring, time.Now)
	if stats.LostSamples != 9 || !errors.Is(err, ErrObservationClosed) || !errors.Is(err, context.DeadlineExceeded) || !ring.State().Closed {
		t.Fatal("final-only loss became natural success", stats, err, ring.State())
	}
}

func TestPacketRingEngineCancelJoinsBeforeCallerBudgetRelease(t *testing.T) {
	start := time.Now().UTC()
	ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
	source, stop := context.WithCancel(ctx)
	defer cancel()
	defer stop()
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1024}, start)
	if err := budget.ReserveRing(1024); err != nil {
		t.Fatal(err)
	}
	ring := packetRingFixture(t, source, start, 256)
	entered, canceled, join := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	engine := func(call context.Context, _ string, _ int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		close(entered)
		<-call.Done()
		frame := syntheticTCP(80, "")
		deliver(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: start})
		close(canceled)
		<-join
		return gadget.CaptureStats{}, nil
	}
	go func() { _, err := runPacketRingEngine(source, engine, "pod", ring, time.Now); done <- err }()
	<-entered
	stop()
	<-canceled
	select {
	case <-done:
		t.Fatal("unjoined engine returned")
	default:
	}
	if budget.Usage(time.Now()).RingReserved != 1024 || ring.State().Packets.Seen != 0 {
		t.Fatal("late callback or premature release")
	}
	close(join)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !ring.State().Closed {
		t.Fatal("joined canceled source memory not wiped")
	}
	// This is an explicit synthetic caller reservation, not a wired global owner.
	if err := budget.ReleaseRing(1024); err != nil || budget.Usage(time.Now()).RingReserved != 0 {
		t.Fatal(err)
	}
}

func TestPacketRingEngineFailureAndPreflight(t *testing.T) {
	for _, mode := range []string{"provider", "malformed", "capacity", "closed", "no-deadline"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Now().UTC()
			ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
			defer cancel()
			clock := &packetRingClock{at: start}
			segment := int64(256)
			if mode == "capacity" {
				segment = 64
			}
			ring := packetRingFixture(t, ctx, start, segment)
			if mode == "no-deadline" {
				ctx = context.Background()
			}
			if mode == "closed" {
				ring.Close()
			}
			providerErr := errors.New("synthetic engine failure")
			called := false
			engine := func(call context.Context, _ string, _ int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
				called = true
				if mode == "provider" {
					return gadget.CaptureStats{}, providerErr
				}
				frame := syntheticTCP(80, "")
				wire := uint32(len(frame))
				if mode == "malformed" {
					wire = 0
				}
				clock.set(start.Add(time.Second))
				deliver(gadget.Frame{Data: frame, Wire: wire, At: clock.now()})
				<-call.Done()
				return gadget.CaptureStats{}, call.Err()
			}
			_, err := runPacketRingEngine(ctx, engine, "pod", ring, clock.now)
			if err == nil || (mode == "provider" && !errors.Is(err, providerErr)) || ((mode == "no-deadline" || mode == "closed") == called) {
				t.Fatal(mode, called, err)
			}
		})
	}
}

func BenchmarkPacketRingBridgeCallback(b *testing.B) {
	for _, bridge := range []bool{false, true} {
		b.Run(map[bool]string{false: "direct-ring", true: "bridge"}[bridge], func(b *testing.B) {
			start := time.Now().UTC()
			ctx, cancel := context.WithDeadline(b.Context(), start.Add(time.Hour))
			defer cancel()
			ring, err := packets.NewRing(ctx, packets.RingBounds{StartedAt: start, Until: start.Add(time.Hour)}, packets.RingLimits{MaxAge: time.Hour, MaxBytes: 16 << 20, SegmentBytes: 4 << 20, MaxSegments: 4, MaxFrozenBytes: 16 << 20, MaxConcurrentSnapshots: 2}, nil)
			if err != nil {
				b.Fatal(err)
			}
			defer ring.Close()
			input := packetRingInput{ctx: ctx, cancel: cancel, ring: ring, now: time.Now}
			frame := syntheticTCP(80, "synthetic")
			f := gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: start}
			b.ReportAllocs()
			for b.Loop() {
				if bridge {
					input.add(f)
				} else if err := ring.Add(f.Data, f.Wire, f.At, time.Now()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
