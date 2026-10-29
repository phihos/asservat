package packets

import (
	planning "asservat.local/asservat/internal/domain/planning"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func ringFixture(t *testing.T, edit func(*RingLimits)) (*Ring, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	limits := RingLimits{MaxAge: 30 * time.Second, MaxBytes: 1024, SegmentBytes: 256, MaxSegments: 4, MaxFrozenBytes: 4096, MaxConcurrentSnapshots: 2}
	if edit != nil {
		edit(&limits)
	}
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Hour))
	t.Cleanup(cancel)
	r, err := NewRing(ctx, RingBounds{now, now.Add(time.Hour)}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err = r.ObservedThrough(now); err != nil {
		t.Fatal(err)
	} // Explicit synthetic attachment observation.
	return r, now
}
func ringAdd(t *testing.T, r *Ring, at, now time.Time) []byte {
	t.Helper()
	full := tcp4(t, true)
	prefix := full[:min(len(full), Snaplen)]
	if err := r.Add(prefix, uint32(len(full)), at, now); err != nil {
		t.Fatal(err)
	}
	return full
}
func ringCopy(t *testing.T, r *Ring, from, to, now time.Time) *RingSnapshot {
	t.Helper()
	s, err := r.Snapshot(RingWindow{from, to}, now, r.limits.MaxFrozenBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestRingSanitizedCopiedRecordsAndMaintainedPCAPNG(t *testing.T) {
	r, now := ringFixture(t, nil)
	for _, full := range corpus(t) {
		prefix := full[:min(len(full), Snaplen)]
		if err := r.Add(prefix, uint32(len(full)), now, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.ObservedThrough(now); err != nil {
		t.Fatal(err)
	}
	s := ringCopy(t, r, now, now, now)
	var output bytes.Buffer
	w, err := pcapgo.NewNgWriterInterface(&output, pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: Snaplen, TimestampResolution: 9}, pcapgo.NgWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		p, e := ringNext(s)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if !p.At.Equal(now) || p.Wire < uint32(p.Length) || p.Length > Snaplen {
			t.Fatal("original facts lost", p)
		}
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: p.At, CaptureLength: p.Length, Length: int(p.Wire)}, p.Header[:p.Length]); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	n, err := CheckHeadersOnly(bytes.NewReader(output.Bytes()))
	if err != nil || n != count || count == 0 || bytes.Contains(output.Bytes(), []byte(marker)) {
		t.Fatal("unsafe copied PCAPNG", n, count, err)
	}
	if r.State().Packets.Seen != uint64(len(corpus(t))) || r.State().Packets.Filtered != 0 {
		t.Fatal("lost counters", r.State())
	}
}
func TestRingOriginalRecordDoesNotAliasInputOrLiveRotation(t *testing.T) {
	r, now := ringFixture(t, nil)
	original := ringAdd(t, r, now, now)
	s := ringCopy(t, r, now, now, now)
	clear(original)
	for i := 1; i <= 20; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		ringAdd(t, r, at, at)
	}
	p, err := ringNext(s)
	if err != nil || p.Header[12] != 8 || !p.At.Equal(now) {
		t.Fatal("copy changed after overwrite", err, p)
	}
	if r.State().HistoryEvicted == 0 || r.State().LiveBytes != 1024 {
		t.Fatal("rotation not bounded", r.State())
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ringNext(s); !errors.Is(err, io.EOF) {
		t.Fatal("source close changed admitted copy", err)
	}
	p.Header[0] = 99 // A returned value is independently owned, even after Close.
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if r.State().FrozenBytes != 0 || r.State().Snapshots != 0 {
		t.Fatal("copy hold leaked", r.State())
	}
}
func TestRingQuietAgingNeverRestampsOldSegments(t *testing.T) {
	r, now := ringFixture(t, nil)
	ringAdd(t, r, now, now)
	ringAdd(t, r, now.Add(10*time.Second), now.Add(10*time.Second))
	if err := r.Advance(now.Add(31 * time.Second)); err != nil {
		t.Fatal(err)
	}
	s := ringCopy(t, r, now, now.Add(31*time.Second), now.Add(31*time.Second))
	if _, err := ringNext(s); !errors.Is(err, io.EOF) {
		t.Fatal("oldest record did not expire whole segment", err)
	}
	if !s.Coverage().HistoryEvicted || s.Coverage().Complete || r.State().HistoryEvicted != 2 {
		t.Fatal("age invented coverage", s.Coverage(), r.State())
	}
}
func TestRingQuietCoverageRequiresExplicitOwnerObservation(t *testing.T) {
	r, now := ringFixture(t, nil)
	end := now.Add(5 * time.Second)
	if err := r.Advance(end); err != nil {
		t.Fatal(err)
	}
	s := ringCopy(t, r, now, end, end)
	if s.Coverage().Complete {
		t.Fatal("housekeeping fabricated quiet observation")
	}
	s.Close()
	if err := r.ObservedThrough(end); err != nil {
		t.Fatal(err)
	}
	s = ringCopy(t, r, now, end, end)
	if !s.Coverage().Complete {
		t.Fatal("known quiet interval lost", s.Coverage())
	}
	if _, err := ringNext(s); !errors.Is(err, io.EOF) {
		t.Fatal("quiet snapshot fabricated packet", err)
	}
}
func TestRingEvictionAndInputGapsAreDistinctAndCanWarmAgain(t *testing.T) {
	r, now := ringFixture(t, nil)
	for i := 0; i < 20; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		ringAdd(t, r, at, at)
	}
	end := now.Add(time.Second)
	r.ObservedThrough(end)
	s := ringCopy(t, r, now, end, end)
	if !s.Coverage().HistoryEvicted || s.Coverage().InputUnknown {
		t.Fatal("overwrite became unknown input", s.Coverage())
	}
	s.Close()
	r.Gap(end)
	end = end.Add(time.Second)
	r.ObservedThrough(end)
	s = ringCopy(t, r, now, end, end)
	if !s.Coverage().InputUnknown || s.Coverage().Complete {
		t.Fatal("unknown input became zero loss", s.Coverage())
	}
	s.Close()
	s = ringCopy(t, r, now.Add(time.Second+time.Nanosecond), end, end)
	if !s.Coverage().Complete {
		t.Fatal("subsequent clean interval did not warm", s.Coverage())
	}
}
func TestRingBoundsAndStoppedSource(t *testing.T) {
	for _, mode := range []string{"caller-deadline", "source-deadline", "cancel", "stop"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Hour))
			defer cancel()
			bound := now.Add(2 * time.Second)
			if mode == "caller-deadline" {
				ctx, cancel = context.WithDeadline(ctx, bound)
				defer cancel()
				bound = now.Add(time.Minute)
			}
			limits := RingLimits{MaxAge: 30 * time.Second, MaxBytes: 512, SegmentBytes: 256, MaxSegments: 2, MaxFrozenBytes: 512, MaxConcurrentSnapshots: 1}
			r, err := NewRing(ctx, RingBounds{now, bound}, limits, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ringAdd(t, r, now, now)
			r.ObservedThrough(now)
			if mode == "stop" {
				r.Stop(now)
				if err = r.Stop(now); err != nil {
					t.Fatal("stop replay", err)
				}
				if err = r.Add(nil, 0, now, now); !errors.Is(err, ErrRingClosed) {
					t.Fatal("stopped accepted input", err)
				}
				s := ringCopy(t, r, now, now, now)
				if !s.Coverage().Complete || !s.Coverage().SourceStoppedAt.Equal(now) {
					t.Fatal(s.Coverage())
				}
				return
			}
			alias := r.arena
			if mode == "cancel" {
				cancel()
				err = r.Advance(now)
			} else {
				err = r.Advance(now.Add(2 * time.Second))
			}
			if !errors.Is(err, ErrRingClosed) || r.State().LiveBytes != 0 || !bytes.Equal(alias, make([]byte, len(alias))) {
				t.Fatal("original cutoff failed to erase", err, r.State())
			}
			if _, err = r.Snapshot(RingWindow{now, now}, now, 512); !errors.Is(err, ErrRingClosed) {
				t.Fatal("expired source supplied new copy", err)
			}
		})
	}
}
func TestRingCopyCapsAndCloseNextSynchronization(t *testing.T) {
	r, now := ringFixture(t, func(l *RingLimits) { l.MaxFrozenBytes = 84; l.MaxConcurrentSnapshots = 1 })
	ringAdd(t, r, now, now)
	if _, err := r.Snapshot(RingWindow{now, now}, now, 1); !errors.Is(err, ErrRingCapacity) {
		t.Fatal("copy exceeded declared bytes", err)
	}
	s, err := r.Snapshot(RingWindow{now, now}, now, 84)
	if err != nil {
		t.Fatal(err)
	}
	alias := s.data
	if _, err = r.Snapshot(RingWindow{now, now}, now, 84); !errors.Is(err, ErrRingCapacity) {
		t.Fatal("stalled consumer exceeded count/frozen", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			_, e := ringNext(s)
			if e != nil {
				return
			}
		}
	}()
	go func() { defer wg.Done(); s.Close(); s.Close() }()
	wg.Wait()
	if !bytes.Equal(alias, make([]byte, len(alias))) || r.State().FrozenBytes != 0 || r.State().Snapshots != 0 {
		t.Fatal("close did not wipe/release once", r.State())
	}
	if _, err = ringNext(s); !errors.Is(err, ErrRingClosed) {
		t.Fatal("closed iterator read", err)
	}
}
func TestRingInputAndConstructorNegatives(t *testing.T) {
	for _, mode := range []string{"wire", "future", "old", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			r, now := ringFixture(t, func(l *RingLimits) {
				if mode == "oversized" {
					l.SegmentBytes = 64
				}
			})
			full := tcp4(t, true)
			prefix := full[:min(Snaplen, len(full))]
			at := now
			wire := uint32(len(full))
			if mode == "wire" {
				wire = 0
			}
			if mode == "future" {
				at = now.Add(time.Second)
			}
			if mode == "old" {
				at = now.Add(-time.Second)
			}
			if err := r.Add(prefix, wire, at, now); err == nil {
				t.Fatal("invalid input retained")
			}
			if r.State().Packets.Retained != 0 {
				t.Fatal(r.State())
			}
		})
	}
	r, now := ringFixture(t, nil)
	limits := r.limits
	for _, mode := range []string{"unbounded", "segments", "product", "age", "frozen", "snapshots"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			l := limits
			switch mode {
			case "unbounded":
				ctx = context.Background()
			case "segments":
				l.MaxSegments = 65
			case "product":
				l.SegmentBytes = 1024
			case "age":
				l.MaxAge = time.Hour + 1
			case "frozen":
				l.MaxFrozenBytes = 0
			case "snapshots":
				l.MaxConcurrentSnapshots = 5
			}
			if x, err := NewRing(ctx, RingBounds{now, now.Add(time.Minute)}, l, nil); err == nil {
				x.Close()
				t.Fatal("invalid constructor admitted")
			}
		})
	}
}

func TestRingOutOfOrderTimesAndOriginalWireFilter(t *testing.T) {
	r, now := ringFixture(t, nil)
	ringAdd(t, r, now.Add(10*time.Second), now.Add(10*time.Second))
	ringAdd(t, r, now.Add(5*time.Second), now.Add(11*time.Second))
	s := ringCopy(t, r, now, now.Add(11*time.Second), now.Add(11*time.Second))
	first, _ := ringNext(s)
	second, _ := ringNext(s)
	if !first.At.Equal(now.Add(10*time.Second)) || !second.At.Equal(now.Add(5*time.Second)) {
		t.Fatal("timestamp rewritten or sorted as arrival", first.At, second.At)
	}
	s.Close()
	r.Advance(now.Add(36 * time.Second))
	if r.State().HistoryEvicted != 2 {
		t.Fatal("out-of-order earliest expiry ignored", r.State())
	}
	filtered, err := NewRing(r.ctx, r.bounds, r.limits, greater1000)
	if err != nil {
		t.Fatal(err)
	}
	defer filtered.Close()
	full := tcp4(t, true)
	prefix := full[:min(Snaplen, len(full))]
	filtered.Add(prefix, 500, now, now)
	filtered.Add(prefix, 1500, now, now)
	if filtered.State().Packets.Filtered != 1 || filtered.State().Packets.Retained != 1 || filtered.State().Packets.WireBytes != 1500 {
		t.Fatal("filter used prefix rather than original wire", filtered.State())
	}
	copy := ringCopy(t, filtered, now, now, now)
	p, e := ringNext(copy)
	if e != nil || p.Wire != 1500 {
		t.Fatal("original wire not copied", e, p.Wire)
	}
}
func TestRingIndependentFrozenAndCountCaps(t *testing.T) {
	for _, mode := range []string{"bytes", "count"} {
		t.Run(mode, func(t *testing.T) {
			r, now := ringFixture(t, func(l *RingLimits) {
				if mode == "bytes" {
					l.MaxFrozenBytes = 84
					l.MaxConcurrentSnapshots = 2
				} else {
					l.MaxFrozenBytes = 168
					l.MaxConcurrentSnapshots = 1
				}
			})
			ringAdd(t, r, now, now)
			a, e := r.Snapshot(RingWindow{now, now}, now, 84)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			if _, e = r.Snapshot(RingWindow{now, now}, now, 84); !errors.Is(e, ErrRingCapacity) {
				t.Fatal("independent cap ignored", e)
			}
			if r.State().Snapshots != 1 || r.State().FrozenBytes != 84 {
				t.Fatal("refusal changed reservations", r.State())
			}
		})
	}
}

func TestRingInvalidArrivalClockCannotLeaveCompleteCoverage(t *testing.T) {
	r, now := ringFixture(t, nil)
	end := now.Add(time.Second)
	ringAdd(t, r, now, end)
	full := tcp4(t, true)
	if err := r.Add(full[:min(Snaplen, len(full))], uint32(len(full)), now, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("backward arrival clock accepted", err)
	}
	r.ObservedThrough(end.Add(time.Second))
	s := ringCopy(t, r, now, end.Add(time.Second), end.Add(time.Second))
	if s.Coverage().Complete || !s.Coverage().InputUnknown {
		t.Fatal("refused input left false complete coverage", s.Coverage())
	}
}

func ringNext(s *RingSnapshot) (RingPacket, error) {
	var p RingPacket
	err := s.Next(&p)
	return p, err
}

func TestRingFirstObservationCannotBackfillQuietOrFutureCoverage(t *testing.T) {
	template, now := ringFixture(t, nil)
	r, e := NewRing(template.ctx, template.bounds, template.limits, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	end := now.Add(time.Second)
	if e = r.ObservedThrough(end); e != nil {
		t.Fatal(e)
	}
	s := ringCopy(t, r, now, end, end)
	if s.Coverage().Complete || !s.Coverage().InputUnknown {
		t.Fatal("first late assertion backfilled source start", s.Coverage())
	}
}
func TestRingFutureRequestedWindowPreservesOnlyAvailableCopy(t *testing.T) {
	r, now := ringFixture(t, nil)
	ringAdd(t, r, now, now)
	end := now.Add(5 * time.Second)
	snapshot := ringCopy(t, r, now, end, now)
	if snapshot.Coverage().Complete || !snapshot.Coverage().Requested.Until.Equal(end) {
		t.Fatal("future window completed or rewritten", snapshot.Coverage())
	}
	ringAdd(t, r, now.Add(3*time.Second), now.Add(3*time.Second))
	r.ObservedThrough(now.Add(3 * time.Second))
	r.Stop(now.Add(3 * time.Second))
	first, err := ringNext(snapshot)
	if err != nil || !first.At.Equal(now) {
		t.Fatal(err, first.At)
	}
	if _, err = ringNext(snapshot); !errors.Is(err, io.EOF) {
		t.Fatal("snapshot acquired future data", err)
	}
	snapshot.Close()
	partial := ringCopy(t, r, now, end, now.Add(4*time.Second))
	if partial.Coverage().Complete || !partial.Coverage().SourceStoppedAt.Equal(now.Add(3*time.Second)) {
		t.Fatal("stopped source completed original future window", partial.Coverage())
	}
}

func TestRingUnacquiredHistoryIsNotReportedAsEviction(t *testing.T) {
	r, now := ringFixture(t, nil)
	s := ringCopy(t, r, now.Add(-time.Second), now, now)
	if s.Coverage().Complete || s.Coverage().HistoryEvicted || r.State().HistoryEvicted != 0 {
		t.Fatal("new source invented evicted history", s.Coverage(), r.State())
	}
}

func ringOptionFrame(tb testing.TB, shape string) []byte {
	tb.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 2}}
	if shape == "ip-options" {
		ip.Options = []layers.IPv4Option{{OptionType: 1}, {OptionType: 1}, {OptionType: 1}, {OptionType: 1}}
	}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 8080, ACK: true, Options: []layers.TCPOption{{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)}, {OptionType: layers.TCPOptionKindNop}, {OptionType: layers.TCPOptionKindNop}}}
	if shape == "tcp-many-options" {
		tcp.Options = make([]layers.TCPOption, 40)
		for i := range tcp.Options {
			tcp.Options[i] = layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1}
		}
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(bytes.Repeat([]byte(marker), 20))); e != nil {
		tb.Fatal(e)
	}
	return buf.Bytes()[:Snaplen]
}

func TestRingDecoderBorrowEndsWhenAddReturns(t *testing.T) {
	for _, mode := range []string{"tcp-options", "ip-options", "tcp-many-options", "filter-reject", "malformed", "oversized", "wire-invalid"} {
		t.Run(mode, func(t *testing.T) {
			r, now := ringFixture(t, func(l *RingLimits) {
				if mode == "oversized" {
					l.SegmentBytes = 64
				}
			})
			frame := ringOptionFrame(t, mode)
			if mode == "filter-reject" || mode == "wire-invalid" {
				if err := r.Add(frame, 1500, now, now); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "filter-reject" {
				r.filter, _ = NewFilter([]planning.BPFInstruction{{Code: 0x06}})
			}
			if mode == "malformed" {
				frame[0] = 255
				frame[12] = 255
				frame[13] = 255
			}
			wire := uint32(1500)
			if mode == "wire-invalid" {
				wire = 0
			}
			err := r.Add(frame, wire, now, now)
			if mode == "oversized" {
				if !errors.Is(err, ErrRingCapacity) {
					t.Fatal(err)
				}
			} else if mode == "wire-invalid" {
				if !errors.Is(err, ErrInvalid) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			// Reusing caller storage after Add must not mutate borrowed parser working
			// views. Those views may persist only against the ring's zeroed scratch.
			for i := range frame {
				frame[i] = 0xa5
			}
			views := [][]byte{r.decoder.eth.LayerContents(), r.decoder.eth.LayerPayload(), r.decoder.ip4.LayerContents(), r.decoder.ip4.LayerPayload(), r.decoder.tcp.LayerContents(), r.decoder.tcp.LayerPayload()}
			for _, view := range views {
				for _, v := range view {
					if v != 0 {
						t.Fatal("parser retained caller input beyond Add", mode)
					}
				}
			}
		})
	}
}

func TestRingWindowOneReservation(t *testing.T) {
	r, now := ringFixture(t, func(l *RingLimits) { l.MaxConcurrentSnapshots = 1; l.MaxFrozenBytes = 168 })
	end := now.Add(time.Second)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 168)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if s := r.State(); s.Snapshots != 1 || s.FrozenBytes != 168 {
		t.Fatal(s)
	}
	var p RingPacket
	if err = w.Next(&p); err == nil {
		t.Fatal("pending read")
	}
	if err = w.Complete(now); err == nil {
		t.Fatal("early completion")
	}
	ringAdd(t, r, end, end)
	if err = r.ObservedThrough(end); err != nil {
		t.Fatal(err)
	}
	backing := &w.snapshot.data[:cap(w.snapshot.data)][0]
	if err = w.Complete(end); err != nil {
		t.Fatal(err)
	}
	if backing != &w.snapshot.data[0] || cap(w.snapshot.data) != 168 || !w.Coverage().Complete {
		t.Fatal("reservation or coverage changed", w.Coverage())
	}
	for _, at := range []time.Time{now, end} {
		if err = w.Next(&p); err != nil || !p.At.Equal(at) {
			t.Fatal(p, err)
		}
	}
	if err = w.Next(&p); err != io.EOF {
		t.Fatal(err)
	}
	if err = w.Complete(end); err == nil {
		t.Fatal("second completion")
	}
	if s := r.State(); s.Snapshots != 1 || s.FrozenBytes != 168 {
		t.Fatal(s)
	}
	w.Close()
	w.Close()
	if s := r.State(); s.Snapshots != 0 || s.FrozenBytes != 0 {
		t.Fatal(s)
	}
}

func TestRingWindowStopExpiryAndCancellation(t *testing.T) {
	for _, mode := range []string{"stop", "gap", "close", "expiry", "after-expiry", "processing-expired", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			r, now := ringFixture(t, nil)
			end := now.Add(time.Second)
			ringAdd(t, r, now, now)
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
			defer cancel()
			w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			switch mode {
			case "stop":
				r.Stop(now)
			case "gap":
				r.Gap(end)
				r.ObservedThrough(end)
			case "close":
				r.Close()
			case "expiry":
				r.bounds.Until = end
			case "after-expiry":
				r.bounds.Until = end.Add(-time.Nanosecond)
			case "processing-expired":
				end = now.Add(time.Minute)
			case "cancel":
				cancel()
			}
			err = w.Complete(end)
			if mode == "processing-expired" || mode == "cancel" {
				if err == nil {
					t.Fatal("processing lifetime ignored")
				}
				return
			}
			if err != nil || w.Coverage().Complete {
				t.Fatal(err, w.Coverage())
			}
			var p RingPacket
			if err = w.Next(&p); err != nil || !p.At.Equal(now) {
				t.Fatal("precopy lost", err)
			}
		})
	}
}

func TestRingWindowCapacityAndConcurrentClose(t *testing.T) {
	r, now := ringFixture(t, nil)
	end := now.Add(time.Second)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 84)
	if err != nil {
		t.Fatal(err)
	}
	ringAdd(t, r, end, end)
	r.ObservedThrough(end)
	if err = w.Complete(end); !errors.Is(err, ErrRingCapacity) {
		t.Fatal(err)
	}
	var refused RingPacket
	if w.Next(&refused) == nil {
		t.Fatal("failed completion exposed iterator")
	}
	if cap(w.snapshot.data) != 84 || r.State().FrozenBytes != 84 || w.Coverage().Complete {
		t.Fatal("capacity grew")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var p RingPacket
			w.Next(&p)
			w.Coverage()
			w.Complete(end)
			w.Close()
		}()
	}
	wg.Wait()
	if s := r.State(); s.Snapshots != 0 || s.FrozenBytes != 0 {
		t.Fatal(s)
	}
}

func TestRingWindowPreEvictionDoesNotEraseCopiedCoverage(t *testing.T) {
	r, now := ringFixture(t, nil)
	end := now.Add(8 * time.Nanosecond)
	ringAdd(t, r, now, now)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 1; i <= 7; i++ {
		at := now.Add(time.Duration(i) * time.Nanosecond)
		ringAdd(t, r, at, at)
	}
	r.ObservedThrough(end)
	if r.State().HistoryEvicted == 0 {
		t.Fatal("test did not evict live prehistory")
	}
	if err = w.Complete(end); err != nil || !w.Coverage().Complete || w.Coverage().HistoryEvicted {
		t.Fatal(err, w.Coverage())
	}
	n := 0
	var p RingPacket
	for w.Next(&p) == nil {
		n++
	}
	if n != 9 {
		t.Fatal(n)
	}
}
func TestRingWindowAfterZeroHasNoNewAcquisition(t *testing.T) {
	r, now := ringFixture(t, nil)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, now}, now, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r.Close()
	if err = w.Complete(now); err != nil || !w.Coverage().Complete {
		t.Fatal(err, w.Coverage())
	}
}

type ringCheckingContext struct {
	context.Context
	check func() error
}

func (c ringCheckingContext) Err() error { return c.check() }

func TestRingWindowCopyCancellationChecks(t *testing.T) {
	for _, phase := range []string{"admit-processing", "admit-source", "complete-processing", "complete-source"} {
		t.Run(phase, func(t *testing.T) {
			r, now := ringFixture(t, nil)
			end := now.Add(time.Second)
			ringAdd(t, r, now, now)
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
			defer cancel()
			calls := 0
			checked := func(base context.Context, n int) context.Context {
				return ringCheckingContext{Context: base, check: func() error {
					calls++
					if calls >= n {
						return context.Canceled
					}
					return nil
				}}
			}
			if phase == "admit-processing" {
				ctx = checked(ctx, 2)
			}
			if phase == "admit-source" {
				r.ctx = checked(r.ctx, 2)
			}
			w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 1024)
			if phase == "admit-processing" || phase == "admit-source" {
				if err == nil || w != nil || r.State().FrozenBytes != 0 || r.State().Snapshots != 0 {
					t.Fatal("canceled admission retained hold", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			ringAdd(t, r, end, end)
			r.ObservedThrough(end)
			if phase == "complete-processing" {
				w.processing = checked(ctx, 3)
			} else {
				r.ctx = checked(r.ctx, 3)
			}
			err = w.Complete(end)
			if w.Coverage().Complete {
				t.Fatal("canceled copy became complete")
			}
			var p RingPacket
			if phase == "complete-processing" {
				if err == nil || w.Next(&p) == nil {
					t.Fatal("processing cancellation exposed bytes")
				}
			} else {
				if err != nil || w.Next(&p) != nil || !p.At.Equal(now) || w.Next(&p) != io.EOF {
					t.Fatal("source cancellation failed to preserve only prehistory", err, p)
				}
			}
		})
	}
}

func TestRingWindowInvalidCompletionDoesNotSeal(t *testing.T) {
	r, now := ringFixture(t, nil)
	end := now.Add(time.Second)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r.Stop(end.Add(time.Second))
	if err = w.Complete(end); !errors.Is(err, ErrInvalid) || w.finished {
		t.Fatal("backward completion sealed", err)
	}
	if err = w.Complete(end.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestRingWindowNextChecksProcessingAfterLockWait(t *testing.T) {
	r, now := ringFixture(t, nil)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, now}, now, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err = w.Complete(now); err != nil {
		t.Fatal(err)
	}
	w.snapshot.mu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); var p RingPacket; done <- w.Next(&p) }()
	<-started
	cancel()
	w.snapshot.mu.Unlock()
	if err = <-done; !errors.Is(err, ErrRingClosed) || w.snapshot.cursor != 0 {
		t.Fatal("canceled iterator advanced", err)
	}
}

// Revised operational cuts permit buffered late delivery; original times stay
// binding. These are a correction of the old mathematical watermark premise.
func TestRingWindowRetainsLatePreAtFinalCut(t *testing.T) {
	r, now := ringFixture(t, nil)
	end := now.Add(time.Second)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ringAdd(t, r, now, now.Add(time.Millisecond))
	ringAdd(t, r, end, end)
	r.ObservedThrough(end)
	if err = w.Complete(end); err != nil {
		t.Fatal(err)
	}
	n := 0
	var p RingPacket
	for w.Next(&p) == nil {
		n++
	}
	if n != 3 {
		t.Fatalf("late pre omitted: got%d want3", n)
	}
}
func TestRingWindowEvictedLatePreIsPartial(t *testing.T) {
	r, now := ringFixture(t, nil)
	end := now.Add(time.Second)
	ringAdd(t, r, now, now)
	ringAdd(t, r, now, now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, now, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ringAdd(t, r, now, now.Add(time.Nanosecond))
	ringAdd(t, r, now, now.Add(2*time.Nanosecond))
	for i := 1; i <= 7; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		ringAdd(t, r, at, at)
	}
	r.ObservedThrough(end)
	if err = w.Complete(end); err != nil {
		t.Fatal(err)
	}
	if w.Coverage().Complete || !w.Coverage().InputUnknown {
		t.Fatal("evicted uncopied late-pre reported full", w.Coverage())
	}
}

func TestRingWindowArrivalCutDelayedAndAfterZero(t *testing.T) {
	for _, afterZero := range []bool{false, true} {
		t.Run(fmt.Sprint(afterZero), func(t *testing.T) {
			r, now := ringFixture(t, nil)
			end := now.Add(time.Second)
			if afterZero {
				end = now
			}
			ringAdd(t, r, now, now)
			if !afterZero {
				ringAdd(t, r, end, end)
			}
			r.ObservedThrough(end)
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
			defer cancel()
			w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, end}, now, end, 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			// Late pre crosses q0; out-of-window newer data must never compensate it.
			ringAdd(t, r, now, end.Add(time.Nanosecond))
			ringAdd(t, r, end.Add(2*time.Nanosecond), end.Add(2*time.Nanosecond))
			if err = w.Complete(end.Add(2 * time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			n := 0
			var p RingPacket
			for w.Next(&p) == nil {
				n++
				if p.At.After(end) {
					t.Fatal("window widened", p.At)
				}
			}
			want := 3
			if afterZero {
				want = 2
			}
			if n != want {
				t.Fatal(n, want)
			}
			if !w.Coverage().Complete {
				t.Fatal(w.Coverage())
			}
		})
	}
}
func TestRingArrivalSequenceExhaustionRefuses(t *testing.T) {
	r, now := ringFixture(t, nil)
	r.state.Packets.Retained = ^uint64(0) - 1
	ringAdd(t, r, now, now)
	var sequence uint64
	r.walkRetained(RingWindow{now, now}, func(_ []byte, q uint64) { sequence = q })
	if sequence != ^uint64(0) {
		t.Fatal(sequence)
	}
	frame := tcp4(t, true)
	if err := r.Add(frame[:min(len(frame), Snaplen)], uint32(len(frame)), now, now); !errors.Is(err, ErrRingCapacity) {
		t.Fatal(err)
	}
	if r.state.Packets.Retained != ^uint64(0) {
		t.Fatal("counter refilled")
	}
	r.evict(0)
	if r.evictedRetainedThrough != ^uint64(0) {
		t.Fatal(r.evictedRetainedThrough)
	}
}

func TestRingAfterZeroFinalCutPreservesUnknownInput(t *testing.T) {
	for _, mode := range []string{"merge-after-gap", "closed-after-gap", "closed-no-gap"} {
		t.Run(mode, func(t *testing.T) {
			r, now := ringFixture(t, nil)
			ringAdd(t, r, now, now)
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
			defer cancel()
			w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, now}, now, now, 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if !w.pre.Complete {
				t.Fatal("precondition: complete precopy")
			}
			if mode != "closed-no-gap" {
				if err = r.Gap(now.Add(time.Nanosecond)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "merge-after-gap" {
				ringAdd(t, r, now, now.Add(2*time.Nanosecond))
			} else {
				r.Close()
			}
			if err = w.Complete(now.Add(2 * time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			if mode == "closed-no-gap" {
				if !w.Coverage().Complete || w.Coverage().InputUnknown {
					t.Fatal("unchanged frozen pre lost coverage", w.Coverage())
				}
				return
			}
			if w.Coverage().Complete || !w.Coverage().InputUnknown {
				t.Fatal("later unknown input disappeared", w.Coverage())
			}
			if mode == "merge-after-gap" {
				current, err := r.Snapshot(RingWindow{now, now}, now.Add(2*time.Nanosecond), 1024)
				if err != nil {
					t.Fatal(err)
				}
				defer current.Close()
				if current.Coverage().Complete || !current.Coverage().InputUnknown {
					t.Fatal("finite observation mismatch", current.Coverage())
				}
			}
		})
	}
}

func TestRingAfterZeroRetainsKnownStop(t *testing.T) {
	for _, closeSource := range []bool{false, true} {
		t.Run(fmt.Sprint(closeSource), func(t *testing.T) {
			r, now := ringFixture(t, nil)
			ringAdd(t, r, now, now)
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
			defer cancel()
			w, err := r.BeginWindowSnapshot(ctx, RingWindow{now, now}, now, now, 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			stop := now.Add(time.Nanosecond)
			if err = r.Stop(stop); err != nil {
				t.Fatal(err)
			}
			if closeSource {
				r.Close()
			}
			if err = w.Complete(now.Add(2 * time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			if !w.Coverage().Complete || !w.Coverage().SourceStoppedAt.Equal(stop) {
				t.Fatal("known stop disappeared", w.Coverage())
			}
		})
	}
}
