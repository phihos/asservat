package packets

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func ringBenchFrame(b *testing.B) []byte { return ringOptionFrame(b, "tcp-options") }
func ringBench(b *testing.B, filled bool) (*Ring, time.Time, []byte) {
	b.Helper()
	now := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Hour))
	b.Cleanup(cancel)
	limits := RingLimits{MaxAge: 30 * time.Second, MaxBytes: 16 << 20, SegmentBytes: 4 << 20, MaxSegments: 4, MaxFrozenBytes: 64 << 20, MaxConcurrentSnapshots: 4}
	r, e := NewRing(ctx, RingBounds{now, now.Add(time.Hour)}, limits, nil)
	if e != nil {
		b.Fatal(e)
	}
	b.Cleanup(func() { r.Close() })
	frame := ringBenchFrame(b)
	if filled {
		for i := 0; i < (16<<20)/84-4; i++ {
			at := now
			if i > 40000 {
				at = now.Add(time.Nanosecond)
			}
			if e = r.Add(frame, 1500, at, at); e != nil {
				b.Fatal(e)
			}
		}
	}
	return r, now, frame
}
func BenchmarkRingAppend(b *testing.B) {
	r, now, frame := ringBench(b, false)
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for b.Loop() {
		if e := r.Add(frame, 1500, now, now); e != nil {
			b.Fatal(e)
		}
	}
}
func BenchmarkRingFullSnapshotCopy(b *testing.B) {
	r, now, _ := ringBench(b, true)
	end := now.Add(time.Nanosecond)
	b.ReportAllocs()
	b.SetBytes(r.State().LiveBytes)
	b.ResetTimer()
	for b.Loop() {
		s, e := r.Snapshot(RingWindow{now, end}, end, 16<<20)
		if e != nil {
			b.Fatal(e)
		}
		s.Close()
	}
}
func BenchmarkRingQuietExpiry(b *testing.B) {
	r, now, _ := ringBench(b, true)
	template := bytes.Clone(r.arena)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		copy(r.arena, template)
		r.now = now
		r.floor = now
		b.StartTimer()
		if e := r.Advance(now.Add(31 * time.Second)); e != nil {
			b.Fatal(e)
		}
	}
}
func BenchmarkRingSnapshotConsumer(b *testing.B) {
	for _, mode := range []string{"PCAPNG", "PCAPNG-verify"} {
		b.Run(mode, func(b *testing.B) {
			r, now, _ := ringBench(b, true)
			s, e := r.Snapshot(RingWindow{now, now}, now.Add(time.Nanosecond), 8<<20)
			if e != nil {
				b.Fatal(e)
			}
			defer s.Close()
			var output bytes.Buffer
			output.Grow(8 << 20)
			b.ReportAllocs()
			b.SetBytes(int64(len(s.data)))
			b.ResetTimer()
			var p RingPacket
			for b.Loop() {
				s.cursor = 0
				output.Reset()
				var w *pcapgo.NgWriter
				if mode != "Next" {
					var dst io.Writer = io.Discard
					if mode == "PCAPNG-verify" {
						dst = &output
					}
					w, e = pcapgo.NewNgWriterInterface(dst, pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: Snaplen, TimestampResolution: 9}, pcapgo.NgWriterOptions{})
					if e != nil {
						b.Fatal(e)
					}
				}
				for {
					err := s.Next(&p)
					if err == io.EOF {
						break
					}
					if err != nil {
						b.Fatal(err)
					}
					if w != nil {
						if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: p.At, CaptureLength: p.Length, Length: int(p.Wire)}, p.Header[:p.Length]); err != nil {
							b.Fatal(err)
						}
					}
				}
				if w != nil {
					if e = w.Flush(); e != nil {
						b.Fatal(e)
					}
				}
				if mode == "PCAPNG-verify" {
					if _, e = CheckHeadersOnly(bytes.NewReader(output.Bytes())); e != nil {
						b.Fatal(e)
					}
				}
			}
		})
	}
}

// Existing parser/filter allocations are separate from the fixed history arena.
// This is setup allocation cost, not live heap/RSS or native engine overhead.
func BenchmarkRingConstructAndWireCache(b *testing.B) {
	for _, cache := range []bool{false, true} {
		name := "parser-filter"
		if cache {
			name = "4096-wire-VMs"
		}
		b.Run(name, func(b *testing.B) {
			frame := ringBenchFrame(b)
			now := time.Now()
			ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Hour))
			defer cancel()
			limits := RingLimits{MaxAge: time.Second, MaxBytes: 4096, SegmentBytes: 2048, MaxSegments: 2, MaxFrozenBytes: 4096, MaxConcurrentSnapshots: 1}
			b.ReportAllocs()
			for b.Loop() {
				r, e := NewRing(ctx, RingBounds{now, now.Add(time.Hour)}, limits, greater1000)
				if e != nil {
					b.Fatal(e)
				}
				if cache {
					for wire := 1000; wire < 1000+4096; wire++ {
						r.Add(frame, uint32(wire), now, now)
					}
				}
				r.Close()
			}
		})
	}
}

func BenchmarkRingSnapshotNext(b *testing.B) {
	r, now, _ := ringBench(b, true)
	s, e := r.Snapshot(RingWindow{now, now}, now.Add(time.Nanosecond), 8<<20)
	if e != nil {
		b.Fatal(e)
	}
	defer s.Close()
	var p RingPacket
	b.ReportAllocs()
	b.SetBytes(int64(len(s.data)))
	b.ResetTimer()
	for b.Loop() {
		s.cursor = 0
		for {
			err := s.Next(&p)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// Concurrent callback latency includes scheduler/GC and mutex contention; it
// is a local measured sample, not a Gadget loss/latency guarantee.
func BenchmarkRingSnapshotWithAppend(b *testing.B) {
	r, now, frame := ringBench(b, true)
	end := now.Add(time.Nanosecond)
	stop, done := make(chan struct{}), make(chan struct{})
	var maximum, total time.Duration
	var calls int64
	var appendErr error
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			started := time.Now()
			if appendErr = r.Add(frame, 1500, end, end); appendErr != nil {
				return
			}
			elapsed := time.Since(started)
			total += elapsed
			if elapsed > maximum {
				maximum = elapsed
			}
			calls++
		}
	}()
	join := sync.OnceFunc(func() { close(stop); <-done })
	defer join()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s, e := r.Snapshot(RingWindow{now, end}, end, 16<<20)
		if e != nil {
			b.Fatal(e)
		}
		s.Close()
	}
	b.StopTimer()
	join()
	if appendErr != nil {
		b.Fatal(appendErr)
	}
	b.ReportMetric(maximum.Seconds()*1000, "max-append-ms")
	if calls > 0 {
		b.ReportMetric(float64(total.Nanoseconds())/float64(calls), "avg-append-ns")
	}
}

func BenchmarkRingAppendShape(b *testing.B) {
	for _, shape := range []string{"tcp-options", "ip-options", "tcp-many-options"} {
		b.Run(shape, func(b *testing.B) {
			r, now, _ := ringBench(b, false)
			frame := ringOptionFrame(b, shape)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if e := r.Add(frame, 1500, now, now); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
