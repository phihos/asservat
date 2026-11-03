package diagnostics

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

// syntheticHeapProfile is this test process's own heap profile, as
// net/http/pprof serves it with debug=0 (gzip-compressed protobuf).
func syntheticHeapProfile(t testing.TB) []byte {
	t.Helper()
	runtime.GC()
	var b bytes.Buffer
	if err := pprof.Lookup("heap").WriteTo(&b, 0); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// syntheticTrace is a short execution trace of this test process.
func syntheticTrace(t testing.TB) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := trace.Start(&b); err != nil {
		t.Skip("execution tracer already active", err)
	}
	done := make(chan struct{})
	go func() { time.Sleep(5 * time.Millisecond); close(done) }()
	<-done
	trace.Stop()
	return b.Bytes()
}

func gzipped(t testing.TB, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// encoded writes p as gzip-compressed protobuf without validation, so a test
// can store an inconsistent profile.
func encoded(t testing.TB, p *profile.Profile) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := p.WriteUncompressed(&b); err != nil {
		t.Fatal(err)
	}
	return gzipped(t, b.Bytes())
}

func validProfile() *profile.Profile {
	m := &profile.Mapping{ID: 1, Start: 0x1000, Limit: 0x2000, File: "synthetic"}
	f := &profile.Function{ID: 1, Name: "main.synthetic", SystemName: "main.synthetic", Filename: "synthetic.go"}
	l := &profile.Location{ID: 1, Mapping: m, Address: 0x1100, Line: []profile.Line{{Function: f, Line: 3}}}
	return &profile.Profile{
		SampleType:    []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "cpu", Unit: "nanoseconds"}},
		PeriodType:    &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:        10_000_000,
		DurationNanos: int64(10 * time.Second),
		TimeNanos:     time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC).UnixNano(),
		Sample:        []*profile.Sample{{Location: []*profile.Location{l}, Value: []int64{1, 10_000_000}}},
		Mapping:       []*profile.Mapping{m},
		Location:      []*profile.Location{l},
		Function:      []*profile.Function{f},
	}
}

func TestCheckPprof(t *testing.T) {
	heap := syntheticHeapProfile(t)
	if err := CheckPprof(bytes.NewReader(heap)); err != nil {
		t.Fatal("runtime/pprof heap profile", err)
	}
	if err := CheckPprof(bytes.NewReader(encoded(t, validProfile()))); err != nil {
		t.Fatal("synthetic CPU profile", err)
	}
	refused := map[string]func() []byte{
		"not gzip":         func() []byte { return []byte("not a profile") },
		"two members":      func() []byte { return append(bytes.Clone(heap), heap...) },
		"trailing garbage": func() []byte { return append(bytes.Clone(heap), 0) },
		"truncated":        func() []byte { return heap[:len(heap)-4] },
		"bad crc": func() []byte {
			b := bytes.Clone(heap)
			b[len(b)-8] ^= 1
			return b
		},
		"not a protobuf": func() []byte { return gzipped(t, []byte{0xff, 0xff, 0xff, 0xff}) },
		"empty profile":  func() []byte { return gzipped(t, nil) },
		"no sample type": func() []byte { p := validProfile(); p.SampleType, p.Sample = nil, nil; return encoded(t, p) },
		"unnamed unit":   func() []byte { p := validProfile(); p.SampleType[1].Unit = ""; return encoded(t, p) },
		"value count": func() []byte {
			p := validProfile()
			p.Sample[0].Value = []int64{1}
			return encoded(t, p)
		},
		"unknown location": func() []byte {
			p := validProfile()
			p.Location = nil
			return encoded(t, p)
		},
		"duplicate mapping id": func() []byte {
			p := validProfile()
			p.Mapping = append(p.Mapping, &profile.Mapping{ID: 1, Start: 0x3000, Limit: 0x4000})
			return encoded(t, p)
		},
		"mapping range": func() []byte { p := validProfile(); p.Mapping[0].Limit = 0x10; return encoded(t, p) },
		"negative duration": func() []byte {
			p := validProfile()
			p.DurationNanos = -1
			return encoded(t, p)
		},
		"over a day": func() []byte { p := validProfile(); p.DurationNanos = 86_400_000_000_001; return encoded(t, p) },
		"negative period": func() []byte {
			p := validProfile()
			p.Period = -1
			return encoded(t, p)
		},
		"too many mappings": func() []byte {
			p := validProfile()
			for i := uint64(2); i <= MaxPprofMappings+1; i++ {
				p.Mapping = append(p.Mapping, &profile.Mapping{ID: i, Start: i << 20, Limit: i<<20 + 1})
			}
			return encoded(t, p)
		},
	}
	for name, input := range refused {
		want := ErrNotProfile
		if name == "too many mappings" {
			want = artifact.ErrLimit
		}
		if err := CheckPprof(bytes.NewReader(input())); !errors.Is(err, want) {
			t.Fatal(name, err)
		}
	}
	// A decompression bomb stops at the bound and is refused as a limit.
	var bomb bytes.Buffer
	w, _ := gzip.NewWriterLevel(&bomb, gzip.BestCompression)
	_, _ = w.Write(make([]byte, artifact.MaxPprofDecompressedBytes+1))
	_ = w.Close()
	if bomb.Len() > 1<<20 {
		t.Fatal("bomb fixture is not small", bomb.Len())
	}
	if err := CheckPprof(&bomb); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal("decompression bomb", err)
	}
}

func TestCheckGoTrace(t *testing.T) {
	tr := syntheticTrace(t)
	if err := CheckGoTrace(bytes.NewReader(tr)); err != nil {
		t.Fatal("runtime/trace execution trace", err)
	}
	if err := checkGoTrace(bytes.NewReader(tr), 3); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal("event cap", err)
	}
	v1 := append([]byte("go 1.21 trace\x00\x00\x00"), tr[16:]...)
	for name, b := range map[string][]byte{
		"truncated":      tr[:len(tr)/2],
		"header only":    tr[:16],
		"version 1":      v1,
		"pprof":          syntheticHeapProfile(t),
		"trailing bytes": append(bytes.Clone(tr), 1, 2, 3),
	} {
		if err := CheckGoTrace(bytes.NewReader(b)); err == nil {
			t.Fatal("accepted", name)
		}
	}
}

// The streaming forms reach the same verdict for any chunking, and Close
// always ends the check goroutine, also after an early refusal.
func TestStreamingProfileChecks(t *testing.T) {
	heap, tr := syntheticHeapProfile(t), syntheticTrace(t)
	for _, chunk := range []int{1, 7, 4096, 1 << 20} {
		for name, tc := range map[string]struct {
			c  *ProfileCheck
			b  []byte
			ok bool
		}{
			"pprof":        {NewPprofCheck(), heap, true},
			"pprof as tr":  {NewGoTraceCheck(), heap, false},
			"trace":        {NewGoTraceCheck(), tr, true},
			"trace as pp":  {NewPprofCheck(), tr, false},
			"empty stream": {NewPprofCheck(), nil, false},
		} {
			var err error
			for b := tc.b; len(b) > 0 && err == nil; b = b[min(chunk, len(b)):] {
				err = tc.c.Write(b[:min(chunk, len(b))])
			}
			if closeErr := tc.c.Close(); err == nil {
				err = closeErr
			}
			if (err == nil) != tc.ok {
				t.Fatal(name, chunk, err)
			}
		}
	}
}

// TestPprofCheckMemory records the heap the publisher check retains while
// parsing a large synthetic profile close to the decompression bound.
func TestPprofCheckMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a large synthetic profile")
	}
	p := validProfile()
	// Distinct locations and functions: the table shape that costs most per
	// byte when parsed.
	for i := uint64(2); len(p.Location) < MaxPprofLocations; i++ {
		f := &profile.Function{ID: i, Name: "main.synthetic" + string(rune('a'+i%26)), Filename: "synthetic.go"}
		l := &profile.Location{ID: i, Mapping: p.Mapping[0], Address: 0x1000 + i, Line: []profile.Line{{Function: f, Line: int64(i)}}}
		p.Function = append(p.Function, f)
		p.Location = append(p.Location, l)
		p.Sample = append(p.Sample, &profile.Sample{Location: []*profile.Location{l, p.Location[0]}, Value: []int64{1, 10_000_000}})
	}
	var plain bytes.Buffer
	if err := p.WriteUncompressed(&plain); err != nil {
		t.Fatal(err)
	}
	b := gzipped(t, plain.Bytes())
	size := plain.Len()
	p, plain = nil, bytes.Buffer{}
	if size > artifact.MaxPprofDecompressedBytes {
		t.Fatal("fixture over the bound", size)
	}
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	// Sample the live heap while the check runs (stop-the-world reads; a
	// lower bound of the true peak).
	stop, peak := make(chan struct{}), make(chan uint64, 1)
	go func() {
		var m runtime.MemStats
		high := uint64(0)
		for {
			select {
			case <-stop:
				peak <- high
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&m)
				high = max(high, m.HeapInuse)
			}
		}
	}()
	start := time.Now()
	err := CheckPprof(io.MultiReader(bytes.NewReader(b)))
	elapsed := time.Since(start)
	close(stop)
	high := <-peak
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pprof check: %d decompressed bytes (%d compressed), peak live heap about %d MiB over a %d MiB baseline, %s", size, len(b), (high-min(high, base.HeapInuse))>>20, base.HeapInuse>>20, elapsed.Round(time.Millisecond))
}
