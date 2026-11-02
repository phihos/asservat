package diagnostics

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

// fuzzPprofLimit keeps bombs cheap: the property is the same at any bound.
const fuzzPprofLimit = 1 << 20

// FuzzCheckPprof feeds arbitrary bytes, raw and gzip-wrapped, to the
// publisher's pprof check: decompression bombs, oversized tables, invalid
// indexes and truncation. The check must never panic or exceed its bound,
// must be deterministic, and anything it accepts must parse into a
// structurally valid profile with named sample types.
func FuzzCheckPprof(f *testing.F) {
	valid := encoded(f, validProfile())
	f.Add(valid, false)
	f.Add(syntheticHeapProfile(f), false)
	f.Add(valid[:len(valid)/2], false)
	f.Add(append(bytes.Clone(valid), valid...), false)
	var plain bytes.Buffer
	_ = validProfile().WriteUncompressed(&plain)
	f.Add(plain.Bytes(), true)
	f.Add(bytes.Repeat([]byte{0}, 4096), true)                          // bomb shape once wrapped
	f.Add([]byte{0x12, 0x02, 0x08, 0x07, 0x22, 0x02, 0x08, 0x00}, true) // sample -> location 7 absent
	f.Add([]byte{0x1a, 0x0a, 0x08, 0x01, 0x10, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x18, 0x01}, true)
	f.Fuzz(func(t *testing.T, b []byte, wrap bool) {
		if len(b) > 64<<10 {
			return
		}
		in := b
		if wrap {
			var z bytes.Buffer
			w := gzip.NewWriter(&z)
			_, _ = w.Write(b)
			if len(b) <= 4096 { // a bomb: repeat the input past the bound
				for i := 0; i < fuzzPprofLimit/max(1, len(b))+1 && len(b) > 0 && b[0] == 0; i++ {
					_, _ = w.Write(b)
				}
			}
			_ = w.Close()
			in = z.Bytes()
		}
		err := checkPprof(bytes.NewReader(in), fuzzPprofLimit)
		if again := checkPprof(bytes.NewReader(in), fuzzPprofLimit); (again == nil) != (err == nil) {
			t.Fatal("verdict not deterministic", err, again)
		}
		if err != nil {
			if !errors.Is(err, ErrNotProfile) && !errors.Is(err, artifact.ErrLimit) {
				t.Fatal("unexpected error class", err)
			}
			return
		}
		r, gzErr := gzip.NewReader(bytes.NewReader(in))
		if gzErr != nil {
			t.Fatal("accepted a non-gzip stream")
		}
		var out bytes.Buffer
		if n, _ := out.ReadFrom(r); n > fuzzPprofLimit {
			t.Fatal("accepted past the bound", n)
		}
		p, parseErr := profile.ParseUncompressed(out.Bytes())
		if parseErr != nil || p.CheckValid() != nil || len(p.SampleType) == 0 || len(p.Mapping) > MaxPprofMappings {
			t.Fatal("accepted an invalid profile", parseErr)
		}
	})
}

// FuzzCheckGoTrace feeds arbitrary bytes after a valid or arbitrary header
// to the execution-trace check with a small event cap. It must never panic
// and must be deterministic; version 1 headers are always refused.
func FuzzCheckGoTrace(f *testing.F) {
	tr := syntheticTrace(f)
	f.Add(tr)
	f.Add(tr[:len(tr)/2])
	f.Add(tr[:16])
	f.Add(append([]byte("go 1.21 trace\x00\x00\x00"), tr[16:]...))
	f.Add(append([]byte("go 1.26 trace\x00\x00\x00"), 0xff, 0xff, 0xff, 0xff, 0x0f))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}
		done := make(chan error, 1)
		go func() { done <- checkGoTrace(bytes.NewReader(b), 4096) }()
		var err error
		select {
		case err = <-done:
		case <-time.After(10 * time.Second): // a hang is a failure, not a timeout of the run
			t.Fatalf("check did not finish on %d bytes", len(b))
		}
		if again := checkGoTrace(bytes.NewReader(b), 4096); (again == nil) != (err == nil) {
			t.Fatal("verdict not deterministic", err, again)
		}
		if err == nil && !artifact.GoTraceHeader(b) {
			t.Fatal("accepted without a version 2 header")
		}
	})
}
