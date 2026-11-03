package manifest

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func profileExpectation(t *testing.T, typ string) (*Validator, artifact.ContextExpectation, artifact.Layout, artifact.Copies) {
	t.Helper()
	v, e, l, c, _ := fixture(t)
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.ActionID, e.DataClass = "a0123456789abcdef01234567", "raw"
	e.Profile = &artifact.GoProfileAcquisition{SourceRef: "api-local-pprof", EndpointDigest: artifact.Digest{7}, Type: typ, Mode: "interval", DurationMillis: 10_000}
	if typ == "heap" {
		e.Profile.Mode, e.Profile.DurationMillis, e.Profile.ForceGC = "snapshot", 0, true
	}
	e.NativeType = e.Profile.NativeType()
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	l.Binding = e.Binding()
	return v, e, l, c
}

// ADR-284: a Go endpoint profile's manifest records its acquisition facts
// as kind profile, class raw, and round-trips; the other format, a missing
// endpoint digest or a metadata class is refused.
func TestGoProfileManifest(t *testing.T) {
	for _, typ := range []string{"cpu", "heap", "runtimeTrace"} {
		v, e, l, c := profileExpectation(t, typ)
		started := e.TriggeredAt.Add(time.Second)
		b, err := v.MarshalContext(e, l, c, started, started.Add(2*time.Second))
		if err != nil {
			t.Fatal(typ, err)
		}
		if _, err := v.ParseContext(b, e, c); err != nil {
			t.Fatal(typ, err)
		}
		format := `"format":"pprof"`
		if typ == "runtimeTrace" {
			format = `"format":"go-trace"`
		}
		if !bytes.Contains(b, []byte(`"kind":"profile"`)) || bytes.Count(b, []byte(format)) != 2 || !bytes.Contains(b, []byte(`"sourceRef":"api-local-pprof"`)) || bytes.Contains(b, []byte("sampleTypes")) {
			t.Fatalf("%s manifest: %s", typ, b)
		}
		for name, change := range map[string][2]string{
			"class":           {`"dataClass":"raw"`, `"dataClass":"metadata"`},
			"endpoint digest": {`"endpointDigest":`, `"endpointDigestX":`},
			"profile format":  {`"schemaVersion":"profile/v1","format":"pprof"`, `"schemaVersion":"profile/v1","format":"go-trace"`},
			"trace format":    {`"schemaVersion":"profile/v1","format":"go-trace"`, `"schemaVersion":"profile/v1","format":"pprof"`},
		} {
			changed := bytes.Replace(b, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(changed, b) {
				continue
			}
			if validate(v.manifest, changed, artifact.MaxRootBytes) == nil {
				t.Fatal(typ, "schema accepted", name)
			}
		}
	}
}

// Expectation rules: the native type follows the profile type, the class is
// raw, and profile facts never ride on another type.
func TestGoProfileExpectation(t *testing.T) {
	_, e, _, _ := profileExpectation(t, "cpu")
	for name, change := range map[string]func(*artifact.ContextExpectation){
		"trace type for cpu": func(x *artifact.ContextExpectation) { x.NativeType = artifact.GoTraceArtifact },
		"metadata class":     func(x *artifact.ContextExpectation) { x.DataClass = "metadata" },
		"no profile":         func(x *artifact.ContextExpectation) { x.Profile = nil },
		"profile on pcapng":  func(x *artifact.ContextExpectation) { x.NativeType = artifact.PCAPNGArtifact },
		"no endpoint digest": func(x *artifact.ContextExpectation) {
			p := *x.Profile
			p.EndpointDigest = artifact.Digest{}
			x.Profile = &p
		},
		"cpu over 60 s":         func(x *artifact.ContextExpectation) { p := *x.Profile; p.DurationMillis = 61_000; x.Profile = &p },
		"force GC on cpu":       func(x *artifact.ContextExpectation) { p := *x.Profile; p.ForceGC = true; x.Profile = &p },
		"over the type maximum": func(x *artifact.ContextExpectation) { x.Registration.NativeLimit = artifact.MaxPprofBytes + 1 },
		"pod-status action":     func(x *artifact.ContextExpectation) { x.ActionID = "pod-status" },
		"ongoing save": func(x *artifact.ContextExpectation) {
			l := artifact.OngoingLifecycle{}
			x.Lifecycle = &l
		},
	} {
		x := e
		change(&x)
		if x.Validate() == nil {
			t.Fatal("expectation accepted", name)
		}
	}
	if !e.ServedClass() {
		t.Fatal("valid raw profiles must remain eligible for verified publication and download")
	}
}

func feed(c NativeCheck, b []byte, chunk int) error {
	for len(b) > 0 {
		n := min(chunk, len(b))
		if err := c.Write(b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return c.Close()
}

// The producer bounds a pprof response by its gzip envelope only: header,
// trailer length declaration and minimum size, in any chunking.
func TestPprofProducerCheck(t *testing.T) {
	v, e, _, _ := profileExpectation(t, "cpu")
	gz := func(n int) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, _ = w.Write(make([]byte, n))
		_ = w.Close()
		return b.Bytes()
	}
	good := gz(1000)
	bomb := gz(artifact.MaxPprofDecompressedBytes + 1)
	reserved := bytes.Clone(good)
	reserved[3] |= 0x80
	for _, chunk := range []int{1, 3, 7, 8, 9, 4096} {
		for name, tc := range map[string]struct {
			b  []byte
			ok bool
		}{"gzip": {good, true}, "bomb": {bomb, false}, "plain": {[]byte("not a gzip stream at all"), false}, "reserved flag": {reserved, false}, "header only": {good[:10], false}, "empty": {nil, false}} {
			check, err := v.NativeCheck(e, ContextManifest{})
			if err != nil {
				t.Fatal(err)
			}
			if err = feed(check, tc.b, chunk); (err == nil) != tc.ok {
				t.Fatal(name, chunk, err)
			}
			if !tc.ok && !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatal(name, "error", err)
			}
		}
	}
}

func TestGoTraceProducerCheck(t *testing.T) {
	v, e, _, _ := profileExpectation(t, "runtimeTrace")
	for _, chunk := range []int{1, 5, 4096} {
		for name, tc := range map[string]struct {
			b  []byte
			ok bool
		}{
			"go 1.26":   {[]byte("go 1.26 trace\x00\x00\x00rest"), true},
			"go 1.22":   {[]byte("go 1.22 trace\x00\x00\x00"), true},
			"go 1.21":   {[]byte("go 1.21 trace\x00\x00\x00rest"), false},
			"pprof":     {[]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7}, false},
			"truncated": {[]byte("go 1.26 trace"), false},
		} {
			check, err := v.NativeCheck(e, ContextManifest{})
			if err != nil {
				t.Fatal(err)
			}
			if err = feed(check, tc.b, chunk); (err == nil) != tc.ok {
				t.Fatal(name, chunk, err)
			}
		}
	}
}
