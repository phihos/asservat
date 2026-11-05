package logs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func header(n uint16) artifact.LogHeader {
	return artifact.LogHeader{Record: "header", Format: artifact.LogFormat, PodUID: "original-pod", WindowStart: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), WindowEnd: time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC), Origins: n}
}
func origin(i uint16) artifact.LogOrigin {
	return artifact.LogOrigin{Record: "origin", OriginID: i, ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}
}
func coverage() artifact.LogCoverage {
	a := time.Date(2026, 11, 5, 2, 0, 0, 0, time.UTC)
	b := a.Add(time.Second)
	return artifact.LogCoverage{FetchOutcome: "complete", FetchStartedAt: &a, FetchFinishedAt: &b, Gaps: []string{"rotationUnknown"}}
}
func encode(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	e, err := NewEncoder(t.Context(), &b, header(1), artifact.LogNativeLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.BeginOrigin(origin(0)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = e.EndOrigin(coverage()); err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func decodeBytes(t *testing.T, native []byte) ([]byte, artifact.LogFooter, error) {
	t.Helper()
	var b bytes.Buffer
	f, err := Walk(t.Context(), bytes.NewReader(native), artifact.LogNativeLimit, Visitor{Fragment: func(f artifact.LogFragment) error {
		raw, err := f.Bytes()
		if err == nil {
			b.Write(raw)
		}
		clear(raw)
		return err
	}})
	return b.Bytes(), f, err
}
func TestLogCodecPreservesEmptyInvalidAndLongLines(t *testing.T) {
	for _, input := range [][]byte{nil, []byte("\n\n"), {0xff, 0, 0xfe, '\r', '\n', '\n', 'a'}, []byte(strings.Repeat("x", 20000) + "\nlast")} {
		native := encode(t, input)
		out, f, err := decodeBytes(t, native)
		if err != nil || !bytes.Equal(out, input) || f.SourceBytes != uint64(len(input)) {
			t.Fatal("lossy byte reconstruction", err, len(out), len(input), f)
		}
		for _, line := range bytes.Split(bytes.TrimSuffix(native, []byte{'\n'}), []byte{'\n'}) {
			if len(line)+1 > artifact.LogMaxLine {
				t.Fatal("line bound")
			}
		}
	}
}
func TestLogCodecCancellationKeepsOwningError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NewEncoder(ctx, io.Discard, header(1), artifact.LogNativeLimit); !errors.Is(err, context.Canceled) {
		t.Fatal("constructor cancellation lost", err)
	}
	if _, err := Walk(ctx, bytes.NewReader(encode(t, nil)), artifact.LogNativeLimit, Visitor{}); !errors.Is(err, context.Canceled) {
		t.Fatal("decoder cancellation lost", err)
	}
}
func TestLogCodecKnownTimeMustMatchPreservedPrefix(t *testing.T) {
	stamp := "2026-11-05T00:30:00Z"
	var b bytes.Buffer
	e, err := NewEncoder(t.Context(), &b, header(1), artifact.LogNativeLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.BeginOrigin(origin(0)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.WriteLineFragment([]byte("invented prefix\n"), &stamp); err == nil {
		t.Fatal("accepted time absent from original prefix")
	}
}
func mutate(t *testing.T, native []byte, index int, change func(map[string]any)) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(native, []byte{'\n'}), []byte{'\n'})
	var v map[string]any
	if err := json.Unmarshal(lines[index], &v); err != nil {
		t.Fatal(err)
	}
	change(v)
	line, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	lines[index] = line
	return append(bytes.Join(lines, []byte{'\n'}), '\n')
}
func TestLogCodecRejectsMalformedTailAndRecordOrder(t *testing.T) {
	valid := encode(t, []byte("one\n\nlast"))
	cases := map[string][]byte{"missingFooter": valid[:bytes.LastIndex(valid[:len(valid)-1], []byte{'\n'})+1], "noFinalNewline": valid[:len(valid)-1], "extraRecord": append(append([]byte{}, valid...), []byte("{}\n")...), "unknownField": mutate(t, valid, 0, func(v map[string]any) { v["payload"] = 1 }), "nullPod": mutate(t, valid, 0, func(v map[string]any) { v["pod_uid"] = nil }), "badCount": mutate(t, valid, 6, func(v map[string]any) { v["source_bytes"] = 999 }), "wrongOrigin": mutate(t, valid, 2, func(v map[string]any) { v["origin_id"] = 1 }), "offsetGap": mutate(t, valid, 3, func(v map[string]any) { v["offset"] = 999 }), "lineGap": mutate(t, valid, 3, func(v map[string]any) { v["line"] = 9 }), "base64Noncanonical": mutate(t, valid, 2, func(v map[string]any) { v["data"] = "b25lCg==\n" }), "interiorNewline": mutate(t, valid, 2, func(v map[string]any) { v["data"] = base64.StdEncoding.EncodeToString([]byte("x\ny\n")) }), "duplicate": bytes.Replace(valid, []byte(`"origins":1`), []byte(`"origins":1,"origins":1`), 1)}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			count := 0
			f, err := Walk(t.Context(), bytes.NewReader(data), artifact.LogNativeLimit, Visitor{Fragment: func(artifact.LogFragment) error { count++; return nil }})
			if err == nil || f != (artifact.LogFooter{}) {
				t.Fatal("invalid native accepted", err, f, count)
			}
		})
	}
}

func TestLogCodecParsedTimePrefixAndWindow(t *testing.T) {
	stamp := "2026-11-05T00:30:00.123Z"
	data := []byte(stamp + " message\r\n")
	var b bytes.Buffer
	e, err := NewEncoder(t.Context(), &b, header(1), artifact.LogNativeLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.BeginOrigin(origin(0)); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]byte{data[:5], data[5:]} {
		if _, err = e.WriteLineFragment(p, &stamp); err != nil {
			t.Fatal(err)
		}
	}
	if err = e.EndOrigin(coverage()); err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	out, _, err := decodeBytes(t, b.Bytes())
	if err != nil || !bytes.Equal(out, data) {
		t.Fatal("timestamp prefix changed", err)
	}
	bad := mutate(t, b.Bytes(), 2, func(v map[string]any) { v["source_time"] = "2026-11-05T00:31:00Z" })
	if _, _, err = decodeBytes(t, bad); err == nil {
		t.Fatal("known source time detached from prefix")
	}
	var other bytes.Buffer
	e, _ = NewEncoder(t.Context(), &other, header(1), artifact.LogNativeLimit)
	_ = e.BeginOrigin(origin(0))
	outside := "2026-11-05T02:30:00Z"
	if _, err = e.WriteLineFragment([]byte(outside+" x\n"), &outside); err == nil {
		t.Fatal("known time outside requested window")
	}
}
func TestLogCodecEveryOriginKeepsFairEncodedSpaceAndTail(t *testing.T) {
	const capBytes = int64(2 << 20)
	var b bytes.Buffer
	e, err := NewEncoder(t.Context(), &b, header(128), capBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'x'}, artifact.LogMaxFragmentBytes)
	retained := make([]uint64, 128)
	for i := uint16(0); i < 128; i++ {
		o := origin(i)
		o.ContainerName = "app-" + strconv.Itoa(int(i/2))
		if i%2 == 1 {
			o.Source = "previous"
		}
		runtime := strings.Repeat("&", 256)
		o.RuntimeID = &runtime
		if err = e.BeginOrigin(o); err != nil {
			t.Fatal(i, err)
		}
		for {
			n, err := e.Write(payload)
			retained[i] += uint64(n)
			if errors.Is(err, artifact.ErrLimit) {
				break
			}
			if err != nil {
				t.Fatal(i, err)
			}
		}
		if err = e.EndOrigin(coverage()); err != nil {
			t.Fatal("tail reservation", i, err)
		}
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(b.Len()) > capBytes {
		t.Fatal("encoded cap exceeded")
	}
	f, err := Walk(t.Context(), &b, capBytes, Visitor{Coverage: func(c artifact.LogCoverage) error {
		if c.FetchOutcome != "partial" || !hasGap(c, "outputFull") || c.SourceBytes != retained[c.OriginID] {
			t.Fatal(c)
		}
		return nil
	}})
	if err != nil || f.Origins != 128 {
		t.Fatal(err, f)
	}
	for i, n := range retained {
		if n == 0 || n != retained[0] {
			t.Fatal("unfair origin", i, n, retained[0])
		}
	}
}
func TestLogCodecZeroDataOutputFullStillFinalizes(t *testing.T) {
	var b bytes.Buffer
	h := header(1)
	raw, _ := json.Marshal(h)
	limit := int64(len(raw)+1) + originReserve + footerReserve
	e, err := NewEncoder(t.Context(), &b, h, limit)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.BeginOrigin(origin(0)); err != nil {
		t.Fatal(err)
	}
	if n, err := e.Write([]byte("a\n")); n != 0 || !errors.Is(err, artifact.ErrLimit) {
		t.Fatal(n, err)
	}
	if err = e.EndOrigin(coverage()); err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	_, f, err := decodeBytes(t, b.Bytes())
	if err != nil || f.SourceBytes != 0 {
		t.Fatal(err, f)
	}
}

type sourceFailure struct{ err error }

func (r sourceFailure) Read([]byte) (int, error) { return 0, r.err }
func TestLogCodecFullEOFCancelAndSourceErrorOverrideAnyProvisionalRows(t *testing.T) {
	native := encode(t, []byte("one\nsecond\n"))
	boom := errors.New("source failed")
	var visited int
	f, err := Walk(t.Context(), io.MultiReader(bytes.NewReader(native), sourceFailure{boom}), artifact.LogNativeLimit, Visitor{Fragment: func(artifact.LogFragment) error { visited++; return nil }})
	if !errors.Is(err, boom) || f != (artifact.LogFooter{}) || visited != 2 {
		t.Fatal("source EOF not authenticated by codec", err, f, visited)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f, err = Walk(ctx, bytes.NewReader(native), artifact.LogNativeLimit, Visitor{Coverage: func(artifact.LogCoverage) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || f != (artifact.LogFooter{}) {
		t.Fatal("cancel published footer", err, f)
	}
}

type countedReader struct {
	r       io.Reader
	bytes   int64
	maximum int
}

func (r *countedReader) Read(p []byte) (int, error) {
	if len(p) > r.maximum {
		r.maximum = len(p)
	}
	n, e := r.r.Read(p)
	r.bytes += int64(n)
	return n, e
}
func TestLogCodecMaximumNativeStreamDoesNotNeedFullArtifactBuffer(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		e, err := NewEncoder(t.Context(), writer, header(1), artifact.LogNativeLimit)
		if err == nil {
			err = e.BeginOrigin(origin(0))
		}
		payload := bytes.Repeat([]byte{'x'}, artifact.LogMaxFragmentBytes)
		for err == nil {
			_, err = e.Write(payload)
		}
		if errors.Is(err, artifact.ErrLimit) {
			err = e.EndOrigin(coverage())
			if err == nil {
				err = e.Close()
			}
		}
		_ = writer.CloseWithError(err)
		done <- err
	}()
	counted := &countedReader{r: reader}
	f, err := Walk(t.Context(), counted, artifact.LogNativeLimit, Visitor{})
	_ = reader.Close()
	producerErr := <-done
	if err != nil || producerErr != nil || counted.bytes > artifact.LogNativeLimit || counted.bytes < artifact.LogNativeLimit-16384 || counted.maximum > artifact.LogMaxLine+1 || f.SourceBytes < 40<<20 {
		t.Fatal("stream bound", err, producerErr, counted.bytes, counted.maximum, f)
	}
}
func TestLogCodecOriginAndCoverageAssociation(t *testing.T) {
	valid := encode(t, []byte("line\n"))
	for name, data := range map[string][]byte{"missingOrigin": mutate(t, valid, 1, func(v map[string]any) { v["origin_id"] = 1 }), "inventedStream": mutate(t, valid, 1, func(v map[string]any) { v["stream"] = "stdout" }), "coverageCount": mutate(t, valid, 3, func(v map[string]any) { v["fragments"] = 0 }), "unknownTimeNoGap": mutate(t, valid, 3, func(v map[string]any) { v["gaps"] = []string{} }), "missingNullable": mutate(t, valid, 1, func(v map[string]any) { delete(v, "runtime_id") }), "partialFetchPair": mutate(t, valid, 3, func(v map[string]any) { v["fetch_finished_at"] = nil })} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeBytes(t, data); err == nil {
				t.Fatal("invalid association accepted")
			}
		})
	}
}
