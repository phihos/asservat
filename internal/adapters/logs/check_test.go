package logs

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func streamFixture(t *testing.T) (artifact.ContextExpectation, time.Time, time.Time, []byte) {
	t.Helper()
	h := header(1)
	c := coverage()
	e := artifact.ContextExpectation{NativeType: artifact.LogsArtifact, DataClass: "raw", PodUID: h.PodUID, ActionID: "a0123456789abcdef01234567", TriggeredAt: h.WindowEnd, Logs: &artifact.LogCapture{ActionID: "a0123456789abcdef01234567", BeforeMillis: 3600000, TimeoutMillis: 10000, Streams: "combined", MaxNativeBytes: artifact.LogNativeLimit}, Registration: artifact.Registration{NativeLimit: artifact.LogNativeLimit}}
	return e, *c.FetchStartedAt, *c.FetchFinishedAt, encode(t, []byte("one\n\nlast"))
}
func runCheck(e artifact.ContextExpectation, from, until time.Time, native []byte, chunk int) error {
	c, err := NewCheck(e, from, until)
	if err != nil {
		return err
	}
	for len(native) > 0 {
		n := min(chunk, len(native))
		if err = c.Write(native[:n]); err != nil {
			return err
		}
		native = native[n:]
	}
	return c.Close()
}
func TestLogStreamCheckOneByteAndSplitBoundaries(t *testing.T) {
	e, from, until, native := streamFixture(t)
	for _, chunk := range []int{1, 2, 31, 4096, len(native)} {
		if err := runCheck(e, from, until, native, chunk); err != nil {
			t.Fatal(chunk, err)
		}
	}
	c, _ := NewCheck(e, from, until)
	if err := c.Write(native); err != nil {
		t.Fatal(err)
	}
	if c.Close() != nil || c.Close() != nil {
		t.Fatal("closed checker not stable")
	}
	if c.Write([]byte("{}\n")) == nil {
		t.Fatal("post-close record accepted")
	}
}
func TestLogStreamCheckExactAcceptedWindowPodAndFetchInterval(t *testing.T) {
	e, from, until, native := streamFixture(t)
	for name, mut := range map[string]func(map[string]any){"pod": func(v map[string]any) { v["pod_uid"] = "replacement" }, "windowStart": func(v map[string]any) { v["window_start"] = header(1).WindowStart.Add(-time.Nanosecond) }, "windowEnd": func(v map[string]any) { v["window_end"] = header(1).WindowEnd.Add(time.Nanosecond) }} {
		t.Run(name, func(t *testing.T) {
			if err := runCheck(e, from, until, mutate(t, native, 0, mut), 1); !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatal("unbound header", err)
			}
		})
	}
	for name, mut := range map[string]func(map[string]any){"beforeFetch": func(v map[string]any) { v["fetch_started_at"] = from.Add(-time.Nanosecond) }, "afterFetch": func(v map[string]any) { v["fetch_finished_at"] = until.Add(time.Nanosecond) }} {
		t.Run(name, func(t *testing.T) {
			if err := runCheck(e, from, until, mutate(t, native, 5, mut), 33); !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatal("fetch interval escaped manifest", err)
			}
		})
	}
	// A historical source timestamp legitimately precedes HTTP acquisition.
	var b bytes.Buffer
	enc, _ := NewEncoder(t.Context(), &b, header(1), artifact.LogNativeLimit)
	_ = enc.BeginOrigin(origin(0))
	stamp := "2026-11-05T00:30:00.000000037Z"
	_, err := enc.WriteLineFragment([]byte(stamp+" old message\n"), &stamp)
	if err != nil {
		t.Fatal(err)
	}
	_ = enc.EndOrigin(coverage())
	_ = enc.Close()
	if err = runCheck(e, from, until, b.Bytes(), 7); err != nil {
		t.Fatal("source timestamp incorrectly tied to acquisition", err)
	}
}
func TestLogStreamCheckRetainsExactNativeAcquisitionPrecision(t *testing.T) {
	e, from, until, native := streamFixture(t)
	from = from.Add(37 * time.Nanosecond)
	until = until.Add(73 * time.Nanosecond)
	native = mutate(t, native, 5, func(v map[string]any) { v["fetch_started_at"] = from; v["fetch_finished_at"] = until })
	if err := runCheck(e, from, until, native, 1); err != nil {
		t.Fatal("submicrosecond sealed interval rewritten", err)
	}
}
func TestLogStreamCheckRejectsUnterminatedCorruptAndOversizeTail(t *testing.T) {
	e, from, until, native := streamFixture(t)
	lines := bytes.Split(bytes.TrimSuffix(native, []byte{'\n'}), []byte{'\n'})
	for name, data := range map[string][]byte{"unterminated": native[:len(native)-1], "missingFooter": append(bytes.Join(lines[:len(lines)-1], []byte{'\n'}), '\n'), "extraRecord": append(append([]byte{}, native...), []byte("{}\n")...), "wrongFooterCount": mutate(t, native, 6, func(v map[string]any) { v["source_bytes"] = 999 }), "unknownRecord": mutate(t, native, 2, func(v map[string]any) { v["record"] = "payload" }), "oversizeLine": []byte(strings.Repeat(" ", artifact.LogMaxLine) + "\n")} {
		t.Run(name, func(t *testing.T) {
			c, err := NewCheck(e, from, until)
			if err != nil {
				t.Fatal(err)
			}
			err = c.Write(data)
			if err == nil {
				err = c.Close()
			}
			if err == nil {
				t.Fatal("corrupt stream accepted")
			}
			if c.Write(native) != err || c.Close() != err {
				t.Fatal("failure not terminal")
			}
			if len(c.line) != 0 {
				t.Fatal("failed pending bytes retained")
			}
		})
	}
}
func TestLogStreamCheckActionCapAndClosedNativeBranch(t *testing.T) {
	e, from, until, native := streamFixture(t)
	e.Logs.MaxNativeBytes = int64(len(native) - 1)
	e.Registration.NativeLimit = e.Logs.MaxNativeBytes
	if err := runCheck(e, from, until, native, 1); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal("action cap not enforced", err)
	}
	for _, change := range []func(*artifact.ContextExpectation){func(e *artifact.ContextExpectation) { e.NativeType = artifact.PodStatusArtifact }, func(e *artifact.ContextExpectation) { e.DataClass = "metadata" }, func(e *artifact.ContextExpectation) { e.Logs = nil }, func(e *artifact.ContextExpectation) { e.Logs.Streams = "stdout" }, func(e *artifact.ContextExpectation) { e.PodUID = "" }, func(e *artifact.ContextExpectation) { e.ActionID = "other" }, func(e *artifact.ContextExpectation) { e.Registration.NativeLimit-- }} {
		v := e
		v.Logs = e.Logs.Clone()
		change(&v)
		if _, err := NewCheck(v, from, until); err == nil {
			t.Fatal("invalid native/action branch accepted")
		}
	}
	if _, err := NewCheck(e, until, from); err == nil {
		t.Fatal("reversed manifest times")
	}
}
func TestLogStreamCheckSharesWalkStrictJSON(t *testing.T) {
	e, from, until, native := streamFixture(t)
	for name, data := range map[string][]byte{"duplicate": bytes.Replace(native, []byte(`"origins":1`), []byte(`"origins":1,"origins":1`), 1), "nullScalar": mutate(t, native, 2, func(v map[string]any) { v["line"] = nil }), "omittedNullable": mutate(t, native, 1, func(v map[string]any) { delete(v, "runtime_id") })} {
		t.Run(name, func(t *testing.T) {
			if runCheck(e, from, until, data, 1) == nil {
				t.Fatal("stream decoder weaker than Walk")
			}
			if _, err := Walk(t.Context(), bytes.NewReader(data), artifact.LogNativeLimit, Visitor{}); err == nil {
				t.Fatal("Walk weaker than stream decoder")
			}
		})
	}
	// The encoder emits all explicit nullable fields, so both checkers see the
	// same complete JSON object shape even when provenance is unknown.
	raw, _ := json.Marshal(origin(0))
	if !bytes.Contains(raw, []byte(`"runtime_id":null`)) {
		t.Fatal("nullable provenance omitted")
	}
}

func TestLogAcquiringCheckRequiresActualCloseAfterCompleteSource(t *testing.T) {
	e, from, until, native := streamFixture(t)
	e.Registration.AnchorAt = from.Add(-time.Minute)
	e.Registration.WriteUntil = until.Add(time.Minute)
	c, err := NewAcquiringCheck(e, from)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range native {
		if err = c.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err = c.CloseAt(until); err != nil {
		t.Fatal("actual completed end refused", err)
	}
	if c.Close() != nil || c.CloseAt(until) != nil {
		t.Fatal("exact completion not idempotent")
	}
	if c.CloseAt(until.Add(time.Nanosecond)) == nil {
		t.Fatal("completed end changed")
	}
	for _, mode := range []string{"missingEnd", "beforeFetch", "beforeStart", "zero", "writeEquality", "afterWrite", "missingFooter"} {
		t.Run(mode, func(t *testing.T) {
			c, err := NewAcquiringCheck(e, from)
			if err != nil {
				t.Fatal(err)
			}
			data := native
			if mode == "missingFooter" {
				data = native[:bytes.LastIndex(native[:len(native)-1], []byte{'\n'})+1]
			}
			if err = c.Write(data); err != nil {
				t.Fatal(err)
			}
			end := until
			switch mode {
			case "missingEnd":
				err = c.Close()
			case "beforeFetch":
				end = until.Add(-time.Nanosecond)
			case "beforeStart":
				end = from.Add(-time.Nanosecond)
			case "zero":
				end = time.Time{}
			case "writeEquality":
				end = e.Registration.WriteUntil
			case "afterWrite":
				end = e.Registration.WriteUntil.Add(time.Nanosecond)
			}
			if mode != "missingEnd" {
				err = c.CloseAt(end)
			}
			if err == nil {
				t.Fatal("unknown/inconsistent completion accepted")
			}
			if c.CloseAt(until) != err || c.Close() != err {
				t.Fatal("failed acquisition completion revived")
			}
		})
	}
}
func TestLogAcquiringCheckStillBindsOriginalSourceAndFetchStart(t *testing.T) {
	e, from, until, native := streamFixture(t)
	e.Registration.WriteUntil = until.Add(time.Minute)
	for name, data := range map[string][]byte{"pod": mutate(t, native, 0, func(v map[string]any) { v["pod_uid"] = "other" }), "earlyFetch": mutate(t, native, 5, func(v map[string]any) { v["fetch_started_at"] = from.Add(-time.Nanosecond) })} {
		t.Run(name, func(t *testing.T) {
			c, _ := NewAcquiringCheck(e, from)
			if err := c.Write(data); err == nil {
				t.Fatal("acquiring checker weaker than verification")
			}
		})
	}
	for _, change := range []func(*artifact.ContextExpectation){func(e *artifact.ContextExpectation) { e.Registration.WriteUntil = time.Time{} }, func(e *artifact.ContextExpectation) { e.Registration.WriteUntil = from }, func(e *artifact.ContextExpectation) { e.Registration.AnchorAt = from.Add(time.Nanosecond) }} {
		bad := e
		change(&bad)
		if _, err := NewAcquiringCheck(bad, from); err == nil {
			t.Fatal("original write/start bound absent")
		}
	}
	// Known-end verification continues to use ordinaryClose and refuses the
	// acquisition-only completion method; it never substitutes another end.
	check, err := NewCheck(e, from, until)
	if err != nil {
		t.Fatal(err)
	}
	if err = check.Write(native); err != nil {
		t.Fatal(err)
	}
	if check.Close() != nil {
		t.Fatal("known-end verification changed")
	}
}
