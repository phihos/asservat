package syscalls

import (
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func summaryNative(t *testing.T) ([]byte, time.Time) {
	t.Helper()
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	var data []byte
	for _, c := range []Call{{Status: Returned, Number: 1, PID: 7, EnteredBoot: 1, ExitedBoot: 5}, {Status: Returned, Number: 1, PID: 7, EnteredBoot: 3, ExitedBoot: 9, Ret: -2}, {Status: Unmatched, Number: 0, PID: 7}, {Status: Unfinished, Number: 0, PID: 7}, {Status: NoReturn, Number: 0, PID: 7}} {
		var err error
		data, err = AppendEvent(data, c, at, "pod", "epoch")
		if err != nil {
			t.Fatal(err)
		}
	}
	return data, at
}

func TestMetadataSummaryConsumesActualNativeEncoder(t *testing.T) {
	data, at := summaryNative(t)
	got, err := SummarizeMetadata(context.Background(), bytes.NewReader(data), "pod", at, at)
	if err != nil || len(got.Rows) != 2 || got.UnmatchedEvents != 1 || got.UnfinishedEvents != 1 || got.UnknownEvents != 1 {
		t.Fatal(got, err)
	}
	if got.Rows[0].Syscall != "read" || got.Rows[0].Count != 3 || got.Rows[0].PairedCount != 0 || got.Rows[1].Syscall != "write" || got.Rows[1].Count != 2 || got.Rows[1].Errors != 1 || got.Rows[1].PairedCount != 2 || got.Rows[1].TotalDurationNS != 10 {
		t.Fatal(got)
	}
}

func TestMetadataSummaryRefusesMalformedAndArgumentInput(t *testing.T) {
	data, at := summaryNative(t)
	line := bytes.Split(data, []byte("\n"))[0]
	for _, change := range []string{"arguments", "null-duration", "null-errno", "wrong-pod", "outside-window", "outcome", "duration-overflow", "duplicate", "partial"} {
		t.Run(change, func(t *testing.T) {
			var e map[string]any
			if json.Unmarshal(line, &e) != nil {
				t.Fatal("fixture")
			}
			switch change {
			case "arguments":
				e["arguments"] = []any{"secret-buffer"}
			case "null-duration":
				e["duration_ns"] = nil
			case "null-errno":
				e["errno"] = nil
			case "wrong-pod":
				e["identity"].(map[string]any)["pod_uid"] = "other"
			case "outside-window":
				e["timestamp"] = at.Add(time.Second).Format(time.RFC3339Nano)
			case "outcome":
				e["outcome"] = "unfinished"
			case "duration-overflow":
				e["duration_ns"] = uint64(1) << 53
			}
			input, _ := json.Marshal(e)
			input = append(input, '\n')
			if change == "duplicate" {
				input = append([]byte(`{"syscall":"secret",`), line[1:]...)
				input = append(input, '\n')
			}
			if change == "partial" {
				input = input[:len(input)-1]
			}
			got, err := SummarizeMetadata(context.Background(), bytes.NewReader(input), "pod", at, at)
			if err == nil || len(got.Rows) != 0 {
				t.Fatal("invalid metadata returned an aggregate", got, err)
			}
		})
	}
}

type summaryErrorReader struct{ data []byte }

func (r *summaryErrorReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, io.ErrUnexpectedEOF
}
func TestMetadataSummaryRejectsIncompleteSourceAndLimits(t *testing.T) {
	data, at := summaryNative(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SummarizeMetadata(ctx, bytes.NewReader(data), "pod", at, at); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got, err := SummarizeMetadata(context.Background(), &summaryErrorReader{data: data}, "pod", at, at); err == nil || len(got.Rows) != 0 {
		t.Fatal(got, err)
	}
	if _, err := SummarizeMetadata(context.Background(), strings.NewReader(strings.Repeat("x", maxMetadataLine+2)), "pod", at, at); err == nil {
		t.Fatal("unbounded line")
	}
	// Two individually valid durations cannot overflow the canonical safe integer.
	line := bytes.Split(data, []byte("\n"))[0]
	line = bytes.ReplaceAll(line, []byte(`"duration_ns":4`), []byte(`"duration_ns":9007199254740991`))
	overflow := append(append(append([]byte{}, line...), '\n'), line...)
	overflow = append(overflow, '\n')
	if _, err := SummarizeMetadata(context.Background(), bytes.NewReader(overflow), "pod", at, at); err == nil {
		t.Fatal("aggregate overflow")
	}
}

func BenchmarkMetadataSummary(b *testing.B) {
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	for _, distinct := range []bool{false, true} {
		name := "repeated"
		if distinct {
			name = "distinct"
		}
		b.Run(name, func(b *testing.B) {
			var data []byte
			for i := 0; ; i++ {
				e := event{Identity: identity{ProcessRef: "pid:7@epoch", ThreadRef: "pid:7@epoch", PodUID: "pod"}, Syscall: "write", ABI: ABI, Timestamp: at.Format(time.RFC3339Nano), Outcome: "success"}
				if distinct {
					e.Syscall = fmt.Sprintf("syscall_%x", i)
				}
				line, _ := json.Marshal(e)
				if len(data)+len(line)+1 > int(artifact.RecordingNativeLimit) {
					break
				}
				data = append(data, line...)
				data = append(data, '\n')
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := SummarizeMetadata(context.Background(), bytes.NewReader(data), "pod", at, at); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
