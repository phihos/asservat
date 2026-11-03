package syscalls

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"sort"
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

const maxMetadataLine = 16 << 10

// SummarizeMetadata parses the existing metadata-only native JSONL, reusing its
// closed event DTO and strict decoder. The owner supplies an authenticated,
// cancellation-aware reader and independently accepted Pod/window facts. It must
// check final whole-file authentication before releasing this result. No raw
// argument format or external symbol/name lookup is accepted here.
func SummarizeMetadata(ctx context.Context, source io.Reader, pod string, from, until time.Time) (analysis.SyscallAggregation, error) {
	var zero analysis.SyscallAggregation
	if ctx == nil || source == nil || pod == "" || from.IsZero() || until.Before(from) {
		return zero, artifact.ErrInvalid
	}
	limited := &io.LimitedReader{R: source, N: artifact.RecordingNativeLimit + 1}
	reader := bufio.NewReaderSize(limited, maxMetadataLine+1)
	counts := map[string]analysis.SyscallCount{}
	var unmatched, unfinished, unknown uint64
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		line, err := reader.ReadSlice('\n')
		if canceled := ctx.Err(); canceled != nil {
			return zero, canceled
		}
		if limited.N == 0 {
			return zero, artifact.ErrLimit
		}
		if err == io.EOF && len(line) == 0 {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxMetadataLine+1 {
			return zero, artifact.ErrLimit
		}
		if err != nil {
			return zero, err
		}
		var e event
		if decodeMetadataSummaryEvent(line, &e) != nil || !validSummaryEvent(e, pod, from, until) {
			return zero, artifact.ErrInvalid
		}
		c := counts[e.Syscall]
		c.Syscall = e.Syscall
		c.Count++
		if e.Outcome == "error" {
			c.Errors++
		}
		if e.DurationNS != nil {
			if c.TotalDurationNS > maxDuration-*e.DurationNS {
				return zero, artifact.ErrLimit
			}
			c.PairedCount++
			c.TotalDurationNS += *e.DurationNS
		}
		switch e.Outcome {
		case "unmatched":
			unmatched++
		case "unfinished":
			unfinished++
		case "unknown":
			unknown++
		}
		counts[e.Syscall] = c
	}
	out := analysis.SyscallAggregation{Rows: make([]analysis.SyscallCount, 0, len(counts)), UnmatchedEvents: unmatched, UnfinishedEvents: unfinished, UnknownEvents: unknown}
	for _, c := range counts {
		out.Rows = append(out.Rows, c)
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].Syscall < out.Rows[j].Syscall })
	return out, nil
}

func validSummaryEvent(e event, pod string, from, until time.Time) bool {
	bounded := func(s string, n int) bool {
		return utf8.ValidString(s) && utf8.RuneCountInString(s) > 0 && utf8.RuneCountInString(s) <= n
	}
	if e.Identity.PodUID != pod || !bounded(e.Identity.PodUID, 64) || !bounded(e.Identity.ProcessRef, 128) || !bounded(e.Identity.ThreadRef, 128) || !bounded(e.Syscall, 64) || !bounded(e.ABI, 32) {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil || at.Before(from) || at.After(until) || e.DurationNS != nil && *e.DurationNS > maxDuration {
		return false
	}
	switch e.Outcome {
	case "success":
		return e.Errno == "" || bounded(e.Errno, 32)
	case "error":
		return bounded(e.Errno, 32)
	case "unfinished", "unmatched", "unknown":
		return e.DurationNS == nil && e.Errno == ""
	}
	return false
}

// jsontext rejects duplicate members and malformed UTF-8. No field in the
// native metadata event accepts JSON null (including optional fields).
func decodeMetadataSummaryEvent(line []byte, out *event) error {
	tokens := jsontext.NewDecoder(bytes.NewReader(line))
	for {
		token, err := tokens.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil || token.Kind() == 'n' {
			return artifact.ErrInvalid
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return artifact.ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return artifact.ErrInvalid
	}
	return nil
}
