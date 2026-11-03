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
	return summarizeEvents(func(visit func(event) error) (analysis.SyscallRecordCounts, error) {
		return walkMetadata(ctx, source, pod, from, until, visit)
	})
}

type metadataWalk func(func(event) error) (analysis.SyscallRecordCounts, error)

func summarizeEvents(walk metadataWalk) (analysis.SyscallAggregation, error) {
	var zero analysis.SyscallAggregation
	counts := map[string]analysis.SyscallCount{}
	stats, err := walk(func(e event) error {
		c := counts[e.Syscall]
		c.Syscall = e.Syscall
		c.Count++
		if e.Outcome == "error" {
			c.Errors++
		}
		if e.DurationNS != nil {
			if c.TotalDurationNS > maxDuration-*e.DurationNS {
				return artifact.ErrLimit
			}
			c.PairedCount++
			c.TotalDurationNS += *e.DurationNS
		}
		counts[e.Syscall] = c
		return nil
	})
	if err != nil {
		return zero, err
	}
	out := analysis.SyscallAggregation{Rows: make([]analysis.SyscallCount, 0, len(counts)), SyscallRecordCounts: stats}
	for _, c := range counts {
		out.Rows = append(out.Rows, c)
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].Syscall < out.Rows[j].Syscall })
	return out, nil
}

func walkMetadata(ctx context.Context, source io.Reader, pod string, from, until time.Time, visit func(event) error) (analysis.SyscallRecordCounts, error) {
	var zero, stats analysis.SyscallRecordCounts
	if ctx == nil || source == nil || pod == "" || from.IsZero() || until.Before(from) || visit == nil {
		return zero, artifact.ErrInvalid
	}
	limited := &io.LimitedReader{R: source, N: artifact.RecordingNativeLimit + 1}
	reader := bufio.NewReaderSize(limited, maxMetadataLine+1)
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
			return stats, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxMetadataLine+1 {
			return zero, artifact.ErrLimit
		}
		if err != nil {
			return zero, err
		}
		var e event
		if decodeMetadataSummaryEvent(line, &e) != nil || !e.Valid(pod, from, until) {
			return zero, artifact.ErrInvalid
		}
		stats.RecordCount++
		switch e.Outcome {
		case "unmatched":
			stats.UnmatchedEvents++
		case "unfinished":
			stats.UnfinishedEvents++
		case "unknown":
			stats.UnknownEvents++
		}
		if err = visit(e); err != nil {
			return zero, err
		}
	}
}

// jsontext rejects duplicate members and malformed UTF-8. No field in the
// native metadata event accepts JSON null (including optional fields).
func decodeMetadataSummaryEvent(line []byte, out *event) error {
	if !projectionNonNullJSON(line) {
		return artifact.ErrInvalid
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

func projectionNonNullJSON(line []byte) bool {
	tokens := jsontext.NewDecoder(bytes.NewReader(line))
	for {
		token, err := tokens.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil || token.Kind() == 'n' {
			return false
		}
	}
	return true
}
