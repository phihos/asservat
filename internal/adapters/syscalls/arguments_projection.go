package syscalls

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// walkArgumentMetadata validates the entire bounded raw recording and passes
// only explicitly copied metadata to its visitor. Original publication source
// proof is not reconstructed from this file: the caller independently verifies
// the published source's authenticated manifest and canonical NativeCheck.
func walkArgumentMetadata(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time, visit func(event) error) (analysis.SyscallRecordCounts, error) {
	var zero, counts analysis.SyscallRecordCounts
	if e.Recording == nil || e.Recording.Arguments == nil || e.Recording.Syscalls == nil || e.Recording.MaxBytes < 1 || e.Recording.MaxBytes > artifact.RecordingNativeLimit || e.Recording.Syscalls.MaxEvents < 1 || e.Recording.Syscalls.MaxEvents > analysis.SyscallMaxRecords {
		return zero, artifact.ErrInvalid
	}
	a := e.Recording.Arguments
	definitions, err := ArgumentDefinitions(e.Recording.Syscalls.Names, a.CaptureBuffers, int(a.MaxBytesPerEvent))
	if err != nil || artifact.Digest(ArgumentDefinitionDigest(definitions)) != a.DefinitionDigest || int64(ArgumentMaxProbeBytes(definitions)) != a.MaxProbeBytes {
		return zero, artifact.ErrInvalid
	}
	check := &argumentsCheck{e: e, from: from, until: until, projection: true, definitions: definitions, visit: func(e event) error {
		counts.RecordCount++
		switch e.Outcome {
		case "unmatched":
			counts.UnmatchedEvents++
		case "unfinished":
			counts.UnfinishedEvents++
		}
		return visit(e)
	}}
	defer func() { clear(check.line) }()
	limited := &io.LimitedReader{R: source, N: e.Recording.MaxBytes + 1}
	reader := bufio.NewReaderSize(limited, MaxArgumentLine+2)
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		line, err := reader.ReadSlice('\n')
		if canceled := ctx.Err(); canceled != nil {
			clear(line)
			return zero, canceled
		}
		if limited.N == 0 || len(line) > MaxArgumentLine+1 {
			clear(line)
			return zero, artifact.ErrLimit
		}
		if err == io.EOF && len(line) == 0 {
			if err := check.Close(); err != nil {
				return zero, err
			}
			return counts, nil
		}
		if err != nil {
			clear(line)
			return zero, err
		}
		err = check.Write(line)
		clear(line)
		if err != nil {
			return zero, err
		}
	}
}

// Null is not interchangeable with an event/header field. Only the two
// optional footer observation counters may explicitly be null. The regular
// argument decoder separately checks closed DTO shape and duplicate fields.
func projectionArgumentNulls(line []byte, record string) bool {
	if record != "footer" {
		return projectionNonNullJSON(line)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(line, &fields) != nil {
		return false
	}
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && name != "observed_events" && name != "observed_bytes" {
			return false
		}
	}
	return true
}
