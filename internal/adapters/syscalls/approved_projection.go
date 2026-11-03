package syscalls

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// ProjectSyscalls extracts only the fixed metadata fields. The caller must
// independently authenticate the complete native stream and run its canonical
// manifest NativeCheck before releasing a result. This parser grants no source
// or disclosure authority and cannot replace original publication verification.
func ProjectSyscalls(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time, s analysis.SyscallSelection, version artifact.Digest) (analysis.ProjectionResult, error) {
	var zero analysis.ProjectionResult
	if !s.Valid() || ctx == nil || source == nil || e.PodUID == "" || from.IsZero() || until.Before(from) {
		return zero, analysis.ErrInvalid
	}
	if !s.Matches(version) {
		return zero, analysis.ErrInvalidCursor
	}
	var walk metadataWalk
	switch e.NativeType {
	case artifact.SyscallRecordsArtifact:
		walk = func(visit func(event) error) (analysis.SyscallRecordCounts, error) {
			return walkMetadata(ctx, source, e.PodUID, from, until, visit)
		}
	case artifact.SyscallArgumentsArtifact:
		walk = func(visit func(event) error) (analysis.SyscallRecordCounts, error) {
			return walkArgumentMetadata(ctx, source, e, from, until, visit)
		}
	default:
		return zero, analysis.ErrInvalid
	}
	if s.View == analysis.SyscallEventsView {
		page, err := readEventPage(walk, e.PodUID, from, until, s, version)
		if err != nil {
			return zero, err
		}
		return analysis.ProjectionResult{SyscallEvents: &page}, nil
	}
	aggregate, err := summarizeEvents(walk)
	if err != nil {
		return zero, err
	}
	if s.Start > 0 && s.Start >= len(aggregate.Rows) {
		return zero, analysis.ErrInvalidCursor
	}
	page := analysis.SyscallSummaryPage{Version: version, Start: s.Start, Total: len(aggregate.Rows), Rows: make([]analysis.SyscallCount, 0, s.Limit), SyscallRecordCounts: aggregate.SyscallRecordCounts}
	used := 1024 // fixed page metadata; rows are an exact encoded prefix
	for _, row := range aggregate.Rows[s.Start:] {
		encoded, err := json.Marshal(row)
		if err != nil {
			return zero, artifact.ErrInvalid
		}
		if len(page.Rows) == s.Limit || used+len(encoded)+1 > analysis.ContextResultBytes {
			break
		}
		used += len(encoded) + 1
		page.Rows = append(page.Rows, row)
	}
	encoded, err := json.Marshal(page)
	if err != nil || len(encoded) > analysis.ContextResultBytes || !page.Valid(s, version) {
		return zero, analysis.ErrUnavailable
	}
	return analysis.ProjectionResult{SyscallSummary: &page}, nil
}
