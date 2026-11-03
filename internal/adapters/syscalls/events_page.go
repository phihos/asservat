package syscalls

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// ReadMetadataPage consumes the complete authenticated source even after the
// selected page fills. A malformed tail, cancellation or source error returns
// no partial page. The owner must still check final whole-file authentication.
func ReadMetadataPage(ctx context.Context, source io.Reader, pod string, from, until time.Time, s analysis.SyscallSelection, version artifact.Digest) (analysis.SyscallEventPage, error) {
	var zero analysis.SyscallEventPage
	if !s.Valid() || s.View != analysis.SyscallEventsView {
		return zero, analysis.ErrInvalid
	}
	if !s.Matches(version) {
		return zero, analysis.ErrInvalidCursor
	}
	out := analysis.SyscallEventPage{Version: version, Start: s.Start, Events: make([]artifact.SyscallMetadataEvent, 0, s.Limit)}
	used, full := 1024, false // bounded fixed page metadata, separate from event bytes
	stats, err := walkMetadata(ctx, source, pod, from, until, func(e event) error {
		if !s.Includes(e.Syscall, e.Outcome) {
			return nil
		}
		if out.TotalMatching >= s.Start && len(out.Events) < s.Limit && !full {
			encoded, err := json.Marshal(e)
			if err != nil {
				return artifact.ErrInvalid
			}
			if used+len(encoded)+1 > analysis.ContextResultBytes {
				full = true
			} else {
				used += len(encoded) + 1
				out.Events = append(out.Events, e)
			}
		}
		out.TotalMatching++
		return nil
	})
	if err != nil {
		return zero, err
	}
	out.SyscallRecordCounts = stats
	if s.Start > 0 && s.Start >= out.TotalMatching {
		return zero, analysis.ErrInvalidCursor
	}
	encoded, encodeErr := json.Marshal(out)
	if encodeErr != nil || len(encoded) > analysis.ContextResultBytes {
		return zero, artifact.ErrLimit
	}
	if !out.Valid(s, version, pod, from, until) {
		return zero, analysis.ErrUnavailable
	}
	return out, nil
}
