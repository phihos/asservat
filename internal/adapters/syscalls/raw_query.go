package syscalls

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// QuerySyscallArguments selects whole recorded events, without formatting or
// dereferencing their argument values. The caller independently authenticates
// complete framing/native EOF and current grant authority before disclosure.
func QuerySyscallArguments(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time, s analysis.SyscallSelection, version artifact.Digest) (analysis.ProjectionResult, error) {
	var zero analysis.ProjectionResult
	if ctx == nil || source == nil || !s.Valid() || s.View != analysis.SyscallQueryView || e.NativeType != artifact.SyscallArgumentsArtifact || e.PodUID == "" || from.IsZero() || until.Before(from) {
		return zero, analysis.ErrInvalid
	}
	if !s.Matches(version) {
		return zero, analysis.ErrInvalidCursor
	}
	page := analysis.SyscallArgumentPage{Version: version, Start: s.Start, Events: make([]artifact.RawArgumentEvent, 0, s.Limit)}
	full := false
	// Reserve the bounded fixed page fields; individual events use their exact
	// Go JSON encoding, including escaping. Never split an event or an argument.
	used := 512
	counts, err := walkArgumentRecords(ctx, source, e, from, until, func(event artifact.RawArgumentEvent) error {
		if !s.Includes(event.Syscall, event.Outcome) {
			return nil
		}
		if page.TotalMatching >= s.Start && len(page.Events) < s.Limit && !full {
			encoded, err := json.Marshal(event)
			if err != nil {
				return artifact.ErrInvalid
			}
			n := len(encoded) + 1
			clear(encoded)
			if used+n > analysis.SyscallQueryPageBytes {
				full = true
			} else {
				used += n
				page.Events = append(page.Events, event)
			}
		}
		page.TotalMatching++
		return nil
	})
	if err != nil {
		page.Clear()
		return zero, err
	}
	page.SyscallRecordCounts = counts
	if s.Start > 0 && s.Start >= page.TotalMatching {
		page.Clear()
		return zero, analysis.ErrInvalidCursor
	}
	if page.TotalMatching > page.Start && len(page.Events) == 0 {
		page.Clear()
		return zero, analysis.ErrRecordTooLarge
	}
	encoded, err := json.Marshal(page)
	n := len(encoded)
	clear(encoded)
	if err != nil || n > analysis.SyscallQueryPageBytes || !page.Valid(s, version, e.PodUID, from, until) {
		page.Clear()
		return zero, analysis.ErrUnavailable
	}
	return analysis.ProjectionResult{SyscallQuery: &page}, nil
}
