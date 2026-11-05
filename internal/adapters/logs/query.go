package logs

import (
	"context"
	"encoding/base64"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// QueryLogs selects exact saved byte fragments. Walk validates the complete
// native tail even after a page or cursor stops selecting. The caller must also
// finalize authenticated framing and current authority before disclosure.
func QueryLogs(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time, s analysis.LogSelection, version artifact.Digest) (analysis.ProjectionResult, error) {
	var zero analysis.ProjectionResult
	if ctx == nil || source == nil || !s.Valid() || e.NativeType != artifact.LogsArtifact || e.DataClass != "raw" || !e.Logs.Valid() || e.ActionID != e.Logs.ActionID || e.Registration.NativeLimit != e.Logs.MaxNativeBytes || e.PodUID == "" || from.IsZero() || until.Before(from) {
		return zero, analysis.ErrInvalid
	}
	start, end, err := e.Logs.Window(e.TriggeredAt)
	if err != nil {
		return zero, err
	}
	page := analysis.LogPage{Version: version, PodUID: e.PodUID, WindowStart: start, WindowEnd: end, StartFragment: s.Fragment, StartOffset: s.Offset, Entries: make([]analysis.LogEntry, 0, s.Limit)}
	invalidCursor := !s.Matches(version)
	var origin artifact.LogOrigin
	var fragment, nextFragment uint64
	var nextOffset uint16
	used, full := 2048, false // Bounded page metadata/counters, independently encoded below.
	footer, err := Walk(ctx, source, e.Logs.MaxNativeBytes, Visitor{
		Header: func(h artifact.LogHeader) error {
			if h.PodUID != e.PodUID || !h.WindowStart.Equal(start) || !h.WindowEnd.Equal(end) {
				return artifact.ErrInvalid
			}
			page.OriginCount = h.Origins
			return nil
		},
		Origin: func(o artifact.LogOrigin) error { origin = o; return nil },
		Fragment: func(f artifact.LogFragment) error {
			index := fragment
			fragment++
			raw, err := f.Bytes()
			if err != nil {
				return err
			}
			defer clear(raw)
			if index < s.Fragment || full || invalidCursor {
				return nil
			}
			offset := 0
			if index == s.Fragment {
				offset = int(s.Offset)
				if offset >= len(raw) {
					invalidCursor = true
					return nil
				}
			}
			for offset < len(raw) {
				if len(page.Entries) >= s.Limit {
					full = true
					break
				}
				stop := min(offset+analysis.LogPageFragmentBytes, len(raw))
				row := analysis.LogEntry{Origin: origin, Fragment: index, Line: f.Line, Offset: f.Offset + uint64(offset), LineOffset: f.LineOffset + uint64(offset), Continuation: f.LineOffset+uint64(offset) > 0, EndLine: f.EndLine && stop == len(raw), SourceTime: f.SourceTime, Data: base64.StdEncoding.EncodeToString(raw[offset:stop])}
				n := row.EncodedUpperBound() + 1
				if used+n > analysis.LogQueryPageBytes {
					full = true
					break
				}
				used += n
				page.Entries = append(page.Entries, row)
				offset = stop
				nextFragment, nextOffset = index, uint16(offset)
				if offset == len(raw) {
					nextFragment, nextOffset = index+1, 0
				}
			}
			return nil
		},
		Coverage: func(c artifact.LogCoverage) error {
			if c.FetchStartedAt != nil && (c.FetchStartedAt.Before(from) || c.FetchFinishedAt.After(until)) {
				return artifact.ErrIntegrity
			}
			switch c.FetchOutcome {
			case "complete":
				page.CompleteOrigins++
			case "partial":
				page.PartialOrigins++
			case "unavailable":
				page.UnavailableOrigins++
			}
			if len(c.Gaps) > 0 {
				page.GappedOrigins++
			}
			if hasGap(c, "timestampUnknown") {
				page.UnknownTimestampOrigins++
			}
			return nil
		},
	})
	if err != nil {
		page.Clear()
		return zero, err
	}
	if invalidCursor || s.Fragment > 0 && s.Fragment >= footer.Fragments || footer.Fragments == 0 && s.Offset > 0 {
		page.Clear()
		return zero, analysis.ErrInvalidCursor
	}
	page.TotalFragments, page.SourceBytes = footer.Fragments, footer.SourceBytes
	if footer.Fragments > 0 && len(page.Entries) == 0 {
		page.Clear()
		return zero, analysis.ErrRecordTooLarge
	}
	if nextFragment < footer.Fragments {
		page.HasNext, page.NextFragment, page.NextOffset = true, nextFragment, nextOffset
	}
	if ctx.Err() != nil {
		page.Clear()
		return zero, ctx.Err()
	}
	if !page.ValidShape(s, version, e.PodUID) {
		page.Clear()
		return zero, analysis.ErrUnavailable
	}
	return analysis.ProjectionResult{Logs: &page}, nil
}
