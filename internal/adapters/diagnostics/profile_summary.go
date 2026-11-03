package diagnostics

import (
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"

	analysis "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

const (
	MaxSummarySamples      = 100000
	MaxSummaryLocations    = 100000
	MaxSummaryFunctions    = 100000
	MaxSummarySampleFrames = 4096
	MaxSummaryFrameVisits  = 1 << 20
)

var ErrProfileSampleType = errors.New("profile sample type unavailable or ambiguous")

// SummarizePprof interprets bounded data only. It supplies no source authority,
// key capability or raw-read permission and never performs symbol lookup.
// The caller must own a cancellation-aware/deadline-bound reader. The library
// parser is synchronous: its post-parse table limits do not bound allocations
// already made, and context cancellation cannot interrupt that parser. ADR-286
// requires separate worker process/resource and eventual-join qualification.
func SummarizePprof(ctx context.Context, r io.Reader, selection analysis.ProfileSummarySelection) (out analysis.ProfileSummary, err error) {
	defer func() {
		if recover() != nil {
			out = analysis.ProfileSummary{}
			err = ErrNotProfile
		}
	}()
	if ctx == nil || r == nil || !selection.Valid() {
		return out, analysis.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	limited := &io.LimitedReader{R: summaryContextReader{ctx, r}, N: artifact.MaxPprofBytes + 1}
	p, err := parsePprof(limited, artifact.MaxPprofDecompressedBytes)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if limited.N == 0 {
		return out, artifact.ErrLimit
	}
	if err != nil {
		return out, err
	}
	return summarizePprof(ctx, p, selection)
}

type summaryContextReader struct {
	ctx   context.Context
	inner io.Reader
}

func (r summaryContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.inner.Read(p)
	if canceled := r.ctx.Err(); canceled != nil {
		clear(p[:n])
		return 0, canceled
	}
	return n, err
}

type summaryCount struct {
	name             string
	flat, cumulative int64
}

func summarizePprof(ctx context.Context, p *profile.Profile, s analysis.ProfileSummarySelection) (analysis.ProfileSummary, error) {
	var zero analysis.ProfileSummary
	if len(p.Sample) > MaxSummarySamples || len(p.Location) > MaxSummaryLocations || len(p.Function) > MaxSummaryFunctions {
		return zero, artifact.ErrLimit
	}
	sampleType := -1
	for i, t := range p.SampleType {
		if t.Type == s.SampleType {
			if sampleType >= 0 {
				return zero, ErrProfileSampleType
			}
			sampleType = i
		}
	}
	if sampleType < 0 {
		return zero, ErrProfileSampleType
	}
	if !analysis.ProfileSummaryText(p.SampleType[sampleType].Unit, 64) {
		return zero, ErrNotProfile
	}
	out := analysis.ProfileSummary{SampleType: s.SampleType, Unit: p.SampleType[sampleType].Unit, Top: make([]analysis.ProfileHotspot, 0, s.TopN), SymbolStatus: "missing"}
	if p.DurationNanos > 0 {
		seconds := float64(p.DurationNanos) / 1e9
		out.DurationSeconds = &seconds
	}
	counts := make(map[string]summaryCount)
	visits := 0
	named, missing, signed := false, false, false
	for _, sample := range p.Sample {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		v := sample.Value[sampleType]
		if !analysis.ProfileSummaryValue(v) || !addSummary(&out.Total, v) {
			return zero, artifact.ErrLimit
		}
		signed = signed || v < 0
		seen := make(map[string]bool)
		frames := 0
		addFrame := func(name string) error {
			frames++
			visits++
			if frames > MaxSummarySampleFrames || visits > MaxSummaryFrameVisits {
				return artifact.ErrLimit
			}
			if name == "" {
				missing = true
			} else {
				if !analysis.ProfileSummaryText(name, 512) {
					return artifact.ErrLimit
				}
				named = true
			}
			count := counts[name]
			count.name = name
			if frames == 1 && !addSummary(&count.flat, v) {
				return artifact.ErrLimit
			}
			if !seen[name] {
				if !addSummary(&count.cumulative, v) {
					return artifact.ErrLimit
				}
				seen[name] = true
			}
			counts[name] = count
			return nil
		}
		// Empty and stripped stacks remain explicitly unresolved, never named by
		// a raw address, file path, mapping name or a guessed runtime function.
		if len(sample.Location) == 0 {
			if err := addFrame(""); err != nil {
				return zero, err
			}
		}
		for _, location := range sample.Location {
			if err := ctx.Err(); err != nil {
				return zero, err
			}
			if len(location.Line) == 0 {
				if err := addFrame(""); err != nil {
					return zero, err
				}
			}
			// pprof locations and inline lines are ordered from leaf to caller.
			for _, line := range location.Line {
				if err := addFrame(line.Function.Name); err != nil {
					return zero, err
				}
			}
		}
	}
	if named {
		out.SymbolStatus = "complete"
		if missing {
			out.SymbolStatus = "partial"
		}
	}
	top := &summaryHeap{}
	for _, count := range counts {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if top.Len() < s.TopN {
			heap.Push(top, count)
		} else if summaryBefore(count, (*top)[0]) {
			(*top)[0] = count
			heap.Fix(top, 0)
		}
	}
	sort.Slice(*top, func(i, j int) bool { return summaryBefore((*top)[i], (*top)[j]) })
	for _, count := range *top {
		h := analysis.ProfileHotspot{Flat: count.flat, Cumulative: count.cumulative}
		if count.name != "" {
			name := count.name
			h.Function = &name
		}
		if !signed && out.Total > 0 {
			fraction := float64(count.flat) / float64(out.Total)
			h.Fraction = &fraction
		}
		out.Top = append(out.Top, h)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !out.Valid(s) {
		return zero, artifact.ErrLimit
	}
	encoded, err := json.Marshal(out)
	defer clear(encoded)
	if err != nil || len(encoded) > analysis.ProfileSummaryBytes {
		return zero, artifact.ErrLimit
	}
	return out, nil
}

// Every intermediate sum must remain an exactly representable JSON integer.
func addSummary(dst *int64, v int64) bool {
	n := *dst + v // both operands are already bounded to +/- (2^53-1).
	if !analysis.ProfileSummaryValue(n) {
		return false
	}
	*dst = n
	return true
}
func summaryAbs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
func summaryBefore(a, b summaryCount) bool {
	if x, y := summaryAbs(a.cumulative), summaryAbs(b.cumulative); x != y {
		return x > y
	}
	if x, y := summaryAbs(a.flat), summaryAbs(b.flat); x != y {
		return x > y
	}
	return a.name < b.name
}

// Keep the worst retained row at the root: aggregation never materializes an
// unbounded sorted copy of the function table just to return at most100 rows.
type summaryHeap []summaryCount

func (h summaryHeap) Len() int           { return len(h) }
func (h summaryHeap) Less(i, j int) bool { return summaryBefore(h[j], h[i]) }
func (h summaryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *summaryHeap) Push(v any)        { *h = append(*h, v.(summaryCount)) }
func (h *summaryHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }
