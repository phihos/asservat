package diagnostics

import (
	"context"

	analysis "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

// pprofAggregation retains approved function aggregates only. The native object
// graph can become unreachable before a second profile is parsed. This does not
// promise immediate garbage collection or establish a physical memory bound.
type pprofAggregation struct {
	summary analysis.ProfileSummary
	counts  map[string]summaryCount
	signed  bool
}

func aggregatePprof(ctx context.Context, p *profile.Profile, sampleTypeName string) (pprofAggregation, error) {
	var zero pprofAggregation
	if len(p.Sample) > MaxSummarySamples || len(p.Location) > MaxSummaryLocations || len(p.Function) > MaxSummaryFunctions {
		return zero, artifact.ErrLimit
	}
	sampleType := -1
	for i, t := range p.SampleType {
		if t.Type == sampleTypeName {
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
	out := analysis.ProfileSummary{SampleType: sampleTypeName, Unit: p.SampleType[sampleType].Unit, SymbolStatus: "missing"}
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
	return pprofAggregation{summary: out, counts: counts, signed: signed}, nil
}
