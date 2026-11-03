package diagnostics

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"slices"
	"sort"
	"strings"

	analysis "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

type comparisonAggregate struct {
	pprofAggregation
	facts      analysis.ProfileComparisonFacts
	build      [32]byte
	buildKnown bool
	// Keep exact native nanoseconds privately. The displayed seconds are rounded
	// metadata and must never become the arithmetic denominator.
	durationNanos int64
}

// ComparePprof consumes both bounded native files sequentially, aggregates all
// selected function values, then selects top-N differences. Subtracting already
// truncated summaries would incorrectly treat omitted functions as zero.
// Acquisition facts are independent inputs, never reconstructed authority.
// The source owner must authenticate both complete files before disclosure and
// close their keys/readers; this parser neither opens nor closes a source.
func ComparePprof(ctx context.Context, baseline io.Reader, baselineFacts analysis.ProfileComparisonAcquisition, incident io.Reader, incidentFacts analysis.ProfileComparisonAcquisition, s analysis.ProfileComparisonSelection) (out analysis.ProfileComparison, err error) {
	defer func() {
		if recover() != nil {
			out = analysis.ProfileComparison{}
			err = ErrNotProfile
		}
	}()
	if ctx == nil || baseline == nil || incident == nil || !s.Valid() || !baselineFacts.Valid() || !incidentFacts.Valid() {
		return out, analysis.ErrInvalid
	}
	b, err := readComparisonAggregate(ctx, baseline, baselineFacts, s.SampleType)
	if err != nil {
		return out, err
	}
	i, err := readComparisonAggregate(ctx, incident, incidentFacts, s.SampleType)
	if err != nil {
		return out, err
	}
	return compareAggregates(ctx, b, i, s)
}

func readComparisonAggregate(ctx context.Context, r io.Reader, acquisition analysis.ProfileComparisonAcquisition, sample string) (comparisonAggregate, error) {
	var zero comparisonAggregate
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	limited := &io.LimitedReader{R: summaryContextReader{ctx, r}, N: artifact.MaxPprofBytes + 1}
	p, err := parsePprof(limited, artifact.MaxPprofDecompressedBytes)
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if limited.N == 0 {
		return zero, artifact.ErrLimit
	}
	if err != nil {
		return zero, err
	}
	a, err := aggregatePprof(ctx, p, sample)
	if err != nil {
		return zero, err
	}
	f := analysis.ProfileComparisonFacts{ProfileComparisonAcquisition: acquisition, DurationSeconds: a.summary.DurationSeconds, Total: a.summary.Total, SymbolStatus: a.summary.SymbolStatus}
	if p.PeriodType != nil && p.Period > 0 {
		f.Period = &analysis.ProfileComparisonPeriod{Type: p.PeriodType.Type, Unit: p.PeriodType.Unit, Value: p.Period}
	}
	if !f.Valid() {
		return zero, artifact.ErrLimit
	}
	build, known, err := comparisonBuild(ctx, p)
	if err != nil {
		return zero, err
	}
	return comparisonAggregate{pprofAggregation: a, facts: f, build: build, buildKnown: known, durationNanos: p.DurationNanos}, nil
}

// Build IDs may contain arbitrary user data. Only a bounded internal set of
// digests survives parsing; no raw build/mapping string enters the extract.
// Optional build hashing consumes at most the native decompression byte ceiling,
// including digest framing. Repeated string-table references spend that budget
// repeatedly; exhaustion leaves build identity unknown rather than refusing an
// otherwise valid aggregate. Cancellation is checked within each 64 KiB read.
func comparisonBuild(ctx context.Context, p *profile.Profile) ([32]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, false, err
	}
	if len(p.Mapping) == 0 {
		return [32]byte{}, false, nil
	}
	remaining := int64(artifact.MaxPprofDecompressedBytes)
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	set := make(map[[32]byte]bool, len(p.Mapping))
	for _, m := range p.Mapping {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, false, err
		}
		if m.BuildID == "" || int64(len(m.BuildID)) > remaining-sha256.Size {
			return [32]byte{}, false, nil
		}
		remaining -= int64(len(m.BuildID)) + sha256.Size
		h := sha256.New()
		if _, err := io.CopyBuffer(h, summaryContextReader{ctx, strings.NewReader(m.BuildID)}, buffer); err != nil {
			return [32]byte{}, false, err
		}
		var id [32]byte
		copy(id[:], h.Sum(nil))
		set[id] = true
	}
	ids := make([][32]byte, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	h := sha256.New()
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, false, err
		}
		_, _ = h.Write(id[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, true, nil
}

func comparisonWindow(mode string) bool { return mode == "interval" || mode == "delta" }

func compareAggregates(ctx context.Context, b, i comparisonAggregate, s analysis.ProfileComparisonSelection) (analysis.ProfileComparison, error) {
	var zero analysis.ProfileComparison
	if b.summary.Unit != i.summary.Unit || !analysis.ProfileComparisonAcquisitionsCompatible(b.facts.ProfileComparisonAcquisition, i.facts.ProfileComparisonAcquisition) {
		return zero, analysis.ErrProfileIncompatible
	}
	var rates *comparisonRateArithmetic
	if s.Normalization == analysis.ProfileComparisonRate {
		if !comparisonWindow(b.facts.Mode) || !comparisonWindow(i.facts.Mode) || b.facts.DurationSeconds == nil || i.facts.DurationSeconds == nil || b.durationNanos <= 0 || i.durationNanos <= 0 {
			return zero, analysis.ErrProfileIncompatible
		}
		rates = newComparisonRateArithmetic(b.durationNanos, i.durationNanos)
	}
	out := analysis.ProfileComparison{SampleType: s.SampleType, Unit: b.summary.Unit, Normalization: s.Normalization, Aggregation: "cumulative", Comparable: true, Baseline: b.facts, Incident: i.facts, BuildStatus: "unknown", SamplingStatus: "unknown", AcquisitionStatus: "same", Rows: make([]analysis.ProfileComparisonRow, 0, s.TopN), Limitations: []string{"Short sampled profiles do not establish statistical significance or a definitive regression."}}
	if rates != nil {
		out.Limitations = append(out.Limitations, "Rates and deltas round independently from exact native integer ratios; subtracting displayed rates can differ from the displayed delta. Ranking uses displayed deltas.")
	}
	if b.buildKnown && i.buildKnown {
		out.BuildStatus = "different"
		if b.build == i.build {
			out.BuildStatus = "same"
		}
	}
	if b.facts.Period != nil && i.facts.Period != nil {
		out.SamplingStatus = "different"
		if *b.facts.Period == *i.facts.Period {
			out.SamplingStatus = "same"
		}
	}
	if b.facts.ProfileComparisonAcquisition != i.facts.ProfileComparisonAcquisition {
		out.AcquisitionStatus = "different"
	}
	if out.BuildStatus == "unknown" {
		out.Limitations = append(out.Limitations, "Native build identity is unknown for at least one input.")
	} else if out.BuildStatus == "different" {
		out.Limitations = append(out.Limitations, "Native mapping build identities differ; matching function names do not establish identical code.")
	}
	if out.SamplingStatus == "unknown" {
		out.Limitations = append(out.Limitations, "Native sampling configuration is unknown for at least one input.")
	} else if out.SamplingStatus == "different" {
		out.Limitations = append(out.Limitations, "Native sampling configurations differ; account for this when interpreting the values.")
	}
	if out.AcquisitionStatus == "different" {
		out.Limitations = append(out.Limitations, "Acquisition configurations differ; both input configurations are retained in this result.")
	}
	if b.facts.SymbolStatus != "complete" || i.facts.SymbolStatus != "complete" {
		out.Limitations = append(out.Limitations, "Unresolved stacks share a null function bucket; that bucket does not identify the same function across inputs.")
	}
	top := &comparisonHeap{}
	add := func(name string, baseline, incident int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Both raw inputs are bounded to +/- (2^53-1), so their exact signed
		// difference fits int64. Rates instead subtract exact native ratios.
		row := analysis.ProfileComparisonRow{Baseline: float64(baseline), Incident: float64(incident), Delta: float64(incident - baseline)}
		if rates != nil {
			row.Baseline, row.Incident, row.Delta = rates.values(baseline, incident)
		}
		if !analysis.ProfileComparisonNumber(row.Baseline) || !analysis.ProfileComparisonNumber(row.Incident) || !analysis.ProfileComparisonNumber(row.Delta) {
			return artifact.ErrLimit
		}
		if name != "" {
			n := name
			row.Function = &n
		}
		if top.Len() < s.TopN {
			heap.Push(top, row)
		} else if analysis.ProfileComparisonBefore(row, (*top)[0]) {
			(*top)[0] = row
			heap.Fix(top, 0)
		}
		return nil
	}
	for name, count := range b.counts {
		if err := add(name, count.cumulative, i.counts[name].cumulative); err != nil {
			return zero, err
		}
	}
	for name, count := range i.counts {
		if _, exists := b.counts[name]; !exists {
			if err := add(name, 0, count.cumulative); err != nil {
				return zero, err
			}
		}
	}
	sort.Slice(*top, func(a, b int) bool { return analysis.ProfileComparisonBefore((*top)[a], (*top)[b]) })
	out.Rows = append(out.Rows, (*top)...)
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !out.Valid(s) {
		return zero, artifact.ErrLimit
	}
	encoded, err := json.Marshal(out)
	defer clear(encoded)
	if err != nil || len(encoded) > analysis.ProfileComparisonBytes {
		return zero, artifact.ErrLimit
	}
	return out, nil
}

// Only bounded native integers enter this scratch arithmetic: 53-bit values,
// at most47-bit durations, a1e9 scale and at most131-bit cross-products. Reuse
// the small operands per function; there is no evidence-selected precision.
type comparisonRateArithmetic struct {
	baselineDuration, incidentDuration, scale                               big.Int
	baselineNumerator, incidentNumerator, deltaNumerator, work, denominator big.Int
	ratio                                                                   big.Rat
}

func newComparisonRateArithmetic(baselineNanos, incidentNanos int64) *comparisonRateArithmetic {
	r := &comparisonRateArithmetic{}
	r.baselineDuration.SetInt64(baselineNanos)
	r.incidentDuration.SetInt64(incidentNanos)
	r.scale.SetInt64(1000000000)
	r.denominator.Mul(&r.baselineDuration, &r.incidentDuration)
	return r
}

func (r *comparisonRateArithmetic) values(baseline, incident int64) (float64, float64, float64) {
	r.baselineNumerator.SetInt64(baseline)
	r.baselineNumerator.Mul(&r.baselineNumerator, &r.scale)
	r.incidentNumerator.SetInt64(incident)
	r.incidentNumerator.Mul(&r.incidentNumerator, &r.scale)
	r.ratio.SetFrac(&r.baselineNumerator, &r.baselineDuration)
	b, _ := r.ratio.Float64()
	r.ratio.SetFrac(&r.incidentNumerator, &r.incidentDuration)
	i, _ := r.ratio.Float64()
	r.deltaNumerator.Mul(&r.incidentNumerator, &r.baselineDuration)
	r.work.Mul(&r.baselineNumerator, &r.incidentDuration)
	r.deltaNumerator.Sub(&r.deltaNumerator, &r.work)
	r.ratio.SetFrac(&r.deltaNumerator, &r.denominator)
	delta, _ := r.ratio.Float64()
	return b, i, delta
}

type comparisonHeap []analysis.ProfileComparisonRow

func (h comparisonHeap) Len() int           { return len(h) }
func (h comparisonHeap) Less(i, j int) bool { return analysis.ProfileComparisonBefore(h[j], h[i]) }
func (h comparisonHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *comparisonHeap) Push(v any)        { *h = append(*h, v.(analysis.ProfileComparisonRow)) }
func (h *comparisonHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }
