package analysis

import (
	"errors"
	"math"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

var ErrProfileIncompatible = errors.New("profile sample semantics are incompatible")

const (
	ProfileComparisonRaw   = "none"
	ProfileComparisonRate  = "perSecond"
	ProfileComparisonBytes = ProfileSummaryBytes
)

// ProfileComparisonSelection selects a fixed approved aggregate. It carries
// no source identity, read authority, placement or execution budget.
type ProfileComparisonSelection struct {
	SampleType    string
	Normalization string
	TopN          int
}

func NormalizeProfileComparisonSelection(sample, normalization string, topN int) (ProfileComparisonSelection, error) {
	s, err := NormalizeProfileSummarySelection(sample, topN)
	out := ProfileComparisonSelection{SampleType: s.SampleType, Normalization: normalization, TopN: s.TopN}
	if err != nil || !out.Valid() {
		return ProfileComparisonSelection{}, ErrInvalid
	}
	return out, nil
}
func (s ProfileComparisonSelection) Valid() bool {
	return (ProfileSummarySelection{SampleType: s.SampleType, TopN: s.TopN}).Valid() && (s.Normalization == ProfileComparisonRaw || s.Normalization == ProfileComparisonRate)
}

// ProfileComparisonAcquisition is independently supplied from authenticated
// acquisition metadata. A valid value proves no authenticity or readership.
// Native sample/period/duration facts must still be recomputed from the file.
type ProfileComparisonAcquisition struct {
	ProfileType string `json:"profile_type"`
	Mode        string `json:"mode"`
	ForceGC     bool   `json:"force_gc"`
}

func (a ProfileComparisonAcquisition) Valid() bool {
	d := time.Duration(0)
	if a.Mode == "interval" || a.Mode == "delta" {
		d = time.Second
	}
	return a.ProfileType != "runtimeTrace" && artifact.ValidGoProfile(a.ProfileType, a.Mode, d, a.ForceGC)
}

type ProfileComparisonPeriod struct {
	Type  string `json:"type"`
	Unit  string `json:"unit"`
	Value int64  `json:"value"`
}

// ProfileComparisonFacts deliberately excludes labels, paths, addresses,
// mapping names and build IDs. Unknown native duration/period stays null.
type ProfileComparisonFacts struct {
	ProfileComparisonAcquisition
	DurationSeconds *float64                 `json:"duration_seconds"`
	Total           int64                    `json:"total"`
	Period          *ProfileComparisonPeriod `json:"period"`
	SymbolStatus    string                   `json:"symbol_status"`
}

func (f ProfileComparisonFacts) Valid() bool {
	return f.ProfileComparisonAcquisition.Valid() && ProfileSummaryValue(f.Total) &&
		(f.SymbolStatus == "complete" || f.SymbolStatus == "partial" || f.SymbolStatus == "missing") &&
		(f.DurationSeconds == nil || comparisonFinite(*f.DurationSeconds) && *f.DurationSeconds > 0 && *f.DurationSeconds <= 86400) &&
		(f.Period == nil || ProfileSummaryText(f.Period.Type, 64) && ProfileSummaryText(f.Period.Unit, 64) && f.Period.Value > 0 && ProfileSummaryValue(f.Period.Value))
}

type ProfileComparisonRow struct {
	Function *string `json:"function"`
	Baseline float64 `json:"baseline"`
	Incident float64 `json:"incident"`
	// For perSecond, each number is rounded independently from the exact native
	// integer ratios. Delta is not subtraction of the two displayed rates.
	Delta float64 `json:"delta"`
}

// ProfileComparison is a transient extract of cumulative function values,
// ranked by absolute incident-minus-baseline delta then function name. This
// fixed aggregation/ranking is explicit rather than an inferred regression.
type ProfileComparison struct {
	SampleType        string                 `json:"sample_type"`
	Unit              string                 `json:"unit"`
	Normalization     string                 `json:"normalization"`
	Aggregation       string                 `json:"aggregation"`
	Comparable        bool                   `json:"comparable"`
	Baseline          ProfileComparisonFacts `json:"baseline"`
	Incident          ProfileComparisonFacts `json:"incident"`
	BuildStatus       string                 `json:"build_status"`
	SamplingStatus    string                 `json:"sampling_status"`
	AcquisitionStatus string                 `json:"acquisition_status"`
	Rows              []ProfileComparisonRow `json:"rows"`
	Limitations       []string               `json:"limitations"`
}

func comparisonFinite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func ProfileComparisonNumber(n float64) bool {
	return comparisonFinite(n) && math.Abs(n) <= float64(ProfileSummaryMaximumValue)
}
func comparisonStatus(s string) bool { return s == "same" || s == "different" || s == "unknown" }

// ProfileComparisonAcquisitionsCompatible distinguishes counter families and
// state totals from interval/delta values. Go heap and allocs expose the same
// selected heap counters; their differing handler names alone are not a mismatch.
func ProfileComparisonAcquisitionsCompatible(a, b ProfileComparisonAcquisition) bool {
	family := func(kind string) string {
		if kind == "heap" || kind == "allocs" {
			return "heap"
		}
		return kind
	}
	return a.Valid() && b.Valid() && family(a.ProfileType) == family(b.ProfileType) && comparisonWindow(a.Mode) == comparisonWindow(b.Mode)
}

func comparisonSamplingStatus(a, b *ProfileComparisonPeriod) string {
	if a == nil || b == nil {
		return "unknown"
	}
	if *a == *b {
		return "same"
	}
	return "different"
}

func ProfileComparisonBefore(a, b ProfileComparisonRow) bool {
	if x, y := math.Abs(a.Delta), math.Abs(b.Delta); x != y {
		return x > y
	}
	x, y := "", ""
	if a.Function != nil {
		x = *a.Function
	}
	if b.Function != nil {
		y = *b.Function
	}
	return x < y
}

func (r ProfileComparison) Valid(s ProfileComparisonSelection) bool {
	if !s.Valid() || r.SampleType != s.SampleType || r.Normalization != s.Normalization || !ProfileSummaryText(r.Unit, 64) || r.Aggregation != "cumulative" || !r.Comparable || !r.Baseline.Valid() || !r.Incident.Valid() || !comparisonStatus(r.BuildStatus) || !comparisonStatus(r.SamplingStatus) || !comparisonStatus(r.AcquisitionStatus) || r.Rows == nil || len(r.Rows) > s.TopN || r.Limitations == nil || len(r.Limitations) > 16 {
		return false
	}
	if !ProfileComparisonAcquisitionsCompatible(r.Baseline.ProfileComparisonAcquisition, r.Incident.ProfileComparisonAcquisition) || r.SamplingStatus != comparisonSamplingStatus(r.Baseline.Period, r.Incident.Period) {
		return false
	}
	if (r.AcquisitionStatus == "same") != (r.Baseline.ProfileComparisonAcquisition == r.Incident.ProfileComparisonAcquisition) || r.AcquisitionStatus == "unknown" {
		return false
	}
	if s.Normalization == ProfileComparisonRate && (r.Baseline.DurationSeconds == nil || r.Incident.DurationSeconds == nil || !comparisonWindow(r.Baseline.Mode) || !comparisonWindow(r.Incident.Mode)) {
		return false
	}
	if len(r.Rows) == 0 && (r.Baseline.Total != 0 || r.Incident.Total != 0 || r.Baseline.SymbolStatus != "missing" || r.Incident.SymbolStatus != "missing") {
		return false
	}
	seen := map[string]bool{}
	for i, row := range r.Rows {
		name := ""
		if row.Function != nil {
			name = *row.Function
			if !ProfileSummaryText(name, 512) {
				return false
			}
		} else if r.Baseline.SymbolStatus == "complete" && r.Incident.SymbolStatus == "complete" {
			return false
		}
		if row.Function != nil && (r.Baseline.SymbolStatus == "missing" && r.Incident.SymbolStatus == "missing" || r.Baseline.SymbolStatus == "missing" && row.Baseline != 0 || r.Incident.SymbolStatus == "missing" && row.Incident != 0) {
			return false
		}
		if row.Function == nil && (r.Baseline.SymbolStatus == "complete" && row.Baseline != 0 || r.Incident.SymbolStatus == "complete" && row.Incident != 0) {
			return false
		}
		if seen[name] || !ProfileComparisonNumber(row.Baseline) || !ProfileComparisonNumber(row.Incident) || !ProfileComparisonNumber(row.Delta) || i > 0 && !ProfileComparisonBefore(r.Rows[i-1], row) {
			return false
		}
		if s.Normalization == ProfileComparisonRaw && (math.Trunc(row.Baseline) != row.Baseline || math.Trunc(row.Incident) != row.Incident || math.Trunc(row.Delta) != row.Delta || row.Delta != row.Incident-row.Baseline) {
			return false
		}
		if s.Normalization == ProfileComparisonRate && !comparisonRateDeltaConsistent(row) {
			return false
		}
		seen[name] = true
	}
	for _, text := range r.Limitations {
		if !ProfileSummaryText(text, 512) {
			return false
		}
	}
	return true
}

// A structural consumer has the three independently rounded rates, not the
// original per-function integers. Check their possible one-rounding interval;
// this is numeric consistency, never authentication of a worker's calculation.
func comparisonRateDeltaConsistent(row ProfileComparisonRow) bool {
	// With bounded native durations, a zero rate means an exact zero integer
	// numerator. Subtracting it introduces no independent rounding uncertainty.
	if row.Baseline == 0 {
		return row.Delta == row.Incident
	}
	if row.Incident == 0 {
		return row.Delta == -row.Baseline
	}
	ulp := func(v float64) float64 {
		if v == 0 {
			return 0
		} // a zero integer numerator gives an exact zero rate
		return math.Max(math.Nextafter(v, math.Inf(1))-v, v-math.Nextafter(v, math.Inf(-1)))
	}
	displayedDifference := row.Incident - row.Baseline
	uncertainty := 0.0
	for _, v := range []float64{row.Baseline, row.Incident, row.Delta, displayedDifference} {
		if halfULP := ulp(v) / 2; halfULP > 0 {
			// Round the error budget outward after each addition so differently
			// sized ULPs cannot make its floating-point sum too small.
			uncertainty = math.Nextafter(uncertainty+halfULP, math.Inf(1))
		}
	}
	if uncertainty == 0 {
		return row.Delta == displayedDifference
	}
	return math.Abs(row.Delta-displayedDifference) <= uncertainty
}
func comparisonWindow(mode string) bool { return mode == "interval" || mode == "delta" }

func CloneProfileComparison(r ProfileComparison) ProfileComparison {
	r.Rows = slices.Clone(r.Rows)
	r.Limitations = slices.Clone(r.Limitations)
	for i := range r.Rows {
		if r.Rows[i].Function != nil {
			v := *r.Rows[i].Function
			r.Rows[i].Function = &v
		}
	}
	for _, f := range []*ProfileComparisonFacts{&r.Baseline, &r.Incident} {
		if f.DurationSeconds != nil {
			v := *f.DurationSeconds
			f.DurationSeconds = &v
		}
		if f.Period != nil {
			v := *f.Period
			f.Period = &v
		}
	}
	return r
}

func (r *ProfileComparison) Clear() {
	if r == nil {
		return
	}
	clear(r.Rows)
	clear(r.Limitations)
	*r = ProfileComparison{}
}
