package analysis

import (
	"math"
	"strings"
	"testing"
)

func comparisonResultFixture() (ProfileComparison, ProfileComparisonSelection) {
	s, _ := NormalizeProfileComparisonSelection("cpu", ProfileComparisonRate, 0)
	name, btime, itime := "example.work", 30.0, 10.0
	facts := ProfileComparisonFacts{ProfileComparisonAcquisition: ProfileComparisonAcquisition{ProfileType: "cpu", Mode: "interval"}, DurationSeconds: &btime, Total: 300, Period: &ProfileComparisonPeriod{Type: "cpu", Unit: "nanoseconds", Value: 10000000}, SymbolStatus: "complete"}
	i := facts
	i.DurationSeconds = &itime
	i.Total = 100
	return ProfileComparison{SampleType: "cpu", Unit: "nanoseconds", Normalization: ProfileComparisonRate, Aggregation: "cumulative", Comparable: true, Baseline: facts, Incident: i, BuildStatus: "unknown", SamplingStatus: "same", AcquisitionStatus: "same", Rows: []ProfileComparisonRow{{Function: &name, Baseline: 10, Incident: 10, Delta: 0}}, Limitations: []string{"A short sample does not establish a regression."}}, s
}

func TestProfileComparisonSelectionAndAcquisitionSemantics(t *testing.T) {
	s, err := NormalizeProfileComparisonSelection("cpu", ProfileComparisonRaw, 0)
	if err != nil || !s.Valid() || s.TopN != 20 {
		t.Fatal(s, err)
	}
	for _, s := range []ProfileComparisonSelection{{SampleType: "cpu", Normalization: "rate", TopN: 20}, {SampleType: "cpu", Normalization: ProfileComparisonRaw, TopN: 101}, {SampleType: "cpu", Normalization: ProfileComparisonRaw, TopN: -1}, {SampleType: "cpu\n", Normalization: ProfileComparisonRaw, TopN: 20}, {SampleType: strings.Repeat("x", 65), Normalization: ProfileComparisonRaw, TopN: 20}} {
		if s.Valid() {
			t.Fatal("invalid comparison selection", s)
		}
	}
	heap := ProfileComparisonAcquisition{ProfileType: "heap", Mode: "snapshot"}
	allocs := ProfileComparisonAcquisition{ProfileType: "allocs", Mode: "cumulative"}
	if !ProfileComparisonAcquisitionsCompatible(heap, allocs) {
		t.Fatal("same selected heap counters were split by handler name")
	}
	heap.ForceGC = true
	if !ProfileComparisonAcquisitionsCompatible(heap, allocs) {
		t.Fatal("GC setting became an automatic incompatibility")
	}
	allocs.Mode = "delta"
	if ProfileComparisonAcquisitionsCompatible(heap, allocs) {
		t.Fatal("state total confused with a window delta")
	}
	heap.Mode, heap.ForceGC = "delta", false
	if !ProfileComparisonAcquisitionsCompatible(heap, allocs) {
		t.Fatal("window heap counters refused")
	}
	for _, a := range []ProfileComparisonAcquisition{{ProfileType: "runtimeTrace", Mode: "interval"}, {ProfileType: "heap", Mode: "delta", ForceGC: true}, {ProfileType: "cpu", Mode: "snapshot"}, {ProfileType: "java", Mode: "interval"}} {
		if a.Valid() {
			t.Fatal("unsupported acquisition facts", a)
		}
	}
}

func TestProfileComparisonResultIsClosedFiniteAndConsistent(t *testing.T) {
	for _, mutate := range []func(*ProfileComparison){
		func(r *ProfileComparison) { r.SampleType = "bytes" },
		func(r *ProfileComparison) { r.Unit = "" },
		func(r *ProfileComparison) { r.Comparable = false },
		func(r *ProfileComparison) { r.Normalization = "unknown" },
		func(r *ProfileComparison) { r.Aggregation = "flat" },
		func(r *ProfileComparison) { r.Baseline.DurationSeconds = nil },
		func(r *ProfileComparison) { *r.Incident.DurationSeconds = math.Inf(1) },
		func(r *ProfileComparison) { r.Baseline.Total = ProfileSummaryMaximumValue + 1 },
		func(r *ProfileComparison) { r.Baseline.Period.Value = 0 },
		func(r *ProfileComparison) { r.Baseline.Period.Type = "cpu\n" },
		func(r *ProfileComparison) { r.Baseline.ProfileType = "mutex"; r.Baseline.Mode = "delta" },
		func(r *ProfileComparison) { r.Baseline.SymbolStatus = "guessed" },
		func(r *ProfileComparison) { r.BuildStatus = "verified" },
		func(r *ProfileComparison) { r.SamplingStatus = "different" },
		func(r *ProfileComparison) { r.AcquisitionStatus = "different" },
		func(r *ProfileComparison) { r.Rows = nil },
		func(r *ProfileComparison) { r.Rows = []ProfileComparisonRow{} },
		func(r *ProfileComparison) { r.Rows = append(r.Rows, r.Rows[0]) },
		func(r *ProfileComparison) { r.Rows[0].Function = nil },
		func(r *ProfileComparison) { *r.Rows[0].Function = "" },
		func(r *ProfileComparison) { r.Rows[0].Delta = 1 },
		func(r *ProfileComparison) { r.Rows[0].Baseline = math.NaN() },
		func(r *ProfileComparison) { r.Rows[0].Incident = float64(ProfileSummaryMaximumValue) + 1 },
		func(r *ProfileComparison) { r.Limitations = nil },
	} {
		r, s := comparisonResultFixture()
		r = CloneProfileComparison(r)
		if !r.Valid(s) {
			t.Fatal("valid fixture refused", r)
		}
		mutate(&r)
		if r.Valid(s) {
			t.Fatal("inconsistent comparison accepted", r)
		}
	}
	r, s := comparisonResultFixture()
	r = CloneProfileComparison(r)
	r.Normalization, s.Normalization = ProfileComparisonRaw, ProfileComparisonRaw
	r.Baseline.DurationSeconds = nil
	r.Incident.DurationSeconds = nil
	r.Rows[0].Baseline, r.Rows[0].Incident, r.Rows[0].Delta = -10, 4, 14
	if !r.Valid(s) {
		t.Fatal("signed raw comparison refused", r)
	}
	r.Rows[0].Baseline, r.Rows[0].Incident, r.Rows[0].Delta = .1, .2, .2-.1
	if r.Valid(s) {
		t.Fatal("fractional raw integer values accepted")
	}
}

func TestProfileComparisonCloneOwnsNestedTransientValues(t *testing.T) {
	r, _ := comparisonResultFixture()
	copy := CloneProfileComparison(r)
	*copy.Rows[0].Function = "changed"
	*copy.Baseline.DurationSeconds = 9
	copy.Baseline.Period.Value = 9
	copy.Limitations[0] = "changed"
	if *r.Rows[0].Function != "example.work" || *r.Baseline.DurationSeconds != 30 || r.Baseline.Period.Value != 10000000 || r.Limitations[0] == "changed" {
		t.Fatal("copy borrowed nested result data")
	}
	rows, limitations := r.Rows, r.Limitations
	r.Clear()
	if rows[0] != (ProfileComparisonRow{}) || limitations[0] != "" || r.Rows != nil || r.Limitations != nil || *copy.Rows[0].Function != "changed" {
		t.Fatal("clear retained values or changed independent clone")
	}
}

func TestProfileComparisonRateDeltaMayDifferFromDisplayedRateSubtraction(t *testing.T) {
	r, s := comparisonResultFixture()
	r.Rows[0].Baseline = 2999999999999999.5
	r.Rows[0].Incident = r.Rows[0].Baseline
	r.Rows[0].Delta = -1.0 / 3.0
	if !r.Valid(s) {
		t.Fatal("independently rounded exact rate delta refused", r.Rows[0])
	}
	for _, wrong := range []float64{-1, 1, math.NaN(), math.Inf(1)} {
		r.Rows[0].Delta = wrong
		if r.Valid(s) {
			t.Fatal("rate delta outside possible rounding interval accepted", wrong)
		}
	}
	r.Rows[0].Baseline, r.Rows[0].Incident, r.Rows[0].Delta = 0, 10, math.Nextafter(10, math.Inf(1))
	if r.Valid(s) {
		t.Fatal("exact zero side acquired an unnecessary delta rounding step")
	}
	r.Rows[0].Delta = 10
	if !r.Valid(s) {
		t.Fatal("exact zero side delta refused")
	}
}

func TestProfileComparisonRowsRespectEachSidesSymbolCoverage(t *testing.T) {
	for _, mode := range []string{"both-missing-named", "baseline-missing-named-value", "incident-missing-named-value", "baseline-complete-null-value", "incident-complete-null-value"} {
		r, s := comparisonResultFixture()
		switch mode {
		case "both-missing-named":
			r.Baseline.SymbolStatus, r.Incident.SymbolStatus = "missing", "missing"
			r.Rows[0].Baseline, r.Rows[0].Incident, r.Rows[0].Delta = 0, 0, 0
		case "baseline-missing-named-value":
			r.Baseline.SymbolStatus = "missing"
		case "incident-missing-named-value":
			r.Incident.SymbolStatus = "missing"
		case "baseline-complete-null-value":
			r.Rows[0].Function = nil
			r.Incident.SymbolStatus = "missing"
		case "incident-complete-null-value":
			r.Rows[0].Function = nil
			r.Baseline.SymbolStatus = "missing"
		}
		if r.Valid(s) {
			t.Fatal("row contradicts a side's symbol coverage", mode, r.Rows[0])
		}
	}
	r, s := comparisonResultFixture()
	r.Baseline.SymbolStatus = "missing"
	r.Rows[0].Baseline = 0
	r.Rows[0].Delta = r.Rows[0].Incident
	if !r.Valid(s) {
		t.Fatal("named function only present on resolved side refused")
	}
	r.Rows[0].Function = nil
	r.Baseline.SymbolStatus, r.Incident.SymbolStatus = "missing", "complete"
	r.Rows[0].Baseline, r.Rows[0].Incident, r.Rows[0].Delta = 10, 0, -10
	if !r.Valid(s) {
		t.Fatal("unresolved bucket only present on missing side refused")
	}
	r.Baseline.SymbolStatus, r.Incident.SymbolStatus = "partial", "partial"
	r.Rows[0].Baseline, r.Rows[0].Incident, r.Rows[0].Delta = 10, 20, 10
	if !r.Valid(s) {
		t.Fatal("partial sides' unresolved bucket refused")
	}
}
