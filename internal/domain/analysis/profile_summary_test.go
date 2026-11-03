package analysis

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestProfileSummarySelection(t *testing.T) {
	s, e := NormalizeProfileSummarySelection("cpu", 0)
	if e != nil || s.TopN != 20 || !s.Valid() {
		t.Fatal(s, e)
	}
	for _, s := range []ProfileSummarySelection{{"", 20}, {"cpu", -1}, {"cpu", 101}, {strings.Repeat("x", 65), 20}, {"cpu\n", 20}, {string([]byte{0xff}), 20}} {
		if s.Valid() {
			t.Fatal("invalid selection", s)
		}
	}
	if _, err := NormalizeProfileSummarySelection("cpu", 100); err != nil {
		t.Fatal(err)
	}
}
func summaryResultFixture() (ProfileSummary, ProfileSummarySelection) {
	name, seconds, fraction := "example.work", 10.0, 0.5
	s := ProfileSummarySelection{"cpu", 20}
	return ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", DurationSeconds: &seconds, Total: 8, Top: []ProfileHotspot{{Function: &name, Flat: 4, Cumulative: 6, Fraction: &fraction}}, SymbolStatus: "complete"}, s
}
func TestProfileSummaryClosedResultValidation(t *testing.T) {
	for _, mutate := range []func(*ProfileSummary){
		func(r *ProfileSummary) { r.SampleType = "bytes" },
		func(r *ProfileSummary) { r.Unit = "" },
		func(r *ProfileSummary) { r.Total = ProfileSummaryMaximumValue + 1 },
		func(r *ProfileSummary) { r.SymbolStatus = "inferred" },
		func(r *ProfileSummary) { r.SymbolStatus = "missing" },
		func(r *ProfileSummary) { r.Top[0].Function = nil },
		func(r *ProfileSummary) { r.Top = nil },
		func(r *ProfileSummary) { r.Top = append(r.Top, r.Top[0]) },
		func(r *ProfileSummary) { x := math.NaN(); r.Top[0].Fraction = &x },
		func(r *ProfileSummary) { x := math.Inf(1); r.DurationSeconds = &x },
		func(r *ProfileSummary) { x := 0.75; r.Top[0].Fraction = &x }, // cumulative ratio is not flat fraction
		func(r *ProfileSummary) { x := 0.0; r.DurationSeconds = &x },
		func(r *ProfileSummary) { r.Top[0].Flat = -1 },
	} {
		r, s := summaryResultFixture()
		if !r.Valid(s) {
			t.Fatal("valid fixture refused")
		}
		mutate(&r)
		if r.Valid(s) {
			t.Fatal("invalid result accepted", r)
		}
	}
	r, s := summaryResultFixture()
	r.Total = 0
	r.Top[0].Flat = -4
	r.Top[0].Cumulative = -6
	r.Top[0].Fraction = nil
	if !r.Valid(s) {
		t.Fatal("signed delta refused")
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"fraction":null`) || !strings.Contains(string(b), `"flat":-4`) {
		t.Fatal(string(b), err)
	}
	// Undefined percentages are null, not silently rendered as zero.
	r.Top[0].Fraction = new(float64)
	if r.Valid(s) {
		t.Fatal("zero total fabricated a fraction")
	}
}
