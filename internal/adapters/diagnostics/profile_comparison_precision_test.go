package diagnostics

import (
	"bytes"
	"math/big"
	"testing"

	analysis "asservat.local/asservat/internal/domain/analysis"
)

func TestPprofComparisonPreservesSmallRateDeltaBeforeRounding(t *testing.T) {
	for _, negative := range []bool{false, true} {
		baseline, incident := int64(9007199254740989), int64(9007199254740988)
		want := -1.0 / 3.0
		if negative {
			baseline, incident = -baseline, -incident
			want = -want
		}
		b := comparisonFixture([]string{"work"}, []int64{baseline}, 3)
		i := comparisonFixture([]string{"work"}, []int64{incident}, 3)
		s := comparisonSelection(t, analysis.ProfileComparisonRate, 20)
		out, err := runComparison(t, b, i, s)
		if err != nil || !out.Valid(s) || len(out.Rows) != 1 || out.Rows[0].Delta != want {
			t.Fatal("small true delta was lost by subtracting displayed rounded rates", out, err, want)
		}
		if out.Rows[0].Baseline != out.Rows[0].Incident || out.Rows[0].Delta == out.Rows[0].Incident-out.Rows[0].Baseline {
			t.Fatal("fixture no longer crosses independent rate rounding", out.Rows[0])
		}
	}
}

func TestPprofComparisonRateDeltaUsesExactNativeNanoseconds(t *testing.T) {
	bv, iv := int64(9007199254740989), int64(9007199254740988)
	bn, in := int64(3000000000), int64(3000000001)
	b := comparisonFixture([]string{"work"}, []int64{bv}, 3)
	b.DurationNanos = bn
	i := comparisonFixture([]string{"work"}, []int64{iv}, 3)
	i.DurationNanos = in
	s := comparisonSelection(t, analysis.ProfileComparisonRate, 20)
	out, err := ComparePprof(t.Context(), bytes.NewReader(encoded(t, b)), cpuComparisonFacts, bytes.NewReader(encoded(t, i)), cpuComparisonFacts, s)
	// A separate rational oracle compares native values per nanosecond, then
	// scales the exact difference to per-second units before the sole rounding.
	exact := new(big.Rat).Sub(big.NewRat(iv, in), big.NewRat(bv, bn))
	exact.Mul(exact, big.NewRat(1000000000, 1))
	want, _ := exact.Float64()
	if err != nil || !out.Valid(s) || out.Rows[0].Delta != want {
		t.Fatal(out, err, want)
	}
}
