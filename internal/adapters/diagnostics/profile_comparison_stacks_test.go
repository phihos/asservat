package diagnostics

import (
	"testing"

	analysis "asservat.local/asservat/internal/domain/analysis"
	"github.com/google/pprof/profile"
)

func TestPprofComparisonInlineAndRecursiveCumulativeCounts(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		baselineLeaf, baselineRoot   int64
		incidentLeaf, incidentRoot   int64
		baselineTotal, incidentTotal int64
		want                         map[string][3]float64
	}{
		{"positive", 10, 5, 4, 12, 15, 16, map[string][3]float64{
			"inlineParent": {10, 4, -6}, "leaf": {10, 4, -6}, "root": {15, 16, 1},
		}},
		{"signed", -10, 5, 4, -12, -5, -8, map[string][3]float64{
			"inlineParent": {-10, 4, 14}, "leaf": {-10, 4, 14}, "root": {-5, -8, -3},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline, incident := summaryFixture(), summaryFixture()
			baseline.Sample[0].Value[1], baseline.Sample[1].Value[1] = tc.baselineLeaf, tc.baselineRoot
			incident.Sample[0].Value[1], incident.Sample[1].Value[1] = tc.incidentLeaf, tc.incidentRoot
			// Both sources contain inlineParent as an inline caller, never a
			// flat leaf. The incident has additional recursive occurrences of
			// both leaf and inlineParent, across repeated locations and inline
			// lines. Each function receives a sample's cumulative value once.
			incident.Sample[0].Location = []*profile.Location{
				incident.Location[0], incident.Location[2], incident.Location[0],
				incident.Location[1], incident.Location[2],
			}
			s := comparisonSelection(t, analysis.ProfileComparisonRaw, 20)
			out, err := runComparison(t, baseline, incident, s)
			if err != nil || !out.Valid(s) || out.Aggregation != "cumulative" || out.Baseline.Total != tc.baselineTotal || out.Incident.Total != tc.incidentTotal || len(out.Rows) != len(tc.want) {
				t.Fatal("comparison lost cumulative source semantics", out, err)
			}
			seen := map[string]bool{}
			for _, row := range out.Rows {
				if row.Function == nil {
					t.Fatal("named stack became unresolved", row)
				}
				name := *row.Function
				want, exists := tc.want[name]
				if !exists || seen[name] || [3]float64{row.Baseline, row.Incident, row.Delta} != want {
					t.Fatal("flat values or recursive multiplicity entered comparison", name, row, want)
				}
				seen[name] = true
			}
		})
	}
}
