package integration

import (
	"asservat.local/asservat/internal/contracts"
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/google/pprof/profile"
)

func TestInstalledProfileComparisonFocusPreflight(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "profile-comparison")
	if !installedProfileFocus() || !installedRecordingFocus() || !installedFastFixture() || nativeCapacityProfile().Records != installedProfileComparisonQueries*query.ProfileComparisonQueryUnits || nativeCapacityProfile().Records != 40 {
		t.Fatal("comparison focus not wired to exact two-query40-unit fixture")
	}
	checkManualProfilePlan(t, "00000000-0000-4000-8000-000000000001", approvedRecordingArguments("00000000-0000-4000-8000-000000000001", "payments", "api"))
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	if !installedProfileFocus() || nativeCapacityProfile().Records != query.ProfileSummaryQueryUnits {
		t.Fatal("original manual profile funding changed")
	}
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "approved-recording")
	if installedProfileFocus() || nativeCapacityProfile().Records != 8 {
		t.Fatal("non-profile fixture changed")
	}
}

func TestInstalledProfileComparisonIndependentNativeCalculation(t *testing.T) {
	leaf, root := &profile.Function{ID: 1, Name: "leaf"}, &profile.Function{ID: 2, Name: "root"}
	inline := &profile.Location{ID: 1, Line: []profile.Line{{Function: leaf}, {Function: root}}}
	recursive := &profile.Location{ID: 2, Line: []profile.Line{{Function: root}}}
	native := func(value, duration int64) []byte {
		p := &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}}, Sample: []*profile.Sample{{Location: []*profile.Location{inline, recursive, inline}, Value: []int64{value}}}, Location: []*profile.Location{inline, recursive}, Function: []*profile.Function{leaf, root}, DurationNanos: duration}
		var out bytes.Buffer
		if err := p.Write(&out); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	rows, totals, durations, err := independentInstalledProfileComparison(native(10, 2e9), native(14, 1e9), 20)
	if err != nil || totals != [2]int64{10, 14} || durations != [2]float64{2, 1} || len(rows) != 2 || rows[0].Function == nil || *rows[0].Function != "leaf" || rows[1].Function == nil || *rows[1].Function != "root" {
		t.Fatal("independent recursion/inline/rate facts", rows, totals, durations, err)
	}
	for _, row := range rows {
		if row.Baseline != 5 || row.Incident != 14 || row.Delta != 9 {
			t.Fatal("native rate or recursive multiplicity changed", row)
		}
	}
	limited, _, _, err := independentInstalledProfileComparison(native(10, 2e9), native(14, 1e9), 1)
	if err != nil || !reflect.DeepEqual(limited, rows[:1]) {
		t.Fatal("limit was applied before complete native aggregation", err)
	}
	if _, _, _, err := independentInstalledProfileComparison([]byte("invalid"), native(14, 1e9), 20); err == nil {
		t.Fatal("malformed downloaded native profile accepted")
	}
}

func TestInstalledProfileComparisonBrowserReplyRetainsBothSourceProvenance(t *testing.T) {
	raw, err := os.ReadFile("../../examples/mcp-profile-comparison-result.json")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil || wire.ValidateOutput("compare_profiles", raw) != nil {
		t.Fatal("canonical comparison/browser fixture", err)
	}
	var reply installedJourneyEnvelope
	if json.Unmarshal(raw, &reply) != nil || reply.Status != "ok" || reply.DataClass != "extract" || len(reply.Provenance) != 2 || reply.Provenance[0].ArtifactID == "" || reply.Provenance[1].Digest == "" {
		t.Fatal("browser transport dropped comparison source fields")
	}
}
