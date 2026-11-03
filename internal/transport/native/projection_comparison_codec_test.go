package native

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func comparisonCodecScope() query.ContextProjectionScope {
	s := resultScope()
	s.NativeType, s.SourceFormat, s.DisplayVersion, s.SourceProjectionDigest = artifact.PprofArtifact, artifact.PprofFormat, query.ProfileComparisonDisplayVersion, artifact.Digest{}
	s.Selection, s.Profile = query.LineSelection{}, query.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	s.Comparison = query.ProfileComparisonWindow{Normalization: query.ProfileComparisonRaw, Baseline: query.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: "00000000-0000-4000-8000-000000000002", CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: artifact.Digest{2}}}
	return s
}

func TestProjectionComparisonCodecPinsBothVersionsAndClosedResult(t *testing.T) {
	s := comparisonCodecScope()
	f := query.ProfileComparisonFacts{ProfileComparisonAcquisition: query.ProfileComparisonAcquisition{ProfileType: "cpu", Mode: "interval"}, Total: 1, SymbolStatus: "complete"}
	name := "synthetic.work"
	comparison := query.ProfileComparison{SampleType: "cpu", Unit: "nanoseconds", Normalization: query.ProfileComparisonRaw, Aggregation: "cumulative", Comparable: true, Baseline: f, Incident: f, BuildStatus: "unknown", SamplingStatus: "unknown", AcquisitionStatus: "same", Rows: []query.ProfileComparisonRow{{Function: &name, Baseline: 1, Incident: 1}}, Limitations: []string{"Synthetic test."}}
	for _, r := range []query.ProjectionResult{{Comparison: &comparison}, {IncompatibleProfiles: true}} {
		b, err := encodeProjectionResult(r, s)
		if err != nil || len(b) > query.ContextResultBytes {
			t.Fatal("encode", err)
		}
		back, err := decodeProjectionResult(b, s)
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatal("roundtrip", back, err)
		}
		for _, which := range []string{"baseline", "incident"} {
			other := s
			if which == "baseline" {
				other.Comparison.Baseline.Version[0]++
			} else {
				other.Version[0]++
			}
			if _, err := decodeProjectionResult(b, other); err == nil {
				t.Fatal("crossed source version", which)
			}
		}
		for _, bad := range [][]byte{[]byte("null"), append(bytes.Repeat([]byte(" "), query.ContextResultBytes), b...), append(append([]byte{}, b[:len(b)-1]...), []byte(`,"labels":["sensitive-marker"]}`)...)} {
			if _, err := decodeProjectionResult(bad, s); err == nil {
				t.Fatal("malformed/mixed/oversized accepted")
			}
		}
		if _, err := decodeProjectionResult(b, resultScope()); err == nil {
			t.Fatal("comparison accepted by legacy scope")
		}
	}
	bad, _ := json.Marshal(profileComparisonReply{BaselineVersion: s.Comparison.Baseline.Version, IncidentVersion: s.Version, Comparison: &comparison, IncompatibleProfiles: true})
	if _, err := decodeProjectionResult(bad, s); err == nil {
		t.Fatal("mixed semantic refusal accepted")
	}
	if _, err := encodeProjectionResult(query.ProjectionResult{Comparison: &comparison, IncompatibleProfiles: true}, s); err == nil {
		t.Fatal("mixed encoder accepted")
	}
}
