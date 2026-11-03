package native

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
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

func TestComparisonCodecWrapperSizeBecomesPinnedContentFreeRefusal(t *testing.T) {
	s := comparisonCodecScope()
	s.Profile.TopN = 100
	f := query.ProfileComparisonFacts{ProfileComparisonAcquisition: query.ProfileComparisonAcquisition{ProfileType: "cpu", Mode: "interval"}, Total: 100, SymbolStatus: "complete"}
	c := query.ProfileComparison{SampleType: "cpu", Unit: "nanoseconds", Normalization: query.ProfileComparisonRaw, Aggregation: "cumulative", Comparable: true, Baseline: f, Incident: f, BuildStatus: "unknown", SamplingStatus: "unknown", AcquisitionStatus: "same", Rows: []query.ProfileComparisonRow{}, Limitations: []string{}}
	for n := 0; n < 100; n++ {
		name := fmt.Sprintf("%03d.", n)
		c.Rows = append(c.Rows, query.ProfileComparisonRow{Function: &name, Baseline: 1, Incident: 1})
	}
	b, _ := json.Marshal(c)
	remaining := query.ContextResultBytes - 8 - len(b)
	for n := range c.Rows {
		add := min(remaining, 512-len(*c.Rows[n].Function))
		*c.Rows[n].Function += strings.Repeat("x", add)
		remaining -= add
	}
	b, _ = json.Marshal(c)
	if remaining != 0 || len(b) != query.ContextResultBytes-8 || !c.Valid(s.Comparison.Selection(s.Profile)) {
		t.Fatal("invalid wrapper-edge fixture", remaining, len(b))
	}
	wire, err := encodeProjectionResult(query.ProjectionResult{Comparison: &c}, s)
	if err != nil || bytes.Contains(wire, []byte(`"Comparison"`)) {
		t.Fatal("wrapper size dropped protocol ownership or retained content", err)
	}
	r, err := decodeProjectionResult(wire, s)
	if err != nil || !r.Valid(s) || !r.TooLarge || r.Comparison != nil || r.IncompatibleProfiles {
		t.Fatal("missing typed size refusal", r, err)
	}
	for _, other := range []query.ContextProjectionScope{func() query.ContextProjectionScope { o := s; o.Version[0]++; return o }(), func() query.ContextProjectionScope { o := s; o.Comparison.Baseline.Version[0]++; return o }()} {
		if _, err := decodeProjectionResult(wire, other); err == nil {
			t.Fatal("size refusal crossed source versions")
		}
	}
	if _, err := encodeProjectionResult(query.ProjectionResult{TooLarge: true, IncompatibleProfiles: true}, s); err == nil {
		t.Fatal("mixed refusal accepted")
	}
	if _, err := encodeProjectionResult(query.ProjectionResult{TooLarge: true, Comparison: &c}, s); err == nil {
		t.Fatal("size refusal retained content")
	}
}

func TestProjectionComparisonCodecPinsBothVersionsAndClosedResult(t *testing.T) {
	s := comparisonCodecScope()
	f := query.ProfileComparisonFacts{ProfileComparisonAcquisition: query.ProfileComparisonAcquisition{ProfileType: "cpu", Mode: "interval"}, Total: 1, SymbolStatus: "complete"}
	name := "synthetic.work"
	comparison := query.ProfileComparison{SampleType: "cpu", Unit: "nanoseconds", Normalization: query.ProfileComparisonRaw, Aggregation: "cumulative", Comparable: true, Baseline: f, Incident: f, BuildStatus: "unknown", SamplingStatus: "unknown", AcquisitionStatus: "same", Rows: []query.ProfileComparisonRow{{Function: &name, Baseline: 1, Incident: 1}}, Limitations: []string{"Synthetic test."}}
	for _, r := range []query.ProjectionResult{{Comparison: &comparison}, {IncompatibleProfiles: true}, {TooLarge: true}} {
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
