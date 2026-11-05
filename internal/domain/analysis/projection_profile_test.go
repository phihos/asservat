package analysis

import (
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestProfileSummarySourceKeepsRawInputClassification(t *testing.T) {
	source, ok := LookupProjectionSource(artifact.PprofArtifact)
	if !ok || source.NativeType != artifact.PprofArtifact || source.DataClass != "raw" || source.EvidenceType != "profile" || source.NativeLimit != artifact.MaxPprofBytes || source.Format != artifact.PprofFormat {
		t.Fatal("bounded pprof summary source unavailable or reclassified", source)
	}
	for _, kind := range []string{artifact.GoTraceArtifact, "core"} {
		if _, ok := LookupProjectionSource(kind); ok {
			t.Fatal("unreviewed summary source admitted", kind)
		}
	}
}

func TestProfileProjectionScopeAndResultStayClosed(t *testing.T) {
	pod := sourceTestScope()
	b, _ := json.Marshal(pod)
	if strings.Contains(string(b), "Profile") {
		t.Fatal("existing scope wire changed", string(b))
	}
	scope := pod
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, ProfileSummaryDisplayVersion
	scope.SourceProjectionDigest, scope.Selection, scope.Profile = artifact.Digest{}, LineSelection{}, ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	if !scope.Valid() || scope.BeginTool() != "get_profile_summary" || scope.ReadBatches() != 1 || scope.Candidate().Profile != scope.Profile {
		t.Fatal("profile scope not bound")
	}
	var back ContextProjectionScope
	b, _ = json.Marshal(scope)
	if json.Unmarshal(b, &back) != nil || back != scope {
		t.Fatal("profile scope round trip")
	}
	summary := ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", Top: []ProfileHotspot{}, SymbolStatus: "missing"}
	r := ProjectionResult{Summary: &summary}
	if !r.Valid(scope) || r.Valid(pod) {
		t.Fatal("result matched wrong scope")
	}
	r.Headers = HTTPHeaderPage{Records: []HTTPHeaderRecord{}}
	if r.Valid(scope) {
		t.Fatal("mixed result admitted")
	}
	r.Headers = HTTPHeaderPage{}
	scope.Profile.SampleType = "alloc_space"
	if r.Valid(scope) {
		t.Fatal("sample type not bound")
	}
	r.Clear()
	if r.Summary != nil || summary.Top != nil {
		t.Fatal("summary not cleared")
	}
}

func TestProfileSummaryCloneOwnsDisplayPointers(t *testing.T) {
	name, fraction, duration := "work", 1.0, 10.0
	result := ProfileSummary{DurationSeconds: &duration, Top: []ProfileHotspot{{Function: &name, Fraction: &fraction}}}
	clone := CloneProfileSummary(result)
	*clone.DurationSeconds, *clone.Top[0].Function, *clone.Top[0].Fraction = 20, "changed", 0
	if duration != 10 || name != "work" || fraction != 1 {
		t.Fatal("display copy aliases retained summary")
	}
}
