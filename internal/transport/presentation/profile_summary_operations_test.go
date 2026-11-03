package presentation

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func summaryBridge(t *testing.T) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, *projectionAuditTarget) {
	t.Helper()
	s, f, g, p := bridgeAuditFixture(t)
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, value.ProfileSummaryDisplayVersion
	f.a.Scope.SourceProjectionDigest, f.a.Scope.Selection, f.a.Scope.Profile = artifact.Digest{}, value.LineSelection{}, value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.ProfileSummaryWorkerBytes, value.ProfileSummaryWorkerBytes
	f.s.ProfileRoutes = f
	summaries, ok := f.s.ProfileSummaries()
	if !ok {
		t.Fatal("missing typed summaries")
	}
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		p.adapter, err = adapter.WithProfileSummaries(summaries)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.result = &value.ProjectionResult{Summary: &value.ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", Top: []value.ProfileHotspot{}, SymbolStatus: "missing"}}
	return s, f, g, p
}
func summaryInput(top int) []byte {
	b, _ := json.Marshal(ProfileSummaryOperationInput{CaseID: bridgeID, ArtifactID: bridgeID, SampleType: "cpu", TopN: top})
	return b
}
func TestProfileSummaryQueryRemainsExplicitlyDisabled(t *testing.T) {
	_, f, _, p := bridgeAuditFixture(t)
	if p.adapter.serves("get_profile_summary") || slices.Contains(p.adapter.toolNames(), "get_profile_summary") {
		t.Fatal("summary enabled by ordinary query composition")
	}
	if _, ok := f.s.ProfileSummaries(); ok {
		t.Fatal("summary route implicitly enabled")
	}
}
func TestProfileSummaryQueryPendingReadyAndOriginalAuditSelection(t *testing.T) {
	s, f, g, p := summaryBridge(t)
	f.ready = false
	first, err := s.Call(t.Context(), f, "get_profile_summary", summaryInput(20))
	if err != nil {
		t.Fatal("begin", err)
	}
	if s.contracts.ValidateOutput("get_profile_summary", first.Body) != nil || f.admissions != 1 || f.starts != 1 || f.reads != 0 || g.intents[0].InputFormat != "context-query-input/v1" {
		t.Fatal("pending summary admission")
	}
	if f.q.Scope.Profile.SampleType != "cpu" || f.q.Scope.Profile.TopN != 20 {
		t.Fatal("query selection changed")
	}
	_ = first.Close(context.Background())
	f.ready = true
	ready, err := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal("poll", err)
	}
	defer ready.Close(context.Background())
	var out struct {
		DataClass string `json:"data_class"`
		Data      struct {
			Tool   string `json:"tool_name"`
			Result struct {
				Data     value.ProfileSummary `json:"data"`
				Warnings []string             `json:"warnings"`
			}
		}
	}
	if json.Unmarshal(ready.Body, &out) != nil || out.DataClass != "extract" || out.Data.Tool != "get_profile_summary" || out.Data.Result.Data.SampleType != "cpu" || len(out.Data.Result.Warnings) != 2 {
		t.Fatalf("closed summary output %s", ready.Body)
	}
	if s.contracts.ValidateOutput("get_query_result", ready.Body) != nil || f.reads != 1 || f.starts != 1 || p.last.delivery.Tool() != "get_profile_summary" {
		t.Fatal("poll replaced admitted source")
	}
}
func TestProfileSummaryAuditRefusesChangedOrMixedInput(t *testing.T) {
	for _, mode := range []string{"sample", "top", "artifact", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			s, f, _, p := summaryBridge(t)
			p.mutate = func(call *OperationCall, raw *json.RawMessage) {
				var in ProfileSummaryOperationInput
				_ = json.Unmarshal(*raw, &in)
				switch mode {
				case "sample":
					in.SampleType = "alloc_space"
				case "top":
					in.TopN = 19
				case "artifact":
					in.ArtifactID = "00000000-0000-4000-8000-000000000099"
				case "mixed":
					input := analysisapp.ContextQueryInput{Profile: value.ProfileSummaryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}}, QueryID: bridgeID}
					if call.queryInvocation.CheckInput(t.Context(), input) == nil {
						t.Fatal("mixed query input accepted")
					}
					call.queryInvocation = nil
				}
				*raw, _ = json.Marshal(in)
			}
			out, err := s.Call(t.Context(), f, "get_profile_summary", summaryInput(20))
			if err == nil || len(out.Body) != 0 || f.admissions != 0 || f.starts != 0 {
				t.Fatal("unreviewed input dispatched")
			}
		})
	}
}
