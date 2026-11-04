package presentation

import (
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/domain/analysis"
)

func queryOperation(name string) bool {
	return name == "get_file_excerpt" || name == "get_http_headers" || name == "get_profile_summary" || name == "get_pcap_summary" || name == "compare_profiles" || syscallQueryOperation(name) || name == "get_query_result"
}

func normalizeQueryInput(name string, raw []byte) ([]byte, error) {
	if syscallQueryOperation(name) {
		var in SyscallOperationInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		if in.Limit == 0 {
			in.Limit = analysis.SyscallPageRecords
		}
		in.Names = slices.Clone(in.Names)
		slices.Sort(in.Names)
		view := syscallView(name)
		return json.Marshal(struct {
			Tool, DisplayVersion, CaseID, ArtifactID, Cursor string
			Limit                                            int
			Names                                            []string
			ErrorsOnly                                       bool
		}{name, view.DisplayVersion(), in.CaseID, in.ArtifactID, in.Cursor, in.Limit, in.Names, in.ErrorsOnly})
	}

	if name == "compare_profiles" {
		var in ProfileComparisonOperationInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		selection, err := analysis.NormalizeProfileComparisonSelection(in.SampleType, in.Normalization, in.TopN)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Tool, DisplayVersion, CaseID, ArtifactID, BaselineCaseID, BaselineArtifactID, SampleType, Normalization string
			TopN                                                                                                    int
		}{name, analysis.ProfileComparisonDisplayVersion, in.CaseID, in.ArtifactID, in.BaselineCaseID, in.BaselineArtifactID, selection.SampleType, selection.Normalization, selection.TopN})
	}

	if name == "get_pcap_summary" {
		var in PacketSummaryOperationInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		return json.Marshal(struct{ Tool, DisplayVersion, CaseID, ArtifactID string }{name, analysis.PacketSummaryDisplayVersion, in.CaseID, in.ArtifactID})
	}
	if name == "get_profile_summary" {
		var in ProfileSummaryOperationInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		selection, err := analysis.NormalizeProfileSummarySelection(in.SampleType, in.TopN)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Tool, DisplayVersion, CaseID, ArtifactID, SampleType string
			TopN                                                 int
		}{name, analysis.ProfileSummaryDisplayVersion, in.CaseID, in.ArtifactID, selection.SampleType, selection.TopN})
	}

	if name == "get_http_headers" {
		// The cursor is bound as supplied; a malformed one is still audited
		// and answered as InvalidCursor without any lookup. An omitted limit
		// is the canonical default page.
		var in HTTPHeaderOperationInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		if in.Limit == 0 {
			in.Limit = analysis.HTTPHeaderPageRecords
		}
		return json.Marshal(struct {
			Tool, DisplayVersion, CaseID, ArtifactID, Cursor string
			Limit                                            int
		}{name, analysis.HTTPHeadersDisplayVersion, in.CaseID, in.ArtifactID, in.Cursor, in.Limit})
	}
	if name == "get_query_result" {
		var in struct {
			QueryHandle string `json:"query_handle"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		return json.Marshal(struct{ Tool, DisplayVersion, QueryHandle string }{name, analysis.ContextDisplayVersion, in.QueryHandle})
	}
	var in struct {
		CaseID     string `json:"case_id"`
		ArtifactID string `json:"artifact_id"`
		LineStart  int    `json:"line_start"`
		MaxLines   int    `json:"max_lines"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	selection, err := analysis.NormalizeLineSelection(in.LineStart, in.MaxLines)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Tool, DisplayVersion, CaseID, ArtifactID string
		LineStart, MaxLines                      int
	}{name, analysis.ContextDisplayVersion, in.CaseID, in.ArtifactID, selection.LineStart, selection.MaxLines})
}

// ProfileSummaryOperationInput is the exact closed selection bound by the
// query invocation MAC. Registration remains a separate qualification gate.
type ProfileSummaryOperationInput struct {
	CaseID     string `json:"case_id"`
	ArtifactID string `json:"artifact_id"`
	SampleType string `json:"sample_type"`
	TopN       int    `json:"top_n"`
}

// ProfileComparisonOperationInput fixes both roles in the audited selection.
type ProfileComparisonOperationInput struct {
	CaseID             string `json:"case_id"`
	ArtifactID         string `json:"artifact_id"`
	BaselineCaseID     string `json:"baseline_case_id"`
	BaselineArtifactID string `json:"baseline_artifact_id"`
	SampleType         string `json:"sample_type"`
	Normalization      string `json:"normalization"`
	TopN               int    `json:"top_n"`
}

// PacketSummaryOperationInput selects one already saved metadata artifact.
type PacketSummaryOperationInput struct {
	CaseID     string `json:"case_id"`
	ArtifactID string `json:"artifact_id"`
}
