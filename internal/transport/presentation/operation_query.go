package presentation

import (
	"encoding/json"

	"asservat.local/asservat/internal/domain/analysis"
)

func queryOperation(name string) bool {
	return name == "get_file_excerpt" || name == "get_query_result"
}

func normalizeQueryInput(name string, raw []byte) ([]byte, error) {
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
