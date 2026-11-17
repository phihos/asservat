package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
)

type installedPacketSummarySource struct {
	CaseID, ArtifactID, Version, PodUID string
	CaptureMode                         string
	Expires                             time.Time
}

func queryInstalledPacketSummaryWithCall(t *testing.T, ctx context.Context, source installedPacketSummarySource, call func(string, any) installedComparisonReply, verify func(string, string) func()) query.PacketSummary {
	t.Helper()
	result := call("get_extract", map[string]string{"view": "pcapSummary", "case_id": source.CaseID, "artifact_id": source.ArtifactID})
	operation, handle := result.RequestID, ""
	var until time.Time
	for poll := 0; result.Status == "pending"; poll++ {
		var p struct {
			Handle   string    `json:"query_handle"`
			Revision int       `json:"revision"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &p) != nil || p.Handle == "" || p.Revision < 1 || p.Observed.IsZero() || !p.Expires.After(p.Observed) || p.Expires.After(source.Expires) {
			t.Fatal("invalid pending packet query")
		}
		if poll == 0 {
			handle, until = p.Handle, p.Expires
		}
		if p.Handle != handle || !p.Expires.Equal(until) || poll >= 4 {
			t.Fatal("packet query changed original handle/deadline or exhausted polls")
		}
		result = call("get_query_result", map[string]any{"query_handle": handle, "after_revision": p.Revision})
	}
	if result.Status != "ok" {
		t.Fatal("packet summary unavailable", result.Status)
	}
	var finalObserved time.Time
	if handle != "" {
		var nested struct {
			Handle   string                   `json:"query_handle"`
			Tool     string                   `json:"tool_name"`
			Result   installedComparisonReply `json:"result"`
			Observed time.Time                `json:"query_observed_at"`
			Expires  time.Time                `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &nested) != nil || nested.Handle != handle || nested.Tool != "get_extract" || nested.Result.RequestID != result.RequestID || !nested.Expires.Equal(until) {
			t.Fatal("packet poll changed original association")
		}
		finalObserved = nested.Observed
		result = nested.Result
	}
	if result.Status != "ok" || result.DataClass != "extract" || len(result.Provenance) != 1 || result.Provenance[0].ArtifactID != source.ArtifactID || result.Provenance[0].Digest != source.Version {
		t.Fatal("packet summary changed exact source/version/result class")
	}
	var times struct {
		Observed time.Time `json:"query_observed_at"`
		Expires  time.Time `json:"query_expires_at"`
	}
	var summary query.PacketSummary
	if json.Unmarshal(result.Data, &times) != nil || times.Observed.IsZero() || !times.Expires.After(times.Observed) || times.Expires.After(source.Expires) || !until.IsZero() && (!times.Expires.Equal(until) || !times.Observed.Equal(finalObserved)) || json.Unmarshal(result.Data, &summary) != nil || !summary.Valid() {
		t.Fatal("packet summary lost canonical fields/original times")
	}
	expectedMode := source.CaptureMode
	if expectedMode == "" {
		expectedMode = "networkHeaders"
	}
	if summary.CaptureMode != expectedMode {
		t.Fatal("packet summary changed source capture mode")
	}
	if verify(handle, operation) == nil {
		t.Fatal("packet summary lacks exact SQL joined proof")
	}
	return summary
}
