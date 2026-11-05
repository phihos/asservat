package presentation

import (
	"encoding/json"
	"testing"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

// The installed logs journey publishes its original capture, then reads this
// same collection review before inspecting the selected saved result. The
// reviewed finite window has no recorder ring, filter or profile endpoint.
func TestFiniteLogsGrantRetainsReviewedWindowWithoutRecorderFields(t *testing.T) {
	base, current := operationFixture(t, true)
	view := grantView(current.i.VerifiedAt)
	view.Grant.DataClass = "raw"
	view.Grant.Reasons = []authorization.SensitiveReason{{ActionID: "a1", Code: "recordingApprovalRequired"}}
	view.Grant.ResultAccess.Operations = []string{"download_artifact", "get_logs"}
	view.Review.ObservationLimits = nil
	view.Review.Actions = []authapp.GrantReviewAction{{ActionID: "a1", Kind: "logs", ExecutionMode: "onTrigger", Before: "1h", After: "10s", MaxBytes: artifact.LogNativeLimit, Sensitive: []string{"recordingApprovalRequired"}}}
	uc := &grantUseCase{view: view, until: current.metadataUntil}
	service, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := service.Call(t.Context(), current, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	if err != nil {
		t.Fatal("finite logs collection review unavailable", err)
	}
	var out struct {
		Data struct {
			Actions []map[string]any `json:"actions"`
		} `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || len(out.Data.Actions) != 1 {
		t.Fatal("review action missing")
	}
	a := out.Data.Actions[0]
	if a["kind"] != "logs" || a["execution_mode"] != "onTrigger" || a["before"] != "1h" || a["after"] != "10s" || a["max_bytes"] != float64(artifact.LogNativeLimit) {
		t.Fatal("reviewed finite log facts changed", a)
	}
	for _, field := range []string{"ring_max_bytes", "ring_max_age", "filter", "filter_digest", "filter_instructions", "profile"} {
		if _, present := a[field]; present {
			t.Fatal("invented recorder field", field)
		}
	}
}
