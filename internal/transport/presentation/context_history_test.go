package presentation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"slices"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// Test-only history values exercise the wire projection only.
type historyFixture struct {
	ops       *contextOperationFixture
	listed    targets.WorkloadRequest
	origins   []value.HistoryOrigin
	after     *value.HistoryCursor
	limit     int
	repeated  string
	err       error
	next      *value.HistoryCursor
	accepted  time.Time
	untilList time.Time
	sharing   *value.ContextSharing
}

const historyCapture = "00000000-0000-4000-8000-000000000041"

func (h *historyFixture) List(_ context.Context, _ identities.CurrentIdentity, ref targets.WorkloadRequest, origins []value.HistoryOrigin, after *value.HistoryCursor, limit int) (value.HistoryPage, error) {
	h.listed, h.origins, h.after, h.limit = ref, origins, after, limit
	entry := value.HistoryEntry{CaptureID: historyCapture, Origin: value.HistoryManual, AcceptedAt: h.accepted, ExpiresAt: h.accepted.Add(value.HistoryLifetime), Phase: "Succeeded", EvidenceState: "available"}
	return value.HistoryPage{Entries: []value.HistoryEntry{entry}, Next: h.next, ValidUntil: h.untilList}, h.err
}
func (h *historyFixture) settings() value.CaptureSettings {
	return value.CaptureSettings{CaptureID: historyCapture, Origin: value.HistoryManual, ClusterID: "00000000-0000-4000-8000-000000000001", NamespaceUID: "ns", WorkloadUID: "workload", AcceptedAt: h.accepted, ExpiresAt: h.accepted.Add(value.HistoryLifetime),
		TargetJSON:     []byte(`{"adoption":"pinUID","maxPods":1,"namespace":"payments","selection":"allWithinLimit","workloadRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"api","uid":"workload"}}`),
		DependencyJSON: []byte(`[{"digest":"` + hex.EncodeToString(make([]byte, 32)) + `","role":"collector"}]`),
		Namespace:      "payments", WorkloadKind: "Deployment", WorkloadName: "api", RequestedSeconds: 3600, ValidUntil: h.untilList}
}
func (h *historyFixture) Settings(context.Context, identities.CurrentIdentity, string) (value.CaptureSettings, error) {
	return h.settings(), h.err
}
func (h *historyFixture) PreviewRepeat(ctx context.Context, current identities.CurrentIdentity, id string, sharing *value.ContextSharing) (app.ContextPreviewResult, value.CaptureSettings, error) {
	h.repeated, h.sharing = id, sharing
	s := h.settings()
	result, err := h.ops.Preview(ctx, current, value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: s.ClusterID, Namespace: s.Namespace, Kind: s.WorkloadKind, Name: s.WorkloadName}, Diagnostic: value.ContextDiagnosticName, RequestedSeconds: s.RequestedSeconds})
	if h.err != nil {
		return app.ContextPreviewResult{}, value.CaptureSettings{}, h.err
	}
	return result, s, err
}

func historyOperations(t *testing.T) (*ContextOperations, *contextOperationFixture, *historyFixture) {
	t.Helper()
	base, f := operationFixture(t, true)
	h := &historyFixture{ops: f, accepted: f.i.VerifiedAt.Add(-time.Hour).UTC(), untilList: f.metadataUntil}
	s, err := NewContextOperationsWithHistory(base.config, f, f, h)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, h
}

func TestContextHistoryToolsOnlyWithHistoryService(t *testing.T) {
	base, _ := operationFixture(t, true)
	if slices.Contains(base.ToolNames(), "list_capture_history") || slices.Contains(base.ToolNames(), "get_capture_settings") {
		t.Fatal("history tools advertised without a history service")
	}
	if _, err := base.Call(t.Context(), &contextOperationFixture{}, "preview_capture", []byte(`{"history_capture_id":"`+historyCapture+`"}`)); err == nil {
		t.Fatal("repeat branch served without a history service")
	}
	s, _, _ := historyOperations(t)
	if !slices.Contains(s.ToolNames(), "list_capture_history") || !slices.Contains(s.ToolNames(), "get_capture_settings") {
		t.Fatal("history tools missing")
	}
}

func TestContextHistoryWireIsCanonical(t *testing.T) {
	s, f, h := historyOperations(t)
	call := func(name, in string) map[string]any {
		t.Helper()
		b, err := s.Call(t.Context(), f, name, json.RawMessage(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := s.contracts.ValidateOutput(name, b.Body); err != nil {
			t.Fatalf("%s: invalid output %v: %s", name, err, b.Body)
		}
		var out map[string]any
		if json.Unmarshal(b.Body, &out) != nil {
			t.Fatal(name)
		}
		return out
	}
	// Default origin is manual, default limit 20; no cursor without more rows.
	out := call("list_capture_history", `{`+wireTarget+`}`)
	if out["status"] != "ok" || out["next_cursor"] != nil || h.limit != value.DefaultHistoryPage || len(h.origins) != 1 || h.origins[0] != value.HistoryManual || h.listed.Name != "api" || h.after != nil {
		t.Fatal("list defaults", out, h)
	}
	entry := out["data"].(map[string]any)["history"].([]any)[0].(map[string]any)
	if entry["capture_id"] != historyCapture || entry["repeat_state"] != "available" || entry["navigation_uri"] != "https://console.invalid/captures/"+historyCapture {
		t.Fatal("entry", entry)
	}
	// A next page cursor continues only the same selector and origin.
	h.next = &value.HistoryCursor{AcceptedAt: h.accepted, CaptureID: historyCapture}
	out = call("list_capture_history", `{`+wireTarget+`,"origin":"all","limit":1}`)
	cursor, _ := out["next_cursor"].(string)
	if cursor == "" || len(h.origins) != 2 || h.limit != 1 {
		t.Fatal("cursor", out)
	}
	out = call("list_capture_history", `{`+wireTarget+`,"origin":"all","limit":1,"cursor":"`+cursor+`"}`)
	if out["status"] != "ok" || h.after == nil || !h.after.AcceptedAt.Equal(h.accepted) || h.after.CaptureID != historyCapture {
		t.Fatal("cursor did not continue", out, h.after)
	}
	for _, other := range []string{`{` + wireTarget + `,"cursor":"` + cursor + `"}`, `{"target_ref":{"cluster_id":"00000000-0000-4000-8000-000000000001","namespace":"payments","kind":"Deployment","name":"web"},"origin":"all","cursor":"` + cursor + `"}`, `{` + wireTarget + `,"cursor":"forged"}`} {
		if out := call("list_capture_history", other); out["status"] != "error" || out["data"].(map[string]any)["code"] != "UnsupportedRequest" {
			t.Fatal("cursor reused for another list", other, out)
		}
	}
	// Settings: the canonical record, extract class and an exact digest.
	out = call("get_capture_settings", `{"capture_id":"`+historyCapture+`"}`)
	data := out["data"].(map[string]any)
	if out["data_class"] != "extract" || data["kind"] != "captureSettings" {
		t.Fatal("settings", out)
	}
	b, _ := json.Marshal(data["settings"])
	canonical := jsontext.Value(b)
	if canonical.Canonicalize() != nil {
		t.Fatal("settings not JSON")
	}
	if d := sha256.Sum256(canonical); data["settings_digest"] != hex.EncodeToString(d[:]) || data["settings"].(map[string]any)["requested_retention"] != "3600s" {
		t.Fatal("settings digest or retention", data)
	}
	// Collect again restores the target and retention into a normal preview.
	out = call("preview_capture", `{"history_capture_id":"`+historyCapture+`"}`)
	data = out["data"].(map[string]any)
	if out["status"] != "ok" || h.repeated != historyCapture || data["repeated_from_capture_id"] != historyCapture || data["target_ref"].(map[string]any)["name"] != "api" || f.input.RequestedSeconds != 3600 {
		t.Fatal("repeat preview", out)
	}
	if h.sharing != nil {
		t.Fatal("repeat restored or invented a sharing instruction")
	}
	// A new capture-time share (ADR-235) may accompany Collect again.
	out = call("preview_capture", `{"history_capture_id":"`+historyCapture+`","sharing":{"recipients":[{"kind":"User","issuer":"https://id.invalid","id":"reviewer"}]}}`)
	if out["status"] != "ok" || h.sharing == nil || len(h.sharing.Recipients) != 1 || h.sharing.Recipients[0].ID != "reviewer" {
		t.Fatal("repeat dropped the new sharing instruction", out, h.sharing)
	}
	// The history branch takes no other target or retention input.
	for _, in := range []string{`{"history_capture_id":"` + historyCapture + `",` + wireTarget + `}`, `{"history_capture_id":"` + historyCapture + `","requested_retention_seconds":60}`, `{"history_capture_id":"` + historyCapture + `","preset_ref":{"name":"pod-status","version":"v1"}}`} {
		if _, err := s.Call(t.Context(), f, "preview_capture", json.RawMessage(in)); err == nil {
			t.Fatal("history branch accepted another selector", in)
		}
	}
	// A recreated workload is a named, non-retryable refusal; denial stays uniform.
	h.err = value.ErrTargetReplaced
	if out := call("preview_capture", `{"history_capture_id":"`+historyCapture+`"}`); out["data"].(map[string]any)["code"] != "TargetReplaced" {
		t.Fatal("replaced target", out)
	}
	h.err = value.ErrDenied
	for _, name := range []string{"list_capture_history", "get_capture_settings", "preview_capture"} {
		in := `{"capture_id":"` + historyCapture + `"}`
		if name == "list_capture_history" {
			in = `{` + wireTarget + `}`
		} else if name == "preview_capture" {
			in = `{"history_capture_id":"` + historyCapture + `"}`
		}
		if out := call(name, in); out["status"] != "error" || out["data"].(map[string]any)["code"] != "NotAvailable" || out["data_class"] != "metadata" {
			t.Fatal("denial not uniform", name, out)
		}
	}
}
