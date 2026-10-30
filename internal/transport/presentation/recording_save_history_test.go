package presentation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

type recordingHistoryFixture struct{ *historyFixture }

func (h recordingHistoryFixture) Settings(context.Context, identities.CurrentIdentity, string) (value.CaptureSettings, error) {
	s := h.settings()
	s.RecordingSave = &value.RecordingSaveSettings{PolicyUID: "policy-a", PolicyExecutionDigest: artifact.Digest{9}, Windows: []value.RecordingSavePreference{{ActionID: "packets", Before: 90 * time.Second}}}
	return s, nil
}
func (h recordingHistoryFixture) PreviewRepeat(ctx context.Context, i identities.CurrentIdentity, id string, _ *value.ContextSharing) (app.ContextPreviewResult, value.CaptureSettings, error) {
	s, err := h.Settings(ctx, i, id)
	if err != nil {
		return app.ContextPreviewResult{}, s, err
	}
	return app.ContextPreviewResult{}, s, value.ErrRecordingSelectionRequired
}
func TestRecordingSaveHistorySettingsNeverBecomeRecipeOrOldSourceReplay(t *testing.T) {
	ops, current, h := historyOperations(t)
	ops.history = recordingHistoryFixture{h}
	reply, err := ops.Call(t.Context(), current, "get_capture_settings", json.RawMessage(`{"capture_id":"`+historyCapture+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply.Body), `"kind":"recordingSaveSettings"`) || strings.Contains(string(reply.Body), "recipe_spec") || strings.Contains(string(reply.Body), "dependency_pins") || strings.Contains(string(reply.Body), "recording_handle") {
		t.Fatal("recording preferences became ordinary recipe/source authority", string(reply.Body))
	}
	reply, err = ops.Call(t.Context(), current, "preview_capture", json.RawMessage(`{"history_capture_id":"`+historyCapture+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply.Body), `"code":"RecordingSelectionRequired"`) || !strings.Contains(string(reply.Body), `"navigation_uri":"https://console.invalid/captures/new"`) {
		t.Fatal("old recording settings silently invoked a recipe", string(reply.Body))
	}
}

func (h recordingHistoryFixture) List(ctx context.Context, i identities.CurrentIdentity, ref targets.WorkloadRequest, origins []value.HistoryOrigin, after *value.HistoryCursor, limit int) (value.HistoryPage, error) {
	page, err := h.historyFixture.List(ctx, i, ref, origins, after, limit)
	for n := range page.Entries {
		page.Entries[n].Operation = "recordingSave"
		page.Entries[n].ActionKinds = []string{"packetCapture"}
		page.Entries[n].RepeatState = "requiresSelection"
	}
	return page, err
}
func TestRecordingHistoryPreservesSaveOperationAndFreshSelection(t *testing.T) {
	ops, current, h := historyOperations(t)
	ops.history = recordingHistoryFixture{h}
	reply, err := ops.Call(t.Context(), current, "list_capture_history", json.RawMessage(`{`+wireTarget+`}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply.Body), `"operation":"recordingSave"`) || !strings.Contains(string(reply.Body), `"repeat_state":"requiresSelection"`) {
		t.Fatal(string(reply.Body))
	}
}
