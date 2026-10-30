package presentation

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordingSaveReasonForwardedVerbatimWhileCollectionDisabled(t *testing.T) {
	audited, _, actor, f, _ := recordingOperationTestFixture(t)
	for _, reason := range []string{" \n\t<&>\x00 ", strings.Repeat("🙂", 512)} {
		raw, _ := json.Marshal(map[string]any{"recording_handles": []string{"opaque-recording-handle"}, "reason": reason})
		reply, err := audited.Call(t.Context(), actor, "preview_recording_save", raw)
		if err != nil || f.request.Reason == nil || *f.request.Reason != reason {
			t.Fatal("reason lost or changed", err)
		}
		var out struct{ Data RecordingSavePreviewData }
		_ = json.Unmarshal(reply.Body, &out)
		if out.Data.CaptureEnabled || actor.requests != 0 {
			t.Fatal("reason enabled acquisition")
		}
	}
	calls := f.previewCalls
	for _, reason := range []any{"", strings.Repeat("🙂", 513), nil} {
		raw, _ := json.Marshal(map[string]any{"recording_handles": []string{"opaque-recording-handle"}, "reason": reason})
		if _, err := audited.Call(t.Context(), actor, "preview_recording_save", raw); err == nil || calls != f.previewCalls {
			t.Fatal("invalid reason reached app")
		}
	}
}

func TestRecordingSaveReasonRejectsInvalidUnicodeWithoutReplacement(t *testing.T) {
	_, ops, actor, f, _ := recordingOperationTestFixture(t)
	for _, raw := range [][]byte{[]byte(`{"recording_handles":["opaque-recording-handle"],"reason":"\ud800"}`), append(append([]byte(`{"recording_handles":["opaque-recording-handle"],"reason":"`), 255), []byte(`"}`)...)} {
		if _, err := ops.Call(t.Context(), actor, "preview_recording_save", raw); err == nil || f.previewCalls != 0 {
			t.Fatal("invalid Unicode replaced before app")
		}
	}
}
