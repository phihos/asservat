package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestRecordingSavePreviewOutputCountIsNamedAndFinite(t *testing.T) {
	in := humanAuditIntent("preview_recording_save", "context-input/v1")
	out := OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{4}, OutputBytes: OperationRecordingSavePreviewOutputLimit, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second)}
	if !out.Valid() {
		t.Fatal("named128KiB metadata count refused")
	}
	out.OutputBytes++
	if out.Valid() {
		t.Fatal("one over named metadata count accepted")
	}
	out.OutputBytes = OperationOutputLimit + 1
	for _, name := range []string{"list_recordings", "get_capture", "cancel_capture", "preview_capture", "get_case"} {
		out.Intent.Name = name
		if out.Valid() {
			t.Fatal("preview cap escaped operation", name)
		}
	}
}
