package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestRecordingSavePreviewOutputCountIsNamedAndFinite(t *testing.T) {
	in := connectorAuditIntent()
	in.Name, in.InputFormat, in.Peer = "preview_recording_save", "context-input/v1", nil
	in.Actor = identity.Principal{Issuer: "https://identity.invalid", Subject: "maintainer", ClientID: "console", Kind: identity.Human}
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
