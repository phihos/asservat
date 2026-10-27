package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestHistorySettingsOutputCountDoesNotRaiseOtherAuditLimits(t *testing.T) {
	in := connectorAuditIntent()
	in.Name, in.InputFormat, in.Peer = "get_capture_settings", "context-input/v1", nil
	in.Actor = identity.Principal{Issuer: "https://identity.invalid", Subject: "reader", ClientID: "console", Kind: identity.Human}
	out := OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{4}, OutputBytes: OperationCaptureSettingsOutputLimit, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second)}
	if !out.Valid() {
		t.Fatal("bounded settings count refused")
	}
	out.OutputBytes++
	if out.Valid() {
		t.Fatal("unbounded settings count accepted")
	}
	out.OutputBytes = OperationOutputLimit + 1
	for _, name := range []string{"get_capture", "preview_capture", "get_case"} {
		out.Intent.Name = name
		if out.Valid() {
			t.Fatalf("larger count escaped settings operation: %s", name)
		}
	}
}
