package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestHistorySettingsOutputCountDoesNotRaiseOtherAuditLimits(t *testing.T) {
	in := humanAuditIntent("get_capture_settings", "context-input/v1")
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

func humanAuditIntent(name, format string) OperationIntent {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	return OperationIntent{ID: "00000000-0000-4000-8000-000000000005", RootID: "00000000-0000-4000-8000-000000000001", TraceID: "00000000-0000-4000-8000-000000000004", Name: name, InputFormat: format, MACVersion: "mac-v1", AccountVersion: "account-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "reader", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{2}, InputDigest: artifact.Digest{3}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
}
