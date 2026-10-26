package presentation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
)

const wireSharing = `,"sharing":{"recipients":[{"kind":"Group","issuer":"https://id.invalid","id":"incident-team"},{"kind":"User","issuer":"https://id.invalid","id":"reviewer"}],"notAfter":"2030-01-02T03:04:05.123456789Z"}`

// ADR-235: preview_capture carries the capture-time sharing instruction into
// the reviewed intent and says what will be shared; the wire stays valid.
func TestContextOperationsPreviewCarriesCaptureSharing(t *testing.T) {
	s, f := operationFixture(t, true)
	b, err := s.Call(t.Context(), f, "preview_capture", []byte(strings.TrimSuffix(wirePreview, "}")+wireSharing+"}"))
	if err != nil || s.contracts.ValidateOutput("preview_capture", b.Body) != nil {
		t.Fatal("preview with sharing", err, string(b.Body))
	}
	in := f.input.Sharing
	if in == nil || len(in.Recipients) != 2 || in.Recipients[0].Kind != "Group" || in.Recipients[0].ID != "incident-team" || in.Recipients[1].Kind != "User" ||
		!in.NotAfter.Equal(time.Date(2030, 1, 2, 3, 4, 5, 123456000, time.UTC)) {
		t.Fatalf("sharing not mapped (microsecond end): %+v", in)
	}
	var out struct{ Data struct{ Warnings []string } }
	if json.Unmarshal(b.Body, &out) != nil || len(out.Data.Warnings) != 1 || !strings.Contains(out.Data.Warnings[0], "2 recipient(s)") {
		t.Fatal("preview does not say the result will be shared", string(b.Body))
	}
	// Nine recipients exceed the implemented bound.
	many := `,"sharing":{"recipients":[` + strings.Repeat(`{"kind":"User","issuer":"https://id.invalid","id":"u"},`, 8) + `{"kind":"User","issuer":"https://id.invalid","id":"u9"}]}`
	if _, err := s.Call(t.Context(), f, "preview_capture", []byte(strings.TrimSuffix(wirePreview, "}")+many+"}")); err == nil {
		t.Fatal("nine recipients accepted")
	}
}

// A requester without owner authority is refused with its own code before
// any capture; the audit records a denial.
func TestContextOperationsSharingNotPermitted(t *testing.T) {
	s, f := operationFixture(t, true)
	f.err = value.ErrSharingDenied
	for _, call := range []struct{ name, in string }{{"preview_capture", strings.TrimSuffix(wirePreview, "}") + wireSharing + "}"}, {"request_capture", wireRequest}} {
		b, err := s.Call(t.Context(), f, call.name, []byte(call.in))
		if err != nil || !strings.Contains(string(b.Body), `"SharingNotPermitted"`) || !strings.Contains(string(b.Body), "No capture was started") || b.auditDecision != operationAuditDenied || s.contracts.ValidateOutput(call.name, b.Body) != nil {
			t.Fatal(call.name, err, string(b.Body))
		}
	}
}

// get_capture reports sharing separately from the capture's phase.
func TestContextOperationsCaptureSharingStatus(t *testing.T) {
	s, f := operationFixture(t, true)
	for _, status := range []*value.ContextSharingStatus{nil, {State: value.SharingPending}, {State: value.SharingShared, ShareID: "00000000-0000-4000-8000-000000000040"}, {State: value.SharingUnavailable}} {
		f.sharing = status
		b, err := s.Call(t.Context(), f, "get_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
		if err != nil || s.contracts.ValidateOutput("get_capture", b.Body) != nil {
			t.Fatal(err, string(b.Body))
		}
		var out struct {
			Data struct {
				Phase   string
				Sharing *struct {
					State   string `json:"state"`
					ShareID string `json:"share_id"`
				}
			}
		}
		if json.Unmarshal(b.Body, &out) != nil || out.Data.Phase != "Finalizing" || (status == nil) != (out.Data.Sharing == nil) ||
			status != nil && (out.Data.Sharing.State != status.State || out.Data.Sharing.ShareID != status.ShareID) {
			t.Fatal("sharing status not projected separately", string(b.Body))
		}
	}
}
