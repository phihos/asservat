package postgres

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/migrations"
)

// These are bound-projection controls, not SQL authority/rollback qualification.
func TestRecordingGroupAuditBookkeepingKeepsOriginalRequestAndHardEnds(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	requester := identity.Principal{Issuer: "https://identity.example.test", Subject: "operator", ClientID: "console", Kind: identity.Human}
	bounds := value.GroupRequestBounds{StartedAt: now, Until: now.Add(15 * time.Second), Requester: requester}
	admission := value.Admission{RecordingSave: &value.RecordingSaveAdmission{Initiator: authorization.CaptureEligibility{Principal: requester}}}
	admission.Plan.Input.Snapshot = &planning.SourceSnapshotContext{TriggerKind: "recordingSave", Group: &planning.RecordingSaveGroupBinding{ParentCaptureID: "parent", ChildCount: 2}, Request: artifact.SourceSnapshotRequest{T0: now.Add(3 * time.Second), StartBy: now.Add(15 * time.Second), SourceHardUntil: now.Add(time.Minute)}}
	admission.Registration.WriteUntil = now.Add(30 * time.Second)
	intent := audit.CaptureIntent{Initiator: &requester, CreatedAt: now.Add(3 * time.Second), Deadline: now.Add(30 * time.Second), Group: &audit.CaptureGroupBinding{ParentCaptureID: "parent", ChildCount: 2}}
	hard := now.Add(time.Minute)
	got, err := recordingGroupAuditUntil(bounds, admission, intent, hard, hard, hard, hard)
	if err != nil || !got.Equal(bounds.Until) {
		t.Fatalf("original ingress lost: %v %v", got, err)
	}
	// A stale pre-admission observation is deliberately not an input to this
	// immutable bound. All admission proofs are still checked by the transaction.
	for n := 0; n < 4; n++ {
		ends := []time.Time{hard, hard, hard, hard}
		ends[n] = now.Add(7 * time.Second)
		got, err = recordingGroupAuditUntil(bounds, admission, intent, ends...)
		if err != nil || !got.Equal(ends[n]) {
			t.Fatalf("hard end %d ignored: %v %v", n, got, err)
		}
	}
	for _, mutate := range []func(*value.GroupRequestBounds){
		func(b *value.GroupRequestBounds) { b.Requester.ClientID = "other" },
		func(b *value.GroupRequestBounds) { b.StartedAt = intent.CreatedAt.Add(time.Microsecond) },
		func(b *value.GroupRequestBounds) { b.Until = now.Add(16 * time.Second) },
		func(b *value.GroupRequestBounds) { b.Until = intent.CreatedAt },
	} {
		bad := bounds
		mutate(&bad)
		if _, err := recordingGroupAuditUntil(bad, admission, intent, hard); err == nil {
			t.Fatal("invalid original request accepted")
		}
	}
	intent.Group = nil
	if _, err := recordingGroupAuditUntil(bounds, admission, intent, hard); err == nil {
		t.Fatal("singleton gained group bound")
	}
}

func TestRecordingGroupWindowMigrationRestoresExactPriorFunctions(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := fs.ReadFile(migrations.Files(), name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	body := func(s, name string) string {
		t.Helper()
		start := strings.Index(s, "CREATE OR REPLACE FUNCTION "+name+"(")
		if start < 0 {
			start = strings.Index(s, "CREATE FUNCTION "+name+"(")
		}
		if start < 0 {
			t.Fatal("missing", name)
		}
		end := strings.Index(s[start:], "END $$;")
		if end < 0 {
			t.Fatal("unterminated", name)
		}
		return strings.Replace(s[start:start+end+7], "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
	}
	raw := read("00112_recording_save_group_request_bounds.sql")
	up, down, ok := strings.Cut(raw, "-- +goose Down")
	if !ok {
		t.Fatal("no down")
	}
	for _, tc := range []struct{ file, name string }{{"00052_capture_intent_lifecycle.sql", "lock_capture_audit_admission"}, {"00109_recording_save_groups.sql", "guard_context_capture_group"}, {"00110_recording_save_reasons.sql", "reserve_capture_audit"}, {"00111_recording_save_dispatch_window.sql", "guard_operation_audit"}} {
		prior, _, _ := strings.Cut(read(tc.file), "-- +goose Down")
		if body(down, tc.name) != body(prior, tc.name) {
			t.Fatal("downgrade changed prior security function", tc.name)
		}
	}
	if strings.Contains(up, "GRANT ") || !strings.Contains(up, "REVOKE ALL ON FUNCTION recording_save_group_window_valid(public.context_capture,public.recording_save_group,timestamptz) FROM PUBLIC") {
		t.Fatal("new public authority")
	}
	refuse := strings.Index(down, "retained long-window manual groups cannot downgrade")
	restore := strings.Index(down, "CREATE OR REPLACE FUNCTION")
	if refuse < 0 || refuse >= restore || !strings.Contains(down, "LOCK TABLE public.recording_save_group,public.context_capture,public.operation_audit IN SHARE MODE") {
		t.Fatal("restoration can strand retained new semantics")
	}
	// Proof admission remains bounded independently from the immutable request.
	for _, predicate := range []string{"n<original_until", "n<(observed->>'ValidUntil')::timestamptz", "clock_timestamp()>=LEAST(original_until"} {
		if !strings.Contains(body(up, "reserve_capture_audit"), predicate) {
			t.Fatal("lost original admission guard", predicate)
		}
	}
}
