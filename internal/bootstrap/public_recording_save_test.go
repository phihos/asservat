package bootstrap

import (
	captureapp "asservat.local/asservat/internal/application/capture"
	"slices"
	"testing"
)

func TestPublicRecordingServicesRemainPassiveUnderOrdinaryCollectionGate(t *testing.T) {
	c, s := publicContextOperationFixture(t)
	// Deliberately conflicting caller value must not enable the request service.
	s.Recordings = &captureapp.RecordingSaves{Investigation: captureapp.ContextInvestigation{RecordingSaveEnabled: true}}
	s.Cancellations = &captureapp.CaptureCancellation{}
	v, err := composePublicContextUseCases(c, s)
	if err != nil || v.submission.RecordingSaveEnabled {
		t.Fatal("ordinary collection enabled manual source acquisition", err)
	}
	operations, err := NewPublicContextOperations(c, s)
	if err != nil {
		t.Fatal(err)
	}
	names := operations.ToolNames()
	for _, name := range []string{"request_capture", "list_recordings", "preview_recording_save", "cancel_capture"} {
		if !slices.Contains(names, name) {
			t.Fatal("passive discovery or restrictive cancellation lost", name, names)
		}
	}
	if !s.Recordings.Investigation.RecordingSaveEnabled || s.Investigation.RecordingSaveEnabled {
		t.Fatal("assembly mutated caller values")
	}
	c.CollectionEnabled = false
	operations, err = NewPublicContextOperations(c, s)
	if err != nil {
		t.Fatal(err)
	}
	names = operations.ToolNames()
	if slices.Contains(names, "request_capture") || slices.Contains(names, "cancel_capture") || !slices.Contains(names, "list_recordings") || !slices.Contains(names, "preview_recording_save") {
		t.Fatal("ordinary disabled capture gate was bypassed", names)
	}
}
