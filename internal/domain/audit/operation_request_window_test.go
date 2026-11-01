package audit

import (
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestRecordingSaveSubmissionWindowIsOperationSpecific(t *testing.T) {
	for _, tc := range []struct {
		name string
		want time.Duration
	}{{"request_capture", identity.RecordingSaveRequestWindow}, {"preview_capture", 5 * time.Second}, {"preview_recording_save", 5 * time.Second}, {"cancel_capture", 5 * time.Second}, {"get_capture", 5 * time.Second}, {"get_query_result", identity.EvidenceReadRequestWindow}} {
		if got := OperationRequestWindow(tc.name); got != tc.want {
			t.Errorf("%s: %s want %s", tc.name, got, tc.want)
		}
	}
}
