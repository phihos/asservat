package evidence

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestRecordingProfileUnavailableRefusalHasNoCompletion(t *testing.T) {
	c := RecordingCollection{State: RecordingFailed, Failure: "profileUnavailable"}
	if !c.Valid(artifact.Registration{}) {
		t.Fatal("known missing endpoint refusal lost at regional completion")
	}
	c.Completion.StoredAt = time.Now()
	if c.Valid(artifact.Registration{}) {
		t.Fatal("endpoint refusal carried stored evidence")
	}
}
