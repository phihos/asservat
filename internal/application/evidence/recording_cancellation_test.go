package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestRecordingCollectionCancellationVariantIsExclusive(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	p := artifact.RecordingCancellation{CaptureID: id, AttemptID: id, WriterPodUID: id, WriterEpoch: id, ExpectationDigest: artifact.Digest{1}, JoinedAt: time.Now()}
	c := RecordingCollection{State: RecordingCancelled, RecordingCancellation: &p}
	if !c.Valid(artifact.Registration{}) {
		t.Fatal("typed cancellation refused")
	}
	for _, state := range []string{RecordingPending, RecordingStored, RecordingFailed} {
		x := c
		x.State = state
		x.Failure = "captureFailed"
		if x.Valid(artifact.Registration{}) {
			t.Fatal("proof escaped cancellation variant", state)
		}
	}
	c.ProfileCancellation = &artifact.ProfileCancellation{CaptureID: id, AttemptID: id, WriterPodUID: id, WriterEpoch: id, ExpectationDigest: artifact.Digest{1}, JoinedAt: p.JoinedAt}
	if c.Valid(artifact.Registration{}) {
		t.Fatal("mixed cancellation proofs accepted")
	}
	c.ProfileCancellation = nil
	p.WriterEpoch = ""
	if c.Valid(artifact.Registration{}) {
		t.Fatal("invalid proof accepted")
	}
}
