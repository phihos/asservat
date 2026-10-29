package evidence

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-248: a recording is a prepared output whose acquisition runs for its
// duration on the target's node collector. The start exchange only starts
// it; the connector encrypts and stores the node's result when it arrives and
// holds the stored completion until the hub collects it in a later exchange
// on the same ADR-171 pattern. Plaintext and data keys never leave the region.

// ContextRecorder is a prepared output for an expectation with a Recording.
// StartRecording queues the recording on the pinned Pod's node within the
// committed start and returns the instant it was queued (the acquisition
// start). Ownership of the prepared keys moves to the regional holder.
type ContextRecorder interface {
	StartRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error)
}

// PolicyContextRecorder consumes the original finite SQL observation receipt
// and the source resolved within this same authenticated work exchange. It is
// distinct from the ordinary recording start, which cannot dispatch raw work.
type PolicyContextRecorder interface {
	StartPolicyRecording(context.Context, artifact.PinnedPod, time.Time, time.Time, targets.PacketSourceObservation, collector.ObservationPermit) (time.Time, error)
}

// Recording collection states.
const (
	RecordingPending = "pending"
	RecordingStored  = "stored"
	RecordingFailed  = "failed"
)

// RecordingCollection is the region's answer to a collect: still recording,
// stored (with the writer completion of the four write-only objects), or
// failed with a closed phase (captureFailed or storeUnconfirmed). Acquired is
// the queue instant returned at start.
type RecordingCollection struct {
	State      string
	Acquired   time.Time
	Completion artifact.ContextWriterCompletion
	Failure    string
}

// Valid checks the collection against the recording's registration.
func (c RecordingCollection) Valid(r artifact.Registration) bool {
	switch c.State {
	case RecordingPending:
		return c.Completion == (artifact.ContextWriterCompletion{}) && c.Failure == ""
	case RecordingStored:
		return !c.Acquired.IsZero() && c.Completion.Valid(r) && !c.Completion.StoredAt.Before(c.Acquired) && c.Failure == ""
	case RecordingFailed:
		return c.Completion == (artifact.ContextWriterCompletion{}) && (c.Failure == "captureFailed" || c.Failure == "storeUnconfirmed")
	}
	return false
}

// RecordingCollector is the hub's handle on a collect exchange.
type RecordingCollector interface {
	CollectRecording(ctx context.Context) (RecordingCollection, error)
}
