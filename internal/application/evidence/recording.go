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

// SourceSnapshotRecorder starts only an independently admitted window of an
// existing source; it cannot arm or renew that source.
type SourceSnapshotRecorder interface {
	StartSourceSnapshot(context.Context, collector.SourceSnapshot) (time.Time, error)
}

type SourceSnapshotCanceller interface {
	CancelSourceSnapshot(context.Context, collector.SourceSnapshot) error
}

// Recording collection states.
const (
	RecordingPending   = "pending"
	RecordingStored    = "stored"
	RecordingFailed    = "failed"
	RecordingCancelled = "cancelled"
)

// Recording failures of a connector stop on frozen Kubernetes peers
// (ADR-283 part 3). Like captureFailed they record no acquisition; the
// committed start is not refunded.
const (
	RecordingProfilerBusy = "profilerBusy"
	RecordingPeersChanged = "peerMembershipChanged"
	RecordingPeersStale   = "peerMembershipStale"
)

// RecordingCollection is the region's answer to a collect: still recording,
// stored (with the writer completion of the four write-only objects), or
// failed with a closed phase (captureFailed, storeUnconfirmed, or a
// connector stop on Kubernetes peer membership: peerMembershipChanged or
// peerMembershipStale, ADR-283 part 3). Acquired is the queue instant
// returned at start.
type RecordingCollection struct {
	SnapshotCancellation *artifact.SourceSnapshotCancellation `json:",omitempty"`
	SnapshotCoverage     *artifact.SourceSnapshotCoverage     `json:",omitempty"`
	State                string
	Acquired             time.Time
	Completion           artifact.ContextWriterCompletion
	Failure              string
}

// Valid checks the collection against the recording's registration.
func (c RecordingCollection) Valid(r artifact.Registration) bool {
	switch c.State {
	case RecordingPending:
		return c.SnapshotCancellation == nil && c.SnapshotCoverage == nil && c.Completion == (artifact.ContextWriterCompletion{}) && c.Failure == ""
	case RecordingStored:
		return c.SnapshotCancellation == nil && !c.Acquired.IsZero() && c.Completion.Valid(r) && !c.Completion.StoredAt.Before(c.Acquired) && c.Failure == ""
	case RecordingCancelled:
		return c.SnapshotCancellation != nil && c.SnapshotCancellation.Valid() && c.SnapshotCoverage == nil && c.Completion == (artifact.ContextWriterCompletion{}) && c.Failure == ""
	case RecordingFailed:
		return c.SnapshotCancellation == nil && c.SnapshotCoverage == nil && c.Completion == (artifact.ContextWriterCompletion{}) && (c.Failure == "captureFailed" || c.Failure == "storeUnconfirmed" || c.Failure == RecordingProfilerBusy || c.Failure == RecordingPeersChanged || c.Failure == RecordingPeersStale)
	}
	return false
}

// RecordingCollector is the hub's handle on a collect exchange.
type RecordingCollector interface {
	CollectRecording(ctx context.Context) (RecordingCollection, error)
}
