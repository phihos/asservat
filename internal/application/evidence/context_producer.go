package evidence

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// ContextProducer prepares all keys before acquisition. Scope and copy capacity
// must already be accepted. It cannot publish evidence or acknowledge custody.
type ContextProducer interface {
	PrepareContext(context.Context, artifact.ContextExpectation) (PreparedContext, error)
}
type PreparedContext interface {
	StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error)
	Close()
}

// ErrContextStoreUnconfirmed: the capture succeeded but its encrypted store
// was not positively confirmed; no copy receipt may be relied on.
var ErrContextStoreUnconfirmed = errors.New("context store unconfirmed")

// ContextAcquirer is a prepared output that captures, encrypts and stores in
// one place (ADR-171), so plaintext evidence never reaches its caller. It
// returns the acquisition instant (also on an unconfirmed store) and copies.
type ContextAcquirer interface {
	AcquireContext(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, artifact.Copies, error)
}

// StoredContextCloser joins the actual one-use handle and refuses failed,
// partial or unacknowledged writes. Its facts confer no cleanup authority.
type StoredContextCloser interface {
	PreparedContext
	CompleteStored() (artifact.ContextWriterCompletion, error)
}
