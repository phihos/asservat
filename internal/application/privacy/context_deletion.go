package privacy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
)

type ContextDeletionWork struct {
	Deletion   Deletion
	Checkpoint value.ContextDeletionCheckpoint // PurgedAt remains zero until actual purge.
}
type ContextDeletionLedger interface {
	ReadContextDeletion(context.Context, artifact.Location) (value.ContextDeletionCheckpoint, bool, error)
	BeginContextDeletion(context.Context, artifact.Location) (ContextDeletionWork, error)
	RecordContextPurge(context.Context, ContextDeletionWork, time.Time) (value.ContextDeletionCheckpoint, error)
}
type ContextDeletionAudit interface {
	AcknowledgeContextDeletion(context.Context, value.ContextDeletionCheckpoint, audit.Receipt) error
}
type ContextDeletionFinalizer interface {
	FinalizeContextDeletion(context.Context, value.ContextDeletionCheckpoint) error
}
type ContextDeletionWriter interface {
	WriteContextDeletion(context.Context, value.ContextDeletionCheckpoint) (audit.Receipt, error)
}
type ContextDeletionSigner interface {
	SignContextDeletion(context.Context, value.ContextDeletionCheckpoint) ([]byte, error)
}
type ContextDeletionVerifier interface {
	VerifyContextDeletion(context.Context, value.ContextDeletionCheckpoint, []byte) error
}

func ContextDeletionDigest(r value.ContextDeletionCheckpoint) artifact.Digest {
	b, _ := json.Marshal(r)
	return sha256.Sum256(b)
}
func ContextWriterDigest(r artifact.ContextWriterCompletion) artifact.Digest {
	b, _ := json.Marshal(r)
	return sha256.Sum256(b)
}

// ContextCleaner qualifies only protocol-pinned successful API writes. Unknown
// remote writes remain obligations for the separate drain protocol. All ports
// have separate credentials; no human read/capture grant is needed for cleanup.
type ContextCleaner struct {
	Ledger   ContextDeletionLedger
	Audit    ContextDeletionAudit
	Finalize ContextDeletionFinalizer
	Purger   AttemptPurger
	Objects  ContextDeletionWriter
	Now      func() time.Time
}

func (c ContextCleaner) Clean(ctx context.Context, loc artifact.Location) error {
	if loc.Validate() != nil {
		return artifact.ErrInvalid
	}
	if c.Ledger == nil || c.Audit == nil || c.Finalize == nil || c.Purger == nil || c.Objects == nil || c.Now == nil {
		return ErrUnavailable
	}
	checkpoint, found, err := c.Ledger.ReadContextDeletion(ctx, loc)
	if err != nil {
		return err
	}
	if !found {
		work, e := c.Ledger.BeginContextDeletion(ctx, loc)
		if e != nil {
			return e
		}
		if work.Deletion.Registration.Location != loc || work.Checkpoint.Location != loc || work.Deletion.Fence != work.Checkpoint.PurgeFence || !c.Now().Before(work.Deletion.LeaseUntil) {
			return ErrFence
		}
		cleanup, stop := context.WithDeadline(ctx, work.Deletion.LeaseUntil)
		if e = c.Purger.PurgeAttempt(cleanup, work.Deletion.Registration); e != nil {
			stop()
			return e
		}
		done := c.Now().UTC().Truncate(time.Microsecond)
		checkpoint, e = c.Ledger.RecordContextPurge(cleanup, work, done)
		stop()
		if e != nil {
			return e
		}
	}
	if !checkpoint.Valid() || checkpoint.Location != loc {
		return ErrConflict
	}
	receipt, err := c.Objects.WriteContextDeletion(ctx, checkpoint)
	if err != nil {
		return err
	}
	if err = c.Audit.AcknowledgeContextDeletion(ctx, checkpoint, receipt); err != nil {
		return err
	}
	return c.Finalize.FinalizeContextDeletion(ctx, checkpoint)
}
