package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

type ContextDeletionWork struct {
	Deletion   Deletion
	Checkpoint value.ContextDeletionCheckpoint // PurgedAt remains zero until actual purge.
}
type ContextDeletionRecovery interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}
type ContextDeletionLedger interface {
	ReadContextDeletion(context.Context, artifact.Location, artifact.RecoveryProof) (value.ContextDeletionCheckpoint, bool, error)
	BeginContextDeletion(context.Context, artifact.Location, artifact.RecoveryProof) (ContextDeletionWork, error)
	RecordContextPurge(context.Context, ContextDeletionWork, time.Time, artifact.RecoveryProof) (value.ContextDeletionCheckpoint, error)
}
type ContextDeletionAudit interface {
	AcknowledgeContextDeletion(context.Context, value.ContextDeletionCheckpoint, audit.Receipt, artifact.RecoveryProof) error
}
type ContextDeletionFinalizer interface {
	FinalizeContextDeletion(context.Context, value.ContextDeletionCheckpoint, artifact.RecoveryProof) error
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
	Recovery ContextDeletionRecovery
	Now      func() time.Time
}

func (c ContextCleaner) Clean(ctx context.Context, loc artifact.Location) error {
	if loc.Validate() != nil {
		return artifact.ErrInvalid
	}
	if c.Ledger == nil || c.Audit == nil || c.Finalize == nil || c.Purger == nil || c.Objects == nil || c.Recovery == nil || c.Now == nil {
		return ErrUnavailable
	}
	proof, err := c.Recovery.RecoveryState(ctx)
	if err != nil {
		return err
	}
	checkpoint, found, err := c.Ledger.ReadContextDeletion(ctx, loc, proof)
	if err != nil {
		return err
	}
	if !found {
		proof, err = c.Recovery.RecoveryState(ctx)
		if err != nil {
			return err
		}
		work, e := c.Ledger.BeginContextDeletion(ctx, loc, proof)
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
		proof, e = c.Recovery.RecoveryState(cleanup)
		if e != nil {
			stop()
			return e
		}
		checkpoint, e = c.Ledger.RecordContextPurge(cleanup, work, done, proof)
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
	proof, err = c.Recovery.RecoveryState(ctx)
	if err != nil {
		return err
	}
	if err = c.Audit.AcknowledgeContextDeletion(ctx, checkpoint, receipt, proof); err != nil {
		return err
	}
	proof, err = c.Recovery.RecoveryState(ctx)
	if err != nil {
		return err
	}
	return c.Finalize.FinalizeContextDeletion(ctx, checkpoint, proof)
}
