package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"errors"
	"testing"
	"time"
)

type deletionFixture struct {
	checkpoint                      value.ContextDeletionCheckpoint
	saved                           bool
	auditFailure                    bool
	purgeFailure                    bool
	acknowledges, finalizes, purges int
	now                             time.Time
	lease                           time.Time
}

func (f *deletionFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return artifact.RecoveryProof{}, nil
}
func (f *deletionFixture) ReadContextDeletion(context.Context, artifact.Location, artifact.RecoveryProof) (value.ContextDeletionCheckpoint, bool, error) {
	return f.checkpoint, f.saved, nil
}
func (f *deletionFixture) BeginContextDeletion(context.Context, artifact.Location, artifact.RecoveryProof) (ContextDeletionWork, error) {
	return ContextDeletionWork{Deletion: Deletion{Registration: artifact.Registration{Location: f.checkpoint.Location}, LeaseUntil: f.lease, Fence: f.checkpoint.PurgeFence}, Checkpoint: f.checkpoint}, nil
}
func (f *deletionFixture) PurgeAttempt(ctx context.Context, _ artifact.Registration) error {
	f.purges++
	if f.purgeFailure {
		return ErrUnavailable
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(f.lease) {
		return ErrFence
	}
	return nil
}
func (f *deletionFixture) RecordContextPurge(_ context.Context, _ ContextDeletionWork, at time.Time, _ artifact.RecoveryProof) (value.ContextDeletionCheckpoint, error) {
	f.saved = true
	f.checkpoint.PurgedAt = at
	return f.checkpoint, nil
}
func (f *deletionFixture) WriteContextDeletion(context.Context, value.ContextDeletionCheckpoint) (audit.Receipt, error) {
	if f.auditFailure {
		return audit.Receipt{}, ErrUnavailable
	}
	return audit.Receipt{}, nil
}
func (f *deletionFixture) AcknowledgeContextDeletion(context.Context, value.ContextDeletionCheckpoint, audit.Receipt, artifact.RecoveryProof) error {
	f.acknowledges++
	return nil
}
func (f *deletionFixture) FinalizeContextDeletion(context.Context, value.ContextDeletionCheckpoint, artifact.RecoveryProof) error {
	f.finalizes++
	if f.acknowledges == 0 {
		return errors.New("finalized without independent acknowledgement")
	}
	return nil
}
func TestContextCleanupRetriesRecordedPurgeWithoutRepeatingRemoteDeletion(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := &deletionFixture{now: now, lease: now.Add(20 * time.Second), auditFailure: true, checkpoint: value.ContextDeletionCheckpoint{RootID: id, CaptureID: id, StoreID: id, InstallationID: id, IssuerEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, RegistrationDigest: artifact.Digest{1}, WriterDigest: artifact.Digest{2}, DatabaseOID: 1, PostmasterAt: now.Add(-time.Hour), PurgeFence: 1}}
	c := ContextCleaner{Ledger: f, Audit: f, Finalize: f, Purger: f, Objects: f, Recovery: f, Now: func() time.Time { return f.now }}
	if err := c.Clean(context.Background(), f.checkpoint.Location); err == nil || f.purges != 1 || !f.saved || f.finalizes != 0 {
		t.Fatal("audit failure released custody", err)
	}
	original := f.checkpoint
	f.now = f.now.Add(time.Minute)
	f.auditFailure = false
	if err := c.Clean(context.Background(), f.checkpoint.Location); err != nil || f.purges != 1 || f.finalizes != 1 || f.checkpoint != original {
		t.Fatal("retry repeated purge or changed original checkpoint", err)
	}
}
func TestContextCleanupPurgeFailureDoesNotCreatePositiveFact(t *testing.T) {
	now := time.Now()
	id := "10000000-0000-4000-8000-000000000001"
	loc := artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}
	f := &deletionFixture{now: now, lease: now.Add(time.Minute), purgeFailure: true, checkpoint: value.ContextDeletionCheckpoint{Location: loc}}
	c := ContextCleaner{Ledger: f, Audit: f, Finalize: f, Purger: f, Objects: f, Recovery: f, Now: time.Now}
	if err := c.Clean(context.Background(), loc); err == nil || f.saved || f.acknowledges != 0 || f.finalizes != 0 {
		t.Fatal("uncertain purge became success", err)
	}
}
