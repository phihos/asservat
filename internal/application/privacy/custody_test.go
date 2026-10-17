package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"errors"
	"testing"
	"time"
)

type cleanupFixture struct {
	CopyLedger
	steps                    []string
	barrierError, purgeError error
	deadline                 time.Time
}

func (f *cleanupFixture) ClaimDeletion(context.Context, artifact.Location) (Deletion, error) {
	f.steps = append(f.steps, "claim")
	return Deletion{LeaseUntil: f.deadline}, nil
}
func (f *cleanupFixture) FinishDeletion(context.Context, Deletion) error {
	f.steps = append(f.steps, "release")
	return nil
}
func (f *cleanupFixture) CloseAndWait(ctx context.Context, _ artifact.Registration) error {
	f.steps = append(f.steps, "barrier")
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(f.deadline) {
		return errors.New("unbounded cleanup")
	}
	return f.barrierError
}
func (f *cleanupFixture) PurgeAttempt(context.Context, artifact.Registration) error {
	f.steps = append(f.steps, "purge")
	return f.purgeError
}

func TestCleanupFailureNeverReleasesCharge(t *testing.T) {
	for _, stage := range []string{"barrier", "purge", "success"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("synthetic unavailable")
			f := &cleanupFixture{deadline: time.Now().Add(time.Second)}
			if stage == "barrier" {
				f.barrierError = failure
			}
			if stage == "purge" {
				f.purgeError = failure
			}
			err := (Cleaner{Ledger: f, Barrier: f, Purger: f}).Clean(context.Background(), artifact.Location{})
			if stage != "success" {
				if !errors.Is(err, failure) {
					t.Fatal(err)
				}
				for _, s := range f.steps {
					if s == "release" {
						t.Fatal("uncertainty refunded")
					}
				}
				return
			}
			if err != nil || len(f.steps) != 4 || f.steps[0] != "claim" || f.steps[1] != "barrier" || f.steps[2] != "purge" || f.steps[3] != "release" {
				t.Fatal("wrong effect order", err, f.steps)
			}
		})
	}
}
