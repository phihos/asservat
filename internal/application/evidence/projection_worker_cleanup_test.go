package evidence

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Synthetic ledger/API ports isolate the destructive cleanup ordering. Real
// SQL locks, UID-precondition deletion and absence proof need native fixtures.
type projectionCleanupFixture struct {
	now     time.Time
	rows    []ProjectionCleanupCandidate
	term    value.AcquisitionWorkerTermination
	calls   []string
	fail    string
	block   string
	entered chan struct{}
	until   time.Time
}

func (f *projectionCleanupFixture) step(ctx context.Context, phase string) error {
	f.calls = append(f.calls, phase)
	if d, ok := ctx.Deadline(); !ok || !d.Equal(f.until) {
		return errors.New("cleanup changed original caller deadline")
	}
	if f.block == phase {
		close(f.entered)
		<-ctx.Done()
		return ctx.Err()
	}
	if f.fail == phase {
		return errors.New("unknown provider result")
	}
	return ctx.Err()
}
func (f *projectionCleanupFixture) ExpiredProjectionWorkers(ctx context.Context) ([]ProjectionCleanupCandidate, error) {
	return f.rows, f.step(ctx, "list")
}
func (f *projectionCleanupFixture) AbandonUnclaimedProjectionWorker(ctx context.Context, _ query.ContextProjectionWorkerIntent) error {
	return f.step(ctx, "abandon")
}
func (f *projectionCleanupFixture) ObserveExpiredProjectionWorker(ctx context.Context, _ value.AcquisitionWorkerIntent, _ value.DownloadWorkerJob, _ value.AcquisitionWorker) (value.AcquisitionWorkerTermination, error) {
	return f.term, f.step(ctx, "observe")
}
func (f *projectionCleanupFixture) ConfirmProjectionTermination(ctx context.Context, v value.AcquisitionWorkerTermination) (value.AcquisitionWorkerTermination, error) {
	return v, f.step(ctx, "persist")
}
func (f *projectionCleanupFixture) RetireAcquisitionWorker(ctx context.Context, v value.AcquisitionWorkerTermination) (value.AcquisitionWorkerRetirement, error) {
	return value.AcquisitionWorkerRetirement{Termination: v, ObservedAt: f.now, FreshUntil: f.now.Add(time.Second)}, f.step(ctx, "delete-and-prove")
}
func (f *projectionCleanupFixture) RetireProjectionWorker(ctx context.Context, _ value.AcquisitionWorkerRetirement) error {
	return f.step(ctx, "retire")
}
func newProjectionCleanupFixture(t *testing.T) (*projectionCleanupFixture, *ProjectionWorkerCleanup, context.Context) {
	t.Helper()
	p := newProjectionWorkerFixture(t)
	original := routeTestWorker(t, 1)
	profile := original.Intent.Profile
	profile.InstallationID = p.q.Plan.InstallationID
	profile.ClusterID = p.q.Plan.Profile.Path.AcquisitionClusterID
	profile.Configuration = p.q.Plan.Profile.Path.WorkerConfiguration
	intent := value.AcquisitionWorkerIntent{ID: p.q.WorkerID, Parent: value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: p.q.ID}, Profile: profile, CreatedAt: p.q.CreatedAt, RunUntil: p.q.WorkerUntil}
	binding := original.Binding.Acquisition()
	binding.Parent = intent.Parent
	binding.InstallationID = profile.InstallationID
	binding.ClusterID = profile.ClusterID
	binding.Job = intent.JobName()
	job := value.DownloadWorkerJob{IntentID: intent.ID, UID: binding.JobUID, Spec: binding.JobSpec}
	worker := value.AcquisitionWorker{Intent: intent, Job: job, Binding: binding}
	state := ProjectionWorkerState{Intent: query.ContextProjectionWorkerIntent{Query: p.q, Worker: intent}, Audited: true, Claimed: true, Job: job, Worker: worker}
	if !state.Intent.Valid() || !worker.Valid() {
		t.Fatal("invalid cleanup fixture")
	}
	now := p.q.WorkerUntil.Add(time.Second)
	until := time.Now().Add(time.Second)
	ctx, stop := context.WithDeadline(context.Background(), until)
	t.Cleanup(stop)
	f := &projectionCleanupFixture{now: now, rows: []ProjectionCleanupCandidate{{State: state}}, until: until, entered: make(chan struct{})}
	f.term = value.AcquisitionWorkerTermination{Worker: worker, TerminationDigest: artifact.Digest{1}, ObservedAt: now, FreshUntil: now.Add(time.Second)}
	return f, &ProjectionWorkerCleanup{Ledger: f, Jobs: f, Now: func() time.Time { return f.now }}, ctx
}
func TestProjectionCleanupRequiresPersistedTerminationBeforeDelete(t *testing.T) {
	for _, phase := range []string{"", "observe", "persist", "delete-and-prove", "retire"} {
		t.Run(phase, func(t *testing.T) {
			f, s, ctx := newProjectionCleanupFixture(t)
			f.fail = phase
			s.CleanupProjectionWorkers(ctx)
			want := []string{"list", "observe", "persist", "delete-and-prove", "retire"}
			for n, p := range want {
				if p == phase {
					want = want[:n+1]
					break
				}
			}
			if !reflect.DeepEqual(f.calls, want) {
				t.Fatal("unknown cleanup skipped a required proof", f.calls, want)
			}
		})
	}
}
func TestProjectionCleanupNeverClaimedAndAlreadyTerminated(t *testing.T) {
	for _, mode := range []string{"never-claimed", "termination-persisted", "unexpired", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			f, s, ctx := newProjectionCleanupFixture(t)
			want := []string{"list"}
			switch mode {
			case "never-claimed":
				f.rows[0].State.Claimed = false
				f.rows[0].State.Worker = value.AcquisitionWorker{}
				f.rows[0].State.Job = value.DownloadWorkerJob{}
				want = append(want, "abandon")
			case "termination-persisted":
				f.rows[0].Termination = f.term
				f.now = f.now.Add(time.Minute)
				want = append(want, "delete-and-prove", "retire")
			case "unexpired":
				f.now = f.rows[0].State.Intent.Worker.RunUntil.Add(-time.Nanosecond)
			case "too-many":
				for len(f.rows) < 17 {
					f.rows = append(f.rows, f.rows[0])
				}
			}
			s.CleanupProjectionWorkers(ctx)
			if !reflect.DeepEqual(f.calls, want) {
				t.Fatal("cleanup invented or repeated an effect", f.calls, want)
			}
		})
	}
}
func TestProjectionCleanupJoinsBlockingPortsUnderOriginalCaller(t *testing.T) {
	for _, phase := range []string{"list", "observe", "persist", "delete-and-prove", "retire"} {
		t.Run(phase, func(t *testing.T) {
			f, s, parent := newProjectionCleanupFixture(t)
			f.block = phase
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			done := make(chan struct{})
			go func() { s.CleanupProjectionWorkers(ctx); close(done) }()
			select {
			case <-f.entered:
			case <-time.After(time.Second):
				t.Fatal("blocking port not reached")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cleanup detached blocking port")
			}
			if f.calls[len(f.calls)-1] != phase {
				t.Fatal("effect after canceled cleanup", f.calls)
			}
		})
	}
}
func TestProjectionCleanupRotatesAfterUncertainCandidate(t *testing.T) {
	f, s, ctx := newProjectionCleanupFixture(t)
	f.rows = append(f.rows, f.rows[0])
	f.rows[1].State.Claimed = false
	f.rows[1].State.Job = value.DownloadWorkerJob{}
	f.rows[1].State.Worker = value.AcquisitionWorker{}
	f.fail = "observe"
	s.CleanupProjectionWorkers(ctx)
	s.CleanupProjectionWorkers(ctx)
	if !reflect.DeepEqual(f.calls, []string{"list", "observe", "list", "abandon"}) {
		t.Fatal("uncertain candidate starved later cleanup", f.calls)
	}
}
