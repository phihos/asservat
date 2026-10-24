package capacity

import (
	"context"
	"errors"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Each cluster has its own discovery loop: one cluster's blocked step does
// not stop another cluster's discovery, and shutdown still joins both.
func TestCapacityReconcilerClustersDiscoverConcurrently(t *testing.T) {
	source, f := capacityObserverTestFixture()
	q, _ := capacityQualificationFixture()
	q.ID, q.Digest = f.accepted.QualificationID, f.accepted.QualificationDigest
	q.RootBacking.RootID, q.RootBacking.InstallationID = f.accepted.RootID, f.accepted.InstallationID
	q.RootBacking.QualificationID, q.RootBacking.QualificationDigest = q.ID, q.Digest
	other := q.NamespaceGuards[0]
	other.ClusterID = "00000000-0000-4000-8000-0000000000b2"
	q.NamespaceGuards = append(q.NamespaceGuards, other)
	blocked := &capacityRuntimeReader{entered: make(chan struct{}), release: make(chan struct{}), recovery: f.recovery}
	free := &capacityRuntimeReader{recovery: f.recovery}
	work := &CapacityWorkReconciler{Qualification: q, Recovery: blocked, Permissions: blocked, Processing: blocked, Root: &RootBackingCoordinator{}, Enrollment: &EnrollmentCoordinator{}, Bindings: blocked, Now: func() time.Time { return f.now }}
	runner := CapacityReconciler{Source: source, Work: work, Clusters: []CapacityClusterReaders{
		{ClusterID: q.NamespaceGuards[0].ClusterID, Workloads: blocked, Guard: blocked},
		{ClusterID: other.ClusterID, Workloads: free, Guard: free},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	released := false
	defer func() {
		cancel()
		if !released {
			close(blocked.release)
		}
		<-done
	}()
	select {
	case <-blocked.entered:
	case err := <-done:
		t.Fatal("runner stopped", err)
	case <-time.After(2 * time.Second):
		t.Fatal("blocked cluster's discovery did not start")
	}
	// The free cluster completes a whole pass (and starts another) while the
	// first cluster's step is still blocked.
	for until := time.Now().Add(5 * time.Second); free.discovered.Load() < 2; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(until) {
			t.Fatal("a blocked cluster stopped another cluster's discovery", free.discovered.Load())
		}
	}
	if blocked.discovered.Load() != 1 {
		t.Fatal("blocked cluster advanced", blocked.discovered.Load())
	}
	cancel()
	close(blocked.release)
	released = true
}

type capacityStandbyReads struct {
	*capacityWorkFacts
	errs  []error
	calls int
}

func (f *capacityStandbyReads) ReadCapacityGuardedWorkload(context.Context, cfg.NamespaceRef, cfg.WorkloadRef, []string) (CapacityNamespaceProtection, CapacityWorkloadObservation, error) {
	f.calls++
	if f.calls <= len(f.errs) && f.errs[f.calls-1] != nil {
		return CapacityNamespaceProtection{}, CapacityWorkloadObservation{}, f.errs[f.calls-1]
	}
	return f.guard, f.workload, nil
}

// A guarded read that finds no free standby is retried exactly once after
// the bounded wait, only while the step's deadline leaves room; any other
// failure is not retried.
func TestCapacityGuardedReadRetriesOnlyNoStandbyOnce(t *testing.T) {
	saved := capacityStandbyRetryWait
	capacityStandbyRetryWait = 10 * time.Millisecond
	t.Cleanup(func() { capacityStandbyRetryWait = saved })
	noStandby := errors.Join(cfg.ErrUnavailable, ErrCapacityNoStandby)
	for name, c := range map[string]struct {
		errs  []error
		step  time.Duration
		calls int
		ok    bool
	}{
		"retried once":         {[]error{noStandby}, 5 * time.Second, 2, true},
		"second absence fails": {[]error{noStandby, noStandby}, 5 * time.Second, 2, false},
		"other failure":        {[]error{cfg.ErrUnavailable}, 5 * time.Second, 1, false},
		"no room left":         {[]error{noStandby}, time.Second, 1, false},
	} {
		t.Run(name, func(t *testing.T) {
			s, f, _, cluster, _ := capacityWorkFixture()
			s.Now = time.Now
			reads := &capacityStandbyReads{capacityWorkFacts: f, errs: c.errs}
			cluster.Guarded = reads
			ctx, cancel := context.WithTimeout(context.Background(), c.step)
			defer cancel()
			_, err := s.ReadGuardedCandidate(ctx, cluster, f.workload.Namespace.Namespace, f.workload.Workload)
			if reads.calls != c.calls || (err == nil) != c.ok {
				t.Fatal("guarded reads", reads.calls, err)
			}
		})
	}
}
