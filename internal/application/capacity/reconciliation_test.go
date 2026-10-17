package capacity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

func TestCapacityCurrentSourceNeverRenewsOrAliasesAnIssuedObservation(t *testing.T) {
	_, f := capacityObserverTestFixture()
	var current capacityCurrentSource
	defer current.clear()
	if err := current.publish(context.Background(), f.accepted, f.now); err != nil {
		t.Fatal(err)
	}
	owner, first, ok := current.read(f.now)
	if !ok {
		t.Fatal("first current source unavailable")
	}
	first.Observation.Snapshot.Policies[0].Scope.NamespaceLabels["team"] = "mutated"
	_, independent, ok := current.read(f.now)
	if !ok || independent.Observation.Snapshot.Policies[0].Scope.NamespaceLabels["team"] == "mutated" {
		t.Fatal("returned source aliases protected snapshot")
	}
	oldEnd := independent.FreshUntil
	updated := independent
	updated.ObservedAt = updated.ObservedAt.Add(time.Second)
	updated.FreshUntil = updated.FreshUntil.Add(time.Second)
	updated.Observation.Snapshot.ObservedAt = updated.Observation.Snapshot.ObservedAt.Add(time.Second)
	updated.Observation.Snapshot.FreshUntil = updated.Observation.Snapshot.FreshUntil.Add(time.Second)
	if err := current.publish(context.Background(), updated, f.now.Add(time.Second)); err != nil || owner.Err() != nil || !independent.FreshUntil.Equal(oldEnd) || independent.Valid(oldEnd) {
		t.Fatal("heartbeat changed or renewed original observation", err)
	}
	updated.Revision++
	if err := current.publish(context.Background(), updated, f.now.Add(time.Second)); err != nil || owner.Err() == nil {
		t.Fatal("known changed revision did not cancel prior work", err)
	}
	newOwner, _, ok := current.read(f.now.Add(time.Second))
	if !ok {
		t.Fatal("new current observation unavailable")
	}
	current.clear()
	if newOwner.Err() == nil {
		t.Fatal("source failure left work running")
	}
}

type capacityRuntimeReader struct {
	discovered       atomic.Int64
	entered, release chan struct{}
	pages            []CapacityWorkloadPage
	page             int
	guard            CapacityNamespaceProtection
	recovery         artifact.RecoveryProof
}

func (f *capacityRuntimeReader) DiscoverCapacityNamespaces(ctx context.Context, _ string) (CapacityNamespacePage, error) {
	f.discovered.Add(1)
	if f.entered != nil {
		close(f.entered)
		<-f.release // Deliberately uncooperative child: shutdown must actually join.
	}
	return CapacityNamespacePage{ResourceVersion: "ns-1", Namespaces: []cfg.NamespaceRef{{Name: "app", UID: "app-uid"}}}, ctx.Err()
}
func (f *capacityRuntimeReader) DiscoverCapacityWorkloads(ctx context.Context, _ cfg.NamespaceRef, kind, _ string) (CapacityWorkloadPage, error) {
	f.discovered.Add(1)
	if f.page < len(f.pages) {
		v := f.pages[f.page]
		f.page++
		return v, ctx.Err()
	}
	return CapacityWorkloadPage{ResourceVersion: "empty-" + kind}, ctx.Err()
}
func (f *capacityRuntimeReader) ReadCapacityWorkload(context.Context, cfg.NamespaceRef, cfg.WorkloadRef, []string) (CapacityWorkloadObservation, error) {
	return CapacityWorkloadObservation{}, cfg.ErrUnavailable
}
func (f *capacityRuntimeReader) CapacityNamespaceProtection(ctx context.Context) (CapacityNamespaceProtection, error) {
	return f.guard, ctx.Err()
}
func (f *capacityRuntimeReader) ReadCapacityPermissions(context.Context, artifact.RecoveryProof) (AcceptedCapacityPermissions, error) {
	return AcceptedCapacityPermissions{}, cfg.ErrUnavailable
}
func (f *capacityRuntimeReader) DownloadPolicy(context.Context) (privacy.DownloadPolicy, error) {
	return privacy.DownloadPolicy{}, cfg.ErrUnavailable
}
func (f *capacityRuntimeReader) RefreshCapacityEnrollment(context.Context, EnrollmentObservation, Enrollment) error {
	return cfg.ErrUnavailable
}
func (f *capacityRuntimeReader) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, ctx.Err()
}

func TestCapacityDiscoveryBoundsPagesAndRejectsChangedContinuation(t *testing.T) {
	for _, mode := range []string{"valid", "changed-list", "oversized", "wrong-kind", "repeated-cursor"} {
		t.Run(mode, func(t *testing.T) {
			first := CapacityWorkloadPage{ResourceVersion: "work-1", Continue: "next", Workloads: []cfg.WorkloadRef{{Kind: "Deployment", Name: "first", UID: "first-uid"}}}
			second := CapacityWorkloadPage{ResourceVersion: "work-1", Workloads: []cfg.WorkloadRef{{Kind: "Deployment", Name: "second", UID: "second-uid"}}}
			switch mode {
			case "changed-list":
				second.ResourceVersion = "work-2"
			case "oversized":
				second.Workloads = make([]cfg.WorkloadRef, CapacityDiscoveryPageSize+1)
			case "wrong-kind":
				second.Workloads[0].Kind = "Pod"
			case "repeated-cursor":
				second.Continue = "next"
			}
			reader := &capacityRuntimeReader{pages: []CapacityWorkloadPage{first, second}}
			var cursor capacityDiscoveryCursor
			for i := 0; i < 2; i++ {
				if _, _, found, err := cursor.next(context.Background(), reader); err != nil || found {
					t.Fatal("LIST became an effect candidate", err)
				}
			}
			if _, v, found, err := cursor.next(context.Background(), reader); err != nil || !found || v.UID != "first-uid" {
				t.Fatal("first exact candidate missing", err)
			}
			if _, _, found, err := cursor.next(context.Background(), reader); found || (mode == "valid") != (err == nil) {
				t.Fatal("invalid continuation accepted or valid one rejected", err)
			}
			if mode == "valid" {
				if _, v, found, err := cursor.next(context.Background(), reader); err != nil || !found || v.UID != "second-uid" {
					t.Fatal("second exact candidate missing", err)
				}
			}
		})
	}
}

func TestCapacityReconcilerCancellationJoinsBlockedDiscoveryOwner(t *testing.T) {
	source, f := capacityObserverTestFixture()
	q, _ := capacityQualificationFixture()
	q.ID, q.Digest = f.accepted.QualificationID, f.accepted.QualificationDigest
	q.RootBacking.RootID, q.RootBacking.InstallationID = f.accepted.RootID, f.accepted.InstallationID
	q.RootBacking.QualificationID, q.RootBacking.QualificationDigest = q.ID, q.Digest
	reader := &capacityRuntimeReader{entered: make(chan struct{}), release: make(chan struct{}), recovery: f.recovery}
	work := &CapacityWorkReconciler{Qualification: q, Recovery: reader, Permissions: reader, Processing: reader, Root: &RootBackingCoordinator{}, Enrollment: &EnrollmentCoordinator{}, Bindings: reader, Now: func() time.Time { return f.now }}
	runner := CapacityReconciler{Source: source, Work: work, Clusters: []CapacityClusterReaders{{ClusterID: q.NamespaceGuards[0].ClusterID, Workloads: reader, Guard: reader}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-reader.entered:
	case err := <-done:
		t.Fatal("runner stopped before owned child", err)
	case <-time.After(time.Second):
		cancel()
		t.Fatal("discovery did not start")
	}
	cancel()
	select {
	case err := <-done:
		close(reader.release)
		t.Fatal("returned while child was still running", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("joined shutdown result", err)
		}
	case <-time.After(time.Second):
		t.Fatal("completed child was not joined")
	}
}

// ADR-197: a paced (regional) cluster starts no iteration within Pace of its
// previous one's end; an unpaced one keeps the 250 ms local cadence.
func TestCapacityReconcilerPacesRegionalClusterIterations(t *testing.T) {
	for _, pace := range []time.Duration{0, time.Hour} {
		source, f := capacityObserverTestFixture()
		q, _ := capacityQualificationFixture()
		q.ID, q.Digest = f.accepted.QualificationID, f.accepted.QualificationDigest
		q.RootBacking.RootID, q.RootBacking.InstallationID = f.accepted.RootID, f.accepted.InstallationID
		q.RootBacking.QualificationID, q.RootBacking.QualificationDigest = q.ID, q.Digest
		reader := &capacityRuntimeReader{recovery: f.recovery}
		work := &CapacityWorkReconciler{Qualification: q, Recovery: reader, Permissions: reader, Processing: reader, Root: &RootBackingCoordinator{}, Enrollment: &EnrollmentCoordinator{}, Bindings: reader, Now: func() time.Time { return f.now }}
		runner := CapacityReconciler{Source: source, Work: work, Clusters: []CapacityClusterReaders{{ClusterID: q.NamespaceGuards[0].ClusterID, Workloads: reader, Guard: reader, Pace: pace}}}
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		_ = runner.Run(ctx)
		cancel()
		if n := reader.discovered.Load(); pace > 0 && n != 1 || pace == 0 && n < 2 {
			t.Fatal("paced cluster iterations", pace, n)
		}
	}
}

// ADR-197: a regional candidate's read starts only with enough source
// freshness left; otherwise it waits on later ticks without consuming the
// candidate or reconciling anything.
func TestCapacityReconcilerStartsRegionalReadsOnlyWithEnoughSource(t *testing.T) {
	for _, window := range []time.Duration{time.Hour, time.Millisecond} {
		source, f := capacityObserverTestFixture()
		q, _ := capacityQualificationFixture()
		q.ID, q.Digest = f.accepted.QualificationID, f.accepted.QualificationDigest
		q.RootBacking.RootID, q.RootBacking.InstallationID = f.accepted.RootID, f.accepted.InstallationID
		q.RootBacking.QualificationID, q.RootBacking.QualificationDigest = q.ID, q.Digest
		reader := &capacityRuntimeReader{recovery: f.recovery, pages: []CapacityWorkloadPage{{ResourceVersion: "work-1", Workloads: []cfg.WorkloadRef{{Kind: "Deployment", Name: "app", UID: "app-uid"}}}}}
		work := &CapacityWorkReconciler{Qualification: q, Recovery: reader, Permissions: reader, Processing: reader, Root: &RootBackingCoordinator{}, Enrollment: &EnrollmentCoordinator{}, Bindings: reader, Now: func() time.Time { return f.now }}
		var mu sync.Mutex
		stages := map[string]int{}
		report := func(err error, _ time.Duration) {
			step := "ok"
			var s interface{ FixedStep() string }
			if errors.As(err, &s) {
				step = s.FixedStep()
			}
			mu.Lock()
			stages[step]++
			mu.Unlock()
		}
		runner := CapacityReconciler{Source: source, Work: work, Clusters: []CapacityClusterReaders{{ClusterID: q.NamespaceGuards[0].ClusterID, Workloads: reader, Guard: reader, MinSourceWindow: window, Report: report}}}
		_ = source
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		_ = runner.RunWithSourceInvocation(ctx, staticCapacitySource{f.accepted})
		cancel()
		mu.Lock()
		waited, attempted := stages["source-window"], 0
		for k, n := range stages {
			if k != "source-window" {
				attempted += n
			}
		}
		mu.Unlock()
		if window == time.Hour && (waited == 0 || attempted != 0) || window == time.Millisecond && attempted == 0 {
			t.Fatal("source window gate", window, stages)
		}
	}
}

type staticCapacitySource struct{ v AcceptedCapacitySource }

func (s staticCapacitySource) Observe(context.Context) (AcceptedCapacitySource, error) {
	return s.v, nil
}
