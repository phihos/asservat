package capacity

import (
	"context"
	"errors"
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

type capacityDiscoveryRetryReader struct {
	capacityRuntimeReader
	workloads func(context.Context, cfg.NamespaceRef, string, string) (CapacityWorkloadPage, error)
}

func (r *capacityDiscoveryRetryReader) DiscoverCapacityNamespaces(ctx context.Context, _ string) (CapacityNamespacePage, error) {
	return CapacityNamespacePage{ResourceVersion: "namespaces-1", Namespaces: []cfg.NamespaceRef{
		{Name: "app", UID: "app-uid"}, {Name: "later", UID: "later-uid"},
	}}, ctx.Err()
}

func (r *capacityDiscoveryRetryReader) DiscoverCapacityWorkloads(ctx context.Context, ns cfg.NamespaceRef, kind, next string) (CapacityWorkloadPage, error) {
	return r.workloads(ctx, ns, kind, next)
}

// A transient failed LIST must not lose the only Deployment candidate for a
// complete traversal. Retrying is a separate ordinary turn; two consecutive
// failures must still let later kinds/namespaces make progress.
func TestCapacityDiscoveryRetriesFailedPageOnceWithoutSkippingTarget(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		for _, failures := range []int{1, 2} {
			name := "first-page"
			if continuation {
				name = "continuation"
			}
			if failures == 2 {
				name += "/persistent-failure"
			} else {
				name += "/transient-failure"
			}
			t.Run(name, func(t *testing.T) {
				until := time.Now().Add(time.Minute)
				ctx, cancel := context.WithDeadline(context.Background(), until)
				defer cancel()
				app := cfg.NamespaceRef{Name: "app", UID: "app-uid"}
				target := cfg.WorkloadRef{Kind: "Deployment", Name: "target", UID: "target-uid"}
				first := cfg.WorkloadRef{Kind: "Deployment", Name: "first", UID: "first-uid"}
				token := ""
				if continuation {
					token = "original-page-token"
				}
				calls, attempts := 0, 0
				later := false
				reader := &capacityDiscoveryRetryReader{}
				reader.workloads = func(call context.Context, ns cfg.NamespaceRef, kind, next string) (CapacityWorkloadPage, error) {
					calls++
					deadline, ok := call.Deadline()
					if call != ctx || !ok || !deadline.Equal(until) {
						t.Fatal("discovery replaced the original caller or deadline")
					}
					if ns == app && kind == "Deployment" {
						if continuation && calls == 1 {
							if next != "" {
								t.Fatal("first LIST supplied a continuation")
							}
							return CapacityWorkloadPage{ResourceVersion: "work-1", Continue: token, Workloads: []cfg.WorkloadRef{first}}, nil
						}
						if next != token {
							t.Fatalf("retry changed original page token: got %q, want %q", next, token)
						}
						attempts++
						if attempts <= failures {
							return CapacityWorkloadPage{}, cfg.ErrUnavailable
						}
						return CapacityWorkloadPage{ResourceVersion: "work-1", Workloads: []cfg.WorkloadRef{target}}, nil
					}
					if ns.Name == "later" {
						if ns.UID != "later-uid" || kind != "Deployment" || next != "" {
							t.Fatal("later namespace did not start at its original first page")
						}
						later = true
					}
					return CapacityWorkloadPage{ResourceVersion: "empty-1"}, nil
				}
				var cursor capacityDiscoveryCursor
				step := func() (cfg.NamespaceRef, cfg.WorkloadRef, bool, error) {
					t.Helper()
					before := calls
					ns, candidate, found, err := cursor.next(ctx, reader)
					if calls-before > 1 {
						t.Fatal("retry added I/O inside the failed turn")
					}
					return ns, candidate, found, err
				}
				if _, _, found, err := step(); found || err != nil {
					t.Fatal("namespace LIST became a candidate", err)
				}
				if continuation {
					if _, _, found, err := step(); found || err != nil {
						t.Fatal("first page did not load", err)
					}
					if ns, got, found, err := step(); err != nil || !found || ns != app || got != first {
						t.Fatal("first candidate changed or disappeared", err)
					}
				}
				if ns, _, found, err := step(); found || !errors.Is(err, cfg.ErrUnavailable) || ns != app || attempts != 1 {
					t.Fatal("failed page was not refused once in its original scope", err)
				}
				ns, _, found, err := step()
				if attempts != 2 || ns != app || found {
					t.Fatalf("next turn skipped failed page: attempts=%d namespace=%+v found=%v", attempts, ns, found)
				}
				if failures == 1 {
					if err != nil {
						t.Fatal("transient failed page did not recover", err)
					}
					if ns, got, found, err := step(); err != nil || !found || ns != app || got != target {
						t.Fatal("successful retry lost or changed the exact target", err)
					}
				} else if !errors.Is(err, cfg.ErrUnavailable) {
					t.Fatal("second failed LIST was accepted", err)
				}
				for i := 0; i < 6 && !later; i++ {
					if _, _, found, err := step(); err != nil || found {
						t.Fatal("failed page blocked later namespace or replayed a candidate", err)
					}
				}
				if !later || attempts != 2 {
					t.Fatalf("persistent failure pinned namespace or retried without a bound: later=%v attempts=%d", later, attempts)
				}
			})
		}
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

type staticCapacitySource struct{ v AcceptedCapacitySource }

func (s staticCapacitySource) Observe(context.Context) (AcceptedCapacitySource, error) {
	return s.v, nil
}

type staticCapacityDemands []CapacityRefreshDemand

func (d staticCapacityDemands) ReadCapacityRefreshDemands(context.Context) ([]CapacityRefreshDemand, error) {
	return d, nil
}

// ADR-200: a demanded workload is reconciled by the demand lane even while
// discovery is paced away from it; a demand for an unknown cluster is ignored.
func TestCapacityReconcilerDemandLaneReconcilesDemandedWorkload(t *testing.T) {
	for _, known := range []bool{true, false} {
		source, f := capacityObserverTestFixture()
		q, _ := capacityQualificationFixture()
		q.ID, q.Digest = f.accepted.QualificationID, f.accepted.QualificationDigest
		q.RootBacking.RootID, q.RootBacking.InstallationID = f.accepted.RootID, f.accepted.InstallationID
		q.RootBacking.QualificationID, q.RootBacking.QualificationDigest = q.ID, q.Digest
		reader := &capacityRuntimeReader{recovery: f.recovery}
		work := &CapacityWorkReconciler{Qualification: q, Recovery: reader, Permissions: reader, Processing: reader, Root: &RootBackingCoordinator{}, Enrollment: &EnrollmentCoordinator{}, Bindings: reader, Now: func() time.Time { return f.now }}
		cluster := q.NamespaceGuards[0].ClusterID
		demand := CapacityRefreshDemand{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "ns-uid"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "api-uid"}, NotAfter: f.now.Add(time.Minute)}
		if !known {
			demand.ClusterID = "00000000-0000-4000-8000-0000000000ff"
		}
		var reports, unmatched atomic.Int32
		runner := CapacityReconciler{Source: source, Work: work, Clusters: []CapacityClusterReaders{{ClusterID: cluster, Workloads: reader, Guard: reader, Pace: time.Hour}},
			Demands: staticCapacityDemands{demand}, DemandReport: func(_ error, _, _ time.Duration, stage string) {
				if stage == "cluster-unmatched" {
					unmatched.Add(1)
					return
				}
				reports.Add(1)
			}}
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		_ = runner.Run(ctx)
		cancel()
		if !known && unmatched.Load() < 2 {
			t.Fatal("unknown cluster refusal not reported")
		}
		if n := reports.Load(); known && n < 2 || !known && n != 0 {
			t.Fatal("demand lane reconciliations", known, n)
		}
	}
}
