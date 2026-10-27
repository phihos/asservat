package configuration

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

const remoteCluster = "22222222-2222-4222-8222-222222222222"

// ADR-247: journal versions stay equal across writes that keep every
// observed value and change with A -> B -> A; a new journal never continues.
func TestNamespaceJournalVersionsOnlyObservedChanges(t *testing.T) {
	keys := value.NamespaceKeys{Labels: []string{"managed"}, Annotations: []string{"owner"}}
	j, err := NewNamespaceJournal(value.NamespaceList{ClusterID: inheritanceCluster, ResourceVersion: "10", Keys: keys, ObservedAt: time.Now(), Namespaces: []value.ObservedNamespace{observedNamespace("payments", "p", "1", "payments")}})
	if err != nil {
		t.Fatal(err)
	}
	version := func() string { return j.VersionedObservation("j1").Namespaces[0].ResourceVersion }
	first := version()
	same := observedNamespace("payments", "p", "11", "payments")
	if err = j.Apply(value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: "11", Namespace: &same}); err != nil || version() != first || j.Sequence() != 0 {
		t.Fatalf("unrelated write changed the version: %v %s", err, version())
	}
	for i, owner := range []string{"payroll", "payments"} {
		n := observedNamespace("payments", "p", "1"+string(rune('2'+i)), owner)
		if err = j.Apply(value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: n.ResourceVersion, Namespace: &n}); err != nil {
			t.Fatal(err)
		}
	}
	if version() == first || version() != "j1:2" || j.Sequence() != 2 {
		t.Fatalf("A -> B -> A kept the version: %s", version())
	}
	if j.VersionedObservation("j2").Namespaces[0].ResourceVersion == version() {
		t.Fatal("another journal continued the version")
	}
}

type remoteFixture struct {
	list  value.NamespaceList
	err   error
	calls int
}

func (r *remoteFixture) RemoteNamespaces(_ context.Context, cluster string, keys value.NamespaceKeys) (value.NamespaceList, error) {
	r.calls++
	l := r.list
	l.ClusterID, l.Keys = cluster, keys
	return l, r.err
}

// A source of another joined cluster is evaluated against its connector
// journal: exact versions, never continuity; a failed read keeps the last
// state until it lapses with its own ObservedAt.
func TestReconcilerInheritsRemoteClusterJournal(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	src := inheritanceSource()
	src.ClusterID = remoteCluster
	now := s.r.Now()
	remote := &remoteFixture{list: value.NamespaceList{ResourceVersion: "j1", ObservedAt: now, Namespaces: []value.ObservedNamespace{observedNamespace("payments", "payments-uid", "j1:0", "payments")}}}
	s.r.Remote, s.sources = remote, []value.Source{src}
	s.refreshRemote(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	b := f.accepted[len(f.accepted)-1]
	owners, continuous := inheritedOwners(b)
	if len(owners) != 2 || continuous || len(b.RemoteNamespaces) != 1 || b.RemoteNamespaces[0].ClusterID != remoteCluster || b.RemoteNamespaces[0].Namespaces[0].ResourceVersion != "" {
		t.Fatalf("remote source not granted from its journal: %v continuous=%v %+v", owners, continuous, b.RemoteNamespaces)
	}
	for _, p := range b.Bases {
		if p.Resource.Kind == "PermissionSource" && (p.Scope.ClusterID != remoteCluster || p.ObservationVersion != "j1:0") {
			t.Fatalf("basis not bound to the remote journal version: %+v", p)
		}
	}
	// Within the refresh interval no reread; a failed reread keeps the state.
	s.refreshRemote(ctx)
	if remote.calls != 1 {
		t.Fatal("reread before the refresh interval", remote.calls)
	}
	s.remote[remoteCluster].fetchedAt = now.Add(-RemoteNamespaceRefresh)
	remote.err = errors.New("connector unavailable")
	s.refreshRemote(ctx)
	if remote.calls != 2 || s.remote[remoteCluster] == nil {
		t.Fatal("failed reread dropped the last journal state")
	}
	s.remote[remoteCluster].observedAt = now.Add(-src.MaxDecisionAge)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	b = f.accepted[len(f.accepted)-1]
	if o, _ := inheritedOwners(b); len(o) != 0 || len(b.UnavailableSources) != 1 || len(b.RemoteNamespaces) != 0 {
		t.Fatalf("lapsed remote journal still granted: %+v", b)
	}
}

// Concurrent readers of different key sets restart the journal without
// leaking a feed or reporting one key set's journal for another (Gitar
// finding on PR #90): every snapshot names only requested keys and Close
// leaves no feed running.
func TestNamespaceJournalServiceConcurrentRestarts(t *testing.T) {
	base := runtime.NumGoroutine()
	ns := &namespaceFixture{list: value.NamespaceList{ClusterID: inheritanceCluster, ResourceVersion: "10", Namespaces: []value.ObservedNamespace{observedNamespace("payments", "payments-uid", "1", "payments")}}, now: time.Now}
	s := &NamespaceJournalService{Observer: ns, Now: time.Now}
	sets := []value.NamespaceKeys{{Labels: []string{"managed"}, Annotations: []string{"owner"}}, {Labels: []string{"managed", "zone"}, Annotations: []string{"owner"}}}
	var wg sync.WaitGroup
	var bad atomic.Int32
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				keys := sets[(g+i)%2]
				snap, err := s.Snapshot(context.Background(), keys)
				if err != nil {
					continue
				}
				for _, n := range snap.Namespaces {
					if !n.Valid(keys, true) || !strings.HasPrefix(n.ResourceVersion, snap.Journal+":") {
						bad.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()
	s.Close()
	if bad.Load() != 0 {
		t.Fatal("a snapshot reported another key set's journal", bad.Load())
	}
	for end := time.Now().Add(3 * time.Second); runtime.NumGoroutine() > base && time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
	}
	if n := runtime.NumGoroutine(); n > base {
		t.Fatal("restarted feeds kept running after Close", n, base)
	}
}

// The connector journal service starts on the first read, follows every
// transition and reports journal versions; Close joins it.
func TestNamespaceJournalServiceSnapshotsFollowedJournal(t *testing.T) {
	same := observedNamespace("payments", "payments-uid", "2", "payments")
	changed := observedNamespace("payments", "payments-uid", "3", "payroll")
	ns := &namespaceFixture{list: value.NamespaceList{ClusterID: inheritanceCluster, ResourceVersion: "10", Namespaces: []value.ObservedNamespace{observedNamespace("payments", "payments-uid", "1", "payments")}},
		events: []value.NamespaceEvent{{Type: "MODIFIED", ResourceVersion: "2", Namespace: &same}, {Type: "MODIFIED", ResourceVersion: "3", Namespace: &changed}}, now: time.Now}
	s := &NamespaceJournalService{Observer: ns, Now: time.Now}
	defer s.Close()
	keys := value.NamespaceKeys{Labels: []string{"managed"}, Annotations: []string{"owner"}}
	var snap NamespaceJournalSnapshot
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if snap, err = s.Snapshot(context.Background(), keys); err == nil && snap.Sequence == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if snap.Sequence != 1 || len(snap.Namespaces) != 1 || snap.Namespaces[0].ResourceVersion != snap.Journal+":1" {
		t.Fatalf("journal did not follow the observed change only: %+v", snap)
	}
	if _, err := s.Snapshot(context.Background(), value.NamespaceKeys{}); !errors.Is(err, value.ErrInvalid) {
		t.Fatal("empty key set accepted", err)
	}
}
