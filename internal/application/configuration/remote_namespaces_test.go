package configuration

import (
	"context"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/configuration"
)

const remoteCluster = "22222222-2222-4222-8222-222222222222"

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
