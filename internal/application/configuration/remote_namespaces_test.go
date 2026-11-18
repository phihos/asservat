package configuration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
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
}

// ADR-335 D14: a selector-narrowed ClusterAccessBinding of a joined cluster
// is evaluated against that cluster's journal, fetched even while the source
// list is incomplete. A missing journal, a failed first read and a lapsed
// journal leave its labels unknown: the allow grants nothing, the deny
// covers every namespace.
func TestRemoteClusterBindingSelectorFollowsJournal(t *testing.T) {
	_, _, s, ctx := inheritanceRun(t)
	now := s.r.Now()
	binding := func(effect string) value.Binding {
		return value.Binding{Resource: value.Resource{ClusterID: inheritanceCluster, Kind: value.ClusterAccessBindingKind, Name: "sre", UID: "cab-" + effect, Generation: 1, ResourceVersion: "1"},
			Effect: effect, Subjects: []value.Subject{{Kind: "Group", ID: "/sre"}}, Roles: []string{"evidence-reader"}, NamespaceSelector: map[string]string{"managed": "true"}, Scope: value.Scope{ClusterID: remoteCluster, Namespace: value.AllNamespaces}}
	}
	scopes := func(at time.Time) map[string][]string {
		out := map[string][]string{}
		for _, p := range s.inheritance(at).Bases {
			if p.Resource.Kind == value.ClusterAccessBindingKind {
				out[p.Resource.UID] = append(out[p.Resource.UID], p.Scope.Namespace.UID)
			}
		}
		return out
	}
	unknown := func(at time.Time, why string) {
		t.Helper()
		if got := scopes(at); len(got["cab-Allow"]) != 0 || !slices.Equal(got["cab-Deny"], []string{"*"}) {
			t.Fatalf("%s: %v", why, got)
		}
	}
	s.clusterBindings = []value.Binding{binding("Allow"), binding("Deny")}
	s.sources, s.sourcesComplete = nil, false
	unknown(now, "missing journal")
	remote := &remoteFixture{err: errors.New("connector unavailable")}
	s.r.Remote = remote
	s.refreshRemote(ctx)
	if remote.calls != 1 {
		t.Fatal("selector journal not read while sources are incomplete", remote.calls)
	}
	unknown(now, "connector failure")
	remote.err = nil
	remote.list = value.NamespaceList{ResourceVersion: "j1", ObservedAt: now, Namespaces: []value.ObservedNamespace{observedNamespace("payments", "payments-uid", "j1:0", "")}}
	s.remote = nil
	s.refreshRemote(ctx)
	if got := scopes(now); !slices.Equal(got["cab-Allow"], []string{"payments-uid"}) || !slices.Equal(got["cab-Deny"], []string{"payments-uid"}) {
		t.Fatalf("selected namespaces: %v", got)
	}
	unknown(now.Add(authorization.PermissionObservationInterval), "lapsed journal")
}

func TestConfigurationChangeReadsNewRemoteMetadataSource(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	source := inheritanceSource()
	source.ClusterID = remoteCluster
	f.snapshot.Sources = []value.Source{source}
	f.snapshot.ObservedAt = s.r.Now()
	r := &remoteFixture{list: value.NamespaceList{ResourceVersion: "joined", ObservedAt: f.snapshot.ObservedAt, Namespaces: []value.ObservedNamespace{observedNamespace("payments", "payments-uid", "joined:0", "payments")}}}
	s.r.Remote = r
	if err := s.sourceSnapshot(ctx, f.snapshot); err != nil {
		t.Fatal(err)
	}
	latest := f.accepted[len(f.accepted)-1]
	owners, _ := inheritedOwners(latest)
	if r.calls != 1 || len(owners) != 2 || len(latest.RemoteNamespaces) != 1 || latest.RemoteNamespaces[0].ClusterID != remoteCluster {
		t.Fatal("new source was not observed and accepted on the configuration event", r.calls, owners)
	}
}
