package configuration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

type remoteBindingFixture struct {
	deliveries []value.RemoteBindings
	err        error
}

func (r *remoteBindingFixture) RemoteBindings(context.Context) ([]value.RemoteBindings, error) {
	return r.deliveries, r.err
}

func remoteBinding(cluster, name, uid, effect string) value.Binding {
	ns := value.NamespaceRef{Name: "payments", UID: "payments-" + cluster[:8]}
	return value.Binding{Resource: value.Resource{ClusterID: cluster, Namespace: ns.Name, NamespaceUID: ns.UID, Kind: "AccessBinding", Name: name, UID: uid, Generation: 1, ResourceVersion: "rv-" + uid, SpecDigest: artifact.Digest{9}},
		Scope: value.Scope{ClusterID: cluster, Namespace: ns}, Effect: effect, Subjects: []value.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "team-" + name}}, Roles: []string{"evidence-reader"}}
}

func remoteBases(b value.PermissionBatch, cluster string) map[string]string {
	out := map[string]string{}
	for _, p := range b.Bases {
		if p.Resource.Kind == "AccessBinding" && p.Scope.ClusterID == cluster {
			if p.Continuous {
				out[p.Resource.Name] = "continuous"
				continue
			}
			out[p.Resource.Name] = p.Effect
		}
	}
	return out
}

// ADR-329: a joined cluster's delivered AccessBindings grant and deny in that
// cluster like the hub cluster's. The last delivery stays in effect, allows
// included, until a newer one replaces it (connector liveness is not
// authority). The hub cluster's own row and invalid deliveries are ignored,
// and a failed read keeps state.
func TestReconcilerAcceptsRemoteClusterBindings(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	now := s.r.Now()
	invalid := remoteBinding(remoteCluster, "broken", "uid-broken", "")
	invalid.Invalid, invalid.Subjects, invalid.Roles = true, nil, nil
	delivery := value.RemoteBindings{ClusterID: remoteCluster, ObservedAt: now, Bindings: []value.Binding{remoteBinding(remoteCluster, "readers", "uid-allow", "Allow"), remoteBinding(remoteCluster, "blocked", "uid-deny", "Deny"), invalid}}
	own := value.RemoteBindings{ClusterID: inheritanceCluster, ObservedAt: now, Bindings: []value.Binding{remoteBinding(inheritanceCluster, "spoof", "uid-own", "Allow")}}
	foreign := value.RemoteBindings{ClusterID: "33333333-3333-4333-8333-333333333333", ObservedAt: now, Bindings: []value.Binding{remoteBinding(remoteCluster, "mislabelled", "uid-x", "Allow")}}
	reader := &remoteBindingFixture{deliveries: []value.RemoteBindings{delivery, own, foreign}}
	s.r.RemoteBindings = reader
	s.refreshRemoteBindings(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	b := f.accepted[len(f.accepted)-1]
	if got := remoteBases(b, remoteCluster); len(got) != 2 || got["readers"] != "Allow" || got["blocked"] != "Deny" {
		t.Fatalf("remote bindings not accepted as in the hub cluster: %v", got)
	}
	for _, p := range b.Bases {
		if p.Resource.Name == "spoof" || p.Resource.Name == "mislabelled" {
			t.Fatalf("hub-cluster row or mislabelled delivery accepted: %+v", p.Resource)
		}
	}
	// A failed read keeps the last delivery, and an old delivery keeps its
	// allows: no expiry.
	reader.err = errors.New("sql unavailable")
	s.refreshRemoteBindings(ctx)
	d := s.remoteBindings[remoteCluster]
	d.ObservedAt = s.r.Now().Add(-time.Hour)
	s.remoteBindings[remoteCluster] = d
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := remoteBases(f.accepted[len(f.accepted)-1], remoteCluster); len(got) != 2 || got["readers"] != "Allow" || got["blocked"] != "Deny" {
		t.Fatalf("old delivery: want both bindings, got %v", got)
	}
	// An older delivery never replaces a newer one; a newer one without the
	// deny removes it.
	reader.err = nil
	reader.deliveries = []value.RemoteBindings{{ClusterID: remoteCluster, ObservedAt: d.ObservedAt.Add(-time.Second)}}
	s.refreshRemoteBindings(ctx)
	if len(s.remoteBindings[remoteCluster].Bindings) != 3 {
		t.Fatal("older delivery replaced the newer one")
	}
	reader.deliveries = []value.RemoteBindings{{ClusterID: remoteCluster, ObservedAt: s.r.Now()}}
	s.refreshRemoteBindings(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := remoteBases(f.accepted[len(f.accepted)-1], remoteCluster); len(got) != 0 {
		t.Fatalf("empty delivery kept bindings: %v", got)
	}
}

// A cluster whose bindings exceed the stream's remaining budget contributes
// nothing rather than a partial set.
func TestReconcilerSkipsRemoteClusterOverBudget(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	var many []value.Binding
	for i := range 1024 {
		name := "b" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676))
		many = append(many, remoteBinding(remoteCluster, name, "uid-"+name, "Allow"))
	}
	delivery := value.RemoteBindings{ClusterID: remoteCluster, ObservedAt: s.r.Now(), Bindings: many}
	if !delivery.Valid() {
		t.Fatal("fixture delivery invalid")
	}
	s.r.RemoteBindings = &remoteBindingFixture{deliveries: []value.RemoteBindings{delivery}}
	s.refreshRemoteBindings(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := remoteBases(f.accepted[len(f.accepted)-1], remoteCluster); len(got) != 0 {
		t.Fatalf("partial remote cluster accepted: %d bases", len(got))
	}
}

func TestRemoteBindingsValidBounds(t *testing.T) {
	d := value.RemoteBindings{ClusterID: remoteCluster, ObservedAt: time.Now(), Bindings: []value.Binding{remoteBinding(remoteCluster, "a", "uid-a", "Allow")}}
	if !d.Valid() {
		t.Fatal("valid delivery refused")
	}
	dup := d
	dup.Bindings = append(dup.Bindings, remoteBinding(remoteCluster, "a", "uid-b", "Allow"))
	other := d
	other.Bindings = []value.Binding{remoteBinding(inheritanceCluster, "a", "uid-a", "Allow")}
	rows := d
	b := remoteBinding(remoteCluster, "wide", "uid-w", "Allow")
	for i := range 4097 {
		b.Subjects = append(b.Subjects, value.Subject{Kind: "User", Issuer: "https://id.example.test", ID: string(rune(i))})
	}
	rows.Bindings = []value.Binding{b}
	for name, bad := range map[string]value.RemoteBindings{"duplicate name": dup, "other cluster": other, "rows": rows} {
		if bad.Valid() {
			t.Fatal(name)
		}
	}
}

// Deliveries are reread on a change signal, not on the reconciler's tick.
func TestReconcilerRereadsRemoteBindingsOnSignal(t *testing.T) {
	_, _, s, ctx := inheritanceRun(t)
	now := s.r.Now()
	reader := &countingRemoteBindings{remoteBindingFixture: remoteBindingFixture{deliveries: []value.RemoteBindings{{ClusterID: remoteCluster, ObservedAt: now, Bindings: []value.Binding{remoteBinding(remoteCluster, "readers", "uid-allow", "Allow")}}}}}
	s.r.RemoteBindings = reader
	if err := s.refresh(ctx); err != nil && !errors.Is(err, errWatchBehind) {
		t.Fatal(err)
	}
	if reader.reads != 0 {
		t.Fatal("the reconciler tick reread the deliveries", reader.reads)
	}
}

type countingRemoteBindings struct {
	remoteBindingFixture
	reads int
}

func (r *countingRemoteBindings) RemoteBindings(ctx context.Context) ([]value.RemoteBindings, error) {
	r.reads++
	return r.remoteBindingFixture.RemoteBindings(ctx)
}
