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
	if _, err := s.refreshRemoteBindings(ctx); err != nil {
		t.Fatal(err)
	}
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
	// A failed read leaves the cache intact but stops the epoch. An old
	// valid delivery still grants until the connector replaces it.
	reader.err = errors.New("sql unavailable")
	if _, err := s.refreshRemoteBindings(ctx); !errors.Is(err, reader.err) {
		t.Fatal("missing remote binding read error", err)
	}
	reader.err = nil
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
	if _, err := s.refreshRemoteBindings(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.remoteBindings[remoteCluster].Bindings) != 3 {
		t.Fatal("older delivery replaced the newer one")
	}
	reader.deliveries = []value.RemoteBindings{{ClusterID: remoteCluster, ObservedAt: s.r.Now()}}
	if _, err := s.refreshRemoteBindings(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := remoteBases(f.accepted[len(f.accepted)-1], remoteCluster); len(got) != 0 {
		t.Fatalf("empty delivery kept bindings: %v", got)
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
	for name, bad := range map[string]value.RemoteBindings{"duplicate name": dup, "other cluster": other} {
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

func TestRemoteBindingReplacementAtSameTimeAndExplicitWithdrawal(t *testing.T) {
	_, _, s, ctx := inheritanceRun(t)
	d := value.RemoteBindings{ClusterID: remoteCluster, ObservedAt: s.r.Now(), Digest: [32]byte{1}, Bindings: []value.Binding{remoteBinding(remoteCluster, "before", "uid-allow", "Allow")}}
	reader := &remoteBindingFixture{deliveries: []value.RemoteBindings{d}}
	s.r.RemoteBindings = reader
	for _, expected := range []bool{true, false} {
		if changed, err := s.refreshRemoteBindings(ctx); err != nil || changed != expected {
			t.Fatal("initial/unchanged delivery", changed, err)
		}
	}
	d.Digest[0]++
	d.Bindings = nil
	reader.deliveries = []value.RemoteBindings{d}
	if changed, err := s.refreshRemoteBindings(ctx); err != nil || !changed || len(s.remoteBindings[remoteCluster].Bindings) != 0 {
		t.Fatal("changed digest at same observation time", changed, err)
	}
	reader.deliveries = nil
	if changed, err := s.refreshRemoteBindings(ctx); err != nil || !changed || len(s.remoteBindings) != 0 {
		t.Fatal("withdrawn delivery retained", changed, err)
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

type remoteBindingReadFunc func(context.Context) ([]value.RemoteBindings, error)

func (f remoteBindingReadFunc) RemoteBindings(ctx context.Context) ([]value.RemoteBindings, error) {
	return f(ctx)
}

func TestRemoteBindingReadFailureSuspendsBeforeAcceptance(t *testing.T) {
	for _, fail := range []string{"startup", "notification"} {
		t.Run(fail, func(t *testing.T) {
			f, r := reconciliationTest(t)
			changes := make(chan struct{}, 1)
			changes <- struct{}{}
			r.RemoteBindingChanges = changes
			cause := errors.New("remote database unavailable")
			reads := 0
			r.RemoteBindings = remoteBindingReadFunc(func(ctx context.Context) ([]value.RemoteBindings, error) {
				reads++
				if fail == "startup" || reads > 1 {
					return nil, cause
				}
				return []value.RemoteBindings{{ClusterID: remoteCluster, ObservedAt: r.Now(), Bindings: []value.Binding{remoteBinding(remoteCluster, "readers", "uid-reader", "Allow")}}}, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			result := r.RunEpoch(ctx)
			if !errors.Is(result.Err, cause) || !result.Suspended || len(f.accepted) != reads-1 {
				t.Fatalf("failed read: %v, suspended %t, %d reads, %d snapshots accepted", result.Err, result.Suspended, reads, len(f.accepted))
			}
			if fail == "notification" && (reads != 2 || remoteBases(f.accepted[0], remoteCluster)["readers"] != "Allow") {
				t.Fatal("expected an allow only in the initial snapshot")
			}
		})
	}
}
