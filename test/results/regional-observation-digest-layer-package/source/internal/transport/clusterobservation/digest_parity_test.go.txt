package clusterobservation

import (
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
)

// This is the actual pre-extraction algorithm over the unchanged wire DTO,
// not another call to the new application digest. It pins serialization parity.
func originalObservationDigest(t *testing.T, r fleet.ClusterObservationRequest) artifact.Digest {
	t.Helper()
	b, err := contracts.EncodeClusterObservationRequest(RequestWire(r))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte("asservat-cluster-observation-request/v1\x00"))
	h.Write(b)
	var d artifact.Digest
	copy(d[:], h.Sum(nil))
	return d
}

func TestClusterObservationApplicationDigestPreservesEveryClosedWirePurpose(t *testing.T) {
	base := localRequest()
	base.RequestedAt = time.Date(2026, 10, 13, 10, 12, 30, 123456000, time.FixedZone("offset", 3600))
	base.NotAfter = base.RequestedAt.Add(4500 * time.Millisecond)
	for _, purpose := range []fleet.ClusterObservationPurpose{fleet.ObserveCapacityNamespaceGuard, fleet.ObserveCapacityNamespaces, fleet.ObserveCapacityWorkloads, fleet.ObserveCapacityWorkload} {
		r := base.Clone()
		r.Purpose = purpose
		switch purpose {
		case fleet.ObserveCapacityNamespaces:
			r.Continue = "opaque&amp/<cursor>"
		case fleet.ObserveCapacityWorkloads:
			r.Namespace = cfg.NamespaceRef{Name: "service", UID: localID(31)}
			r.Kind = "Deployment"
			r.Continue = "page-2"
		case fleet.ObserveCapacityWorkload:
			r.Namespace = cfg.NamespaceRef{Name: "service", UID: localID(31)}
			r.Workload = cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: localID(32)}
			r.Keys = []string{"team", "a.example/key"}
		}
		t.Run(string(purpose), func(t *testing.T) {
			want := originalObservationDigest(t, r)
			got, err := app.ClusterObservationRequestDigest(r)
			if err != nil || got != want {
				t.Fatal("application digest changed v1 bytes", err)
			}
			wrapped, err := RequestDigest(r)
			if err != nil || wrapped != want {
				t.Fatal("transport wrapper changed digest", err)
			}
			for name, mutate := range map[string]func(*fleet.ClusterObservationRequest){
				"request":   func(x *fleet.ClusterObservationRequest) { x.ID = localID(70) },
				"challenge": func(x *fleet.ClusterObservationRequest) { x.Challenge = localID(71) },
				"root":      func(x *fleet.ClusterObservationRequest) { x.RootID = localID(72) },
				"cluster":   func(x *fleet.ClusterObservationRequest) { x.ClusterID = localID(73) },
				"start":     func(x *fleet.ClusterObservationRequest) { x.RequestedAt = x.RequestedAt.Add(time.Microsecond) },
				"end":       func(x *fleet.ClusterObservationRequest) { x.NotAfter = x.NotAfter.Add(-time.Microsecond) },
				"namespace": func(x *fleet.ClusterObservationRequest) { x.Namespace.UID = localID(74) },
				"workload":  func(x *fleet.ClusterObservationRequest) { x.Workload.UID = localID(75) },
				"kind":      func(x *fleet.ClusterObservationRequest) { x.Kind = "StatefulSet" },
				"cursor":    func(x *fleet.ClusterObservationRequest) { x.Continue = "different-page" },
				"keys":      func(x *fleet.ClusterObservationRequest) { x.Keys = append(x.Keys, "other") },
			} {
				x := r.Clone()
				mutate(&x)
				got, err := app.ClusterObservationRequestDigest(x)
				if err != nil || got == want || got != originalObservationDigest(t, x) {
					t.Fatal("mutation omitted or serialized differently", name, err)
				}
			}
		})
	}
}

func TestClusterObservationApplicationDigestPreservesEmptyAndOrderingSemantics(t *testing.T) {
	r := localRequest()
	baseline := originalObservationDigest(t, r)
	r.Keys = []string{}
	d, err := app.ClusterObservationRequestDigest(r)
	if err != nil || d != baseline {
		t.Fatal("nil versus empty optional keys changed", err)
	}
	r.Keys = []string{"team", "region"}
	forward, err := app.ClusterObservationRequestDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(r.Keys)
	reverse, err := app.ClusterObservationRequestDigest(r)
	if err != nil || reverse == forward || reverse != originalObservationDigest(t, r) {
		t.Fatal("ordered keys normalized or changed", err)
	}
	r.Keys = nil
	r.Namespace = cfg.NamespaceRef{Name: "service"}
	partial, err := app.ClusterObservationRequestDigest(r)
	if err != nil || partial == baseline || partial != originalObservationDigest(t, r) {
		t.Fatal("partial optional selector silently omitted", err)
	}
}
