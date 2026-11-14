package capacity

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type remoteStore struct {
	c   RemoteCapacity
	err error
}

func (s remoteStore) RemoteCapacity(_ context.Context, cluster string) (RemoteCapacity, error) {
	if s.err != nil || cluster != s.c.ClusterID {
		return RemoteCapacity{}, cfg.ErrUnavailable
	}
	return s.c, nil
}

const remoteTestCluster = "40000000-0000-4000-8000-000000000001"

func remoteTestCapacity(at time.Time) RemoteCapacity {
	return RemoteCapacity{ClusterID: remoteTestCluster, ObservedAt: at, Namespaces: []RemoteCapacityNamespace{{Namespace: cfg.NamespaceRef{Name: "payments", UID: "ns-1"}, ResourceVersion: "7",
		Labels: map[string]string{"asservat-trial": "true", "other": "x"}, Workloads: []RemoteCapacityWorkload{{Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "w-1"}, ResourceVersion: "9"}}}}}
}

// ADR-330: a joined cluster's reads come from its latest delivery, which
// stays current until replaced, under the qualification pin's keys only.
func TestRemoteCapacityReaderServesTheCurrentDelivery(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	now := at.Add(2 * time.Second)
	pin := CapacityNamespaceQualification{ClusterID: remoteTestCluster, Digest: artifact.Digest{1}, Keys: []string{"asservat-trial"}}
	r := RemoteCapacityReader{Store: remoteStore{c: remoteTestCapacity(at)}, Pin: pin, Now: func() time.Time { return now }}
	ctx := context.Background()
	ns := cfg.NamespaceRef{Name: "payments", UID: "ns-1"}
	ref := cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "w-1"}
	page, err := r.DiscoverCapacityNamespaces(ctx, "")
	if err != nil || len(page.Namespaces) != 1 || page.Namespaces[0] != ns {
		t.Fatal("namespaces", page, err)
	}
	if w, err := r.DiscoverCapacityWorkloads(ctx, ns, "Deployment", ""); err != nil || len(w.Workloads) != 1 || w.Workloads[0] != ref {
		t.Fatal("workloads", w, err)
	}
	if w, err := r.DiscoverCapacityWorkloads(ctx, ns, "StatefulSet", ""); err != nil || len(w.Workloads) != 0 {
		t.Fatal("other kind", w, err)
	}
	guard, workload, err := r.ReadCapacityGuardedWorkload(ctx, ns, ref, pin.Keys)
	if err != nil || guard.Digest != pin.Digest || !guard.FreshUntil.Equal(now.Add(CapacitySourceInterval)) || workload.Namespace.Labels["asservat-trial"] != "true" || len(workload.Namespace.Labels) != 1 || workload.WorkloadResourceVersion != "9" {
		t.Fatal("guarded read", guard, workload, err)
	}
	if _, err = r.ReadCapacityWorkload(ctx, ns, ref, []string{"other"}); err == nil {
		t.Fatal("keys other than the pin's accepted")
	}
	if _, err = r.ReadCapacityWorkload(ctx, ns, cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "w-2"}, pin.Keys); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("replaced workload", err)
	}
	now = at.Add(time.Hour)
	if g, err := r.CapacityNamespaceProtection(ctx); err != nil || !g.ObservedAt.Equal(now) {
		t.Fatal("an old delivery is no longer current", err)
	}
	r.Store = remoteStore{err: cfg.ErrUnavailable}
	if _, err = r.CapacityNamespaceProtection(ctx); err == nil {
		t.Fatal("no delivery accepted")
	}
	other := remoteTestCapacity(at)
	other.ClusterID = "40000000-0000-4000-8000-000000000002"
	r.Store = remoteStore{c: other}
	if _, err = r.CapacityNamespaceProtection(ctx); err == nil {
		t.Fatal("another cluster's delivery accepted")
	}
}

func TestRemoteCapacityBounds(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	if !remoteTestCapacity(at).Valid() {
		t.Fatal("valid delivery refused")
	}
	for name, mutate := range map[string]func(*RemoteCapacity){
		"cluster":   func(c *RemoteCapacity) { c.ClusterID = "cluster" },
		"time":      func(c *RemoteCapacity) { c.ObservedAt = time.Time{} },
		"duplicate": func(c *RemoteCapacity) { c.Namespaces = append(c.Namespaces, c.Namespaces[0]) },
		"kind":      func(c *RemoteCapacity) { c.Namespaces[0].Workloads[0].Workload.Kind = "Job" },
		"duplicate workload": func(c *RemoteCapacity) {
			c.Namespaces[0].Workloads = append(c.Namespaces[0].Workloads, c.Namespaces[0].Workloads[0])
		},
		"label value": func(c *RemoteCapacity) { c.Namespaces[0].Labels["x"] = string(make([]byte, 64)) },
	} {
		c := remoteTestCapacity(at)
		mutate(&c)
		if c.Valid() {
			t.Errorf("%s accepted", name)
		}
	}
}
