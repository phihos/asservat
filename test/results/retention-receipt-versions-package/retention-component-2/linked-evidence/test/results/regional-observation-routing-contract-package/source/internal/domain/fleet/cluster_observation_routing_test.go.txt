package fleet

import (
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

func routingValues() (ClusterObservationClaim, OwnerBinding, time.Time) {
	start := time.Date(2026, 10, 13, 12, 0, 0, 123456789, time.UTC)
	id := func(s string) string { return s + "0000000-0000-0000-0000-000000000001" }
	r := ClusterObservationRequest{ID: id("1"), Challenge: id("2"), RootID: id("3"), ClusterID: id("4"), Purpose: ObserveCapacityNamespaceGuard, RequestedAt: start, NotAfter: start.Add(4 * time.Second)}
	h := OwnerBinding{id("a"), id("5"), id("6"), id("7"), id("8")}
	v := ClusterObservationLocator{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Holder: h, ExchangeID: id("9"), Sequence: ^uint64(0), Interval: ClusterObservationInterval{start.Add(time.Millisecond), start.Add(3 * time.Second)}}
	return ClusterObservationClaim{r, v}, h, start.Add(time.Second)
}

func TestClusterObservationRoutingOriginalSelection(t *testing.T) {
	c, h, now := routingValues()
	if !c.Matches(h, now) || !c.Request.LocatorQuery().Valid(now) {
		t.Fatal("exact original selection rejected")
	}
	q := c.Request.LocatorQuery()
	if !q.RequestedAt.Equal(c.Request.RequestedAt) || !q.NotAfter.Equal(c.Request.NotAfter) {
		t.Fatal("lookup reset original interval")
	}
	if c.Locator.Holder.InstallationID == c.Locator.RootID || c.Locator.Holder.ClusterID == c.Locator.ClusterID {
		t.Fatal("fixture must distinguish permission root, installation, hub and regional clusters")
	}
	for _, n := range []uint64{1, 1<<53 + 1, ^uint64(0)} {
		c.Locator.Sequence = n
		if !c.Matches(h, now) {
			t.Fatal("valid registration sequence rejected")
		}
	}
}

func TestClusterObservationRoutingRejectsChangedTupleOrInterval(t *testing.T) {
	base, holder, now := routingValues()
	for name, mutate := range map[string]func(*ClusterObservationClaim){
		"request":             func(c *ClusterObservationClaim) { c.Locator.RequestID = c.Request.Challenge },
		"challenge":           func(c *ClusterObservationClaim) { c.Locator.Challenge = c.Request.ID },
		"root":                func(c *ClusterObservationClaim) { c.Locator.RootID = c.Request.ClusterID },
		"region":              func(c *ClusterObservationClaim) { c.Locator.ClusterID = c.Request.RootID },
		"holder-installation": func(c *ClusterObservationClaim) { c.Locator.Holder.InstallationID = c.Request.ClusterID },
		"holder-cluster":      func(c *ClusterObservationClaim) { c.Locator.Holder.ClusterID = c.Request.ClusterID },
		"holder-issuer":       func(c *ClusterObservationClaim) { c.Locator.Holder.IssuerEpoch = c.Request.ClusterID },
		"holder-pod":          func(c *ClusterObservationClaim) { c.Locator.Holder.PodUID = c.Request.ClusterID },
		"holder-process":      func(c *ClusterObservationClaim) { c.Locator.Holder.ProcessEpoch = c.Request.ClusterID },
		"exchange":            func(c *ClusterObservationClaim) { c.Locator.ExchangeID = "" },
		"zero-sequence":       func(c *ClusterObservationClaim) { c.Locator.Sequence = 0 },
		"old-locator": func(c *ClusterObservationClaim) {
			c.Locator.Interval.ObservedAt = c.Request.RequestedAt.Add(-time.Nanosecond)
		},
		"later-locator": func(c *ClusterObservationClaim) {
			c.Locator.Interval.FreshUntil = c.Request.NotAfter.Add(time.Nanosecond)
		},
		"expired-locator":        func(c *ClusterObservationClaim) { c.Locator.Interval.FreshUntil = now },
		"future-locator":         func(c *ClusterObservationClaim) { c.Locator.Interval.ObservedAt = now.Add(time.Nanosecond) },
		"empty-locator-interval": func(c *ClusterObservationClaim) { c.Locator.Interval.FreshUntil = c.Locator.Interval.ObservedAt },
		"overlong-request": func(c *ClusterObservationClaim) {
			c.Request.NotAfter = c.Request.RequestedAt.Add(5*time.Second + time.Nanosecond)
		},
		"expired-request":     func(c *ClusterObservationClaim) { c.Request.NotAfter = now },
		"future-request":      func(c *ClusterObservationClaim) { c.Request.RequestedAt = now.Add(time.Nanosecond) },
		"unknown-purpose":     func(c *ClusterObservationClaim) { c.Request.Purpose = "capture" },
		"wrong-purpose-shape": func(c *ClusterObservationClaim) { c.Request.Keys = []string{"app"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := base.Clone()
			mutate(&c)
			if c.Matches(holder, now) {
				t.Fatal("changed selection accepted")
			}
		})
	}
	if base.Matches(OwnerBinding{}, now) {
		t.Fatal("missing independent holder accepted")
	}
}

func TestClusterObservationRoutingClaimCloneAndClosedPurposes(t *testing.T) {
	base, h, now := routingValues()
	ns := cfg.NamespaceRef{Name: "sample", UID: "namespace"}
	w := cfg.WorkloadRef{Kind: "Deployment", Name: "sample", UID: "workload"}
	for _, purpose := range []ClusterObservationPurpose{ObserveCapacityNamespaceGuard, ObserveCapacityNamespaces, ObserveCapacityWorkloads, ObserveCapacityWorkload} {
		c := base
		c.Request.Purpose = purpose
		switch purpose {
		case ObserveCapacityNamespaces:
			c.Request.Continue = "page"
		case ObserveCapacityWorkloads:
			c.Request.Namespace = ns
			c.Request.Kind = "Deployment"
			c.Request.Continue = "page"
		case ObserveCapacityWorkload:
			c.Request.Namespace = ns
			c.Request.Workload = w
			c.Request.Keys = []string{"app"}
		}
		if !c.Matches(h, now) {
			t.Fatalf("closed purpose %s rejected", purpose)
		}
		clone := c.Clone()
		if len(clone.Request.Keys) != 0 {
			clone.Request.Keys[0] = "changed"
			if c.Request.Keys[0] != "app" {
				t.Fatal("clone shares selected keys")
			}
		}
	}
}
