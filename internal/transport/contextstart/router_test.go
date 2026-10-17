package contextstart

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

func TestContextRouterReservedClusterCapacityAndClosing(t *testing.T) {
	work := workFixture()
	a := work.Work.Channel.Connector.Binding.ClusterID
	b := "00000000-0000-4000-8000-000000000099"
	router, e := NewRouter(RouterLimits{Standby: 2, Captures: 2, Clusters: []ClusterLimit{{a, 1, 1}, {b, 1, 1}}})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	register := func(cluster, exchange string) *Standby {
		t.Helper()
		channel := work.Work.Channel
		channel.Connector.Binding.ClusterID = cluster
		channel.ExchangeID = exchange
		now := time.Now()
		receiver := fleet.APIContextReceiver{Channel: channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
		s, e := router.RegisterStandby(ctx, receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	first := register(a, work.Work.Channel.ExchangeID)
	same := work.Work.Channel
	same.ExchangeID = "00000000-0000-4000-8000-000000000098"
	n := time.Now()
	obs := fleet.APIContextReceiver{Channel: same, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
	if _, e = router.RegisterStandby(ctx, obs, func(context.Context) (fleet.APIContextReceiver, error) { return obs, nil }); e == nil {
		t.Fatal("one cluster stole another's standby reservation")
	}
	second := register(b, same.ExchangeID)
	attached, e := router.Attach(ctx, a, work.Work.CaptureID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = router.Attach(ctx, a, "00000000-0000-4000-8000-000000000097"); e == nil {
		t.Fatal("capture share exceeded")
	}
	// Standby and capture quotas are different: B remains attachable while A is
	// closing; neither A slot is released until its actual handler/socket joins.
	closed := make(chan struct{})
	go func() { attached.Close(); close(closed) }()
	<-first.Context().Done()
	select {
	case <-closed:
		t.Fatal("capture released before socket joined")
	default:
	}
	next, e := router.Attach(ctx, b, "00000000-0000-4000-8000-000000000096")
	if e != nil {
		t.Fatal("another cluster starved", e)
	}
	first.Finish()
	<-closed
	second.Finish()
	next.Close()
	router.Close()
}
func TestContextRouterRejectsOvercommittedReservationsAndMissingOwner(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	if _, e := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 2, 1}}}); e == nil {
		t.Fatal("overcommitted standby accepted")
	}
	if _, e := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 2}}}); e == nil {
		t.Fatal("overcommitted active slots accepted")
	}
	r, e := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = r.Attach(context.Background(), cluster, w.Work.CaptureID); e == nil {
		t.Fatal("detached unbounded owner accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e = r.Attach(ctx, cluster, w.Work.CaptureID); e == nil {
		t.Fatal("missing connection fabricated a route")
	}
}

// ADR-185: a hub with no enrolled region builds a router that refuses starts.
func TestRouterWithoutClustersRefusesEveryStart(t *testing.T) {
	r, e := NewRouter(RouterLimits{Standby: 1, Captures: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	ctx, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	if _, e = r.Query(ctx, "00000000-0000-4000-8000-000000000001", "m", nil, nil); e == nil {
		t.Fatal("router without clusters accepted a query")
	}
}
