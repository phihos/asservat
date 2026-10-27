package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

// Work goes to the standby with the latest residency end, and never to one
// whose residency ends within the margin after the work's deadline: the
// region's exchange is cut there and would end the work mid-run.
func TestRouterSelectsStandbyThatOutlivesTheWork(t *testing.T) {
	work := workFixture()
	cluster := work.Work.Channel.Connector.Binding.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 2, Captures: 2, Clusters: []ClusterLimit{{cluster, 2, 2}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	register := func(ctx context.Context, exchange string) *Standby {
		t.Helper()
		channel := work.Work.Channel
		channel.ExchangeID = exchange
		now := time.Now()
		receiver := fleet.APIContextReceiver{Channel: channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
		s, err := router.RegisterStandby(ctx, receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// The older standby ends in six seconds: within a five-second work's margin.
	ending, end := context.WithTimeout(context.Background(), 6*time.Second)
	defer end()
	old := register(ending, "00000000-0000-4000-8000-000000000091")
	defer old.Finish()
	attach := func(capture string) (*Attachment, error) {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		t.Cleanup(stop)
		return router.Attach(ctx, cluster, capture)
	}
	if _, err := attach("00000000-0000-4000-8000-000000000081"); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal("work attached to a standby that ends during it", err)
	}
	fresh := register(context.Background(), "00000000-0000-4000-8000-000000000092")
	defer fresh.Finish()
	a, err := attach("00000000-0000-4000-8000-000000000082")
	if err != nil {
		t.Fatal(err)
	}
	if a.standby != fresh {
		t.Fatal("work did not go to the standby with the latest residency end")
	}
	// The ending idle standby is retired once it cannot cover any work, so
	// its handler returns and the region opens a replacement.
	select {
	case <-old.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("idle standby that can no longer cover work was not retired")
	}
	if fresh.Context().Err() != nil {
		t.Fatal("attached standby was retired")
	}
	// The attachment's slot frees only after its standby's handler finished.
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	fresh.Finish()
	<-closed
}
