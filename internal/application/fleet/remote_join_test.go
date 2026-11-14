package fleet

import (
	"context"
	"sync"
	"testing"

	value "asservat.local/asservat/internal/domain/fleet"
)

type joinRecords struct {
	mu      sync.Mutex
	exists  bool
	created []*value.BootstrapEnvelope
	changes chan struct{}
}

func (r *joinRecords) Changed(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.changes:
		return nil
	}
}

func (r *joinRecords) Present(context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exists, nil
}

func (r *joinRecords) set(exists bool) {
	r.mu.Lock()
	r.exists = exists
	r.mu.Unlock()
}
func (r *joinRecords) Create(_ context.Context, e *value.BootstrapEnvelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e != nil {
		copied := *e
		e = &copied
	}
	r.created = append(r.created, e)
	r.exists = true
	return nil
}

// A remote cluster's record is issued only when its join Secret is created;
// an existing Secret, live or expired, spends no further bootstrap history.
func TestRemoteClusterJoinIssuesOnlyWhenTheSecretIsCreated(t *testing.T) {
	f, l, _ := newLocalFixture()
	l.Records = nil
	records := &joinRecords{}
	join := RemoteClusterJoin{Bootstrap: l, Records: records}
	var k localKey
	if got := join.create(context.Background(), &k); got != "issued" || len(records.created) != 1 || records.created[0] == nil || records.created[0].BootstrapID != f.intent.Slot.ID {
		t.Fatal("issue", got, records.created)
	}
	if f.activations != 1 {
		t.Fatal("activations", f.activations)
	}
	// After the claim, a recreated Secret carries no record.
	join.Bootstrap.Issuer.Reservations = consumedReservations{f}
	if got := join.create(context.Background(), &k); got != "claimed: written" || len(records.created) != 2 || records.created[1] != nil {
		t.Fatal("claimed", got)
	}
	// An existing Secret is left alone.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = join.Run(ctx, func(string) {})
	if len(records.created) != 2 {
		t.Fatal("existing Secret recreated", len(records.created))
	}
}

// The runner checks once, then only when the watch reports a change: a
// deleted Secret is recreated without any timer.
func TestRemoteClusterJoinRecreatesOnDeleteEvent(t *testing.T) {
	f, l, _ := newLocalFixture()
	l.Records = nil
	records := &joinRecords{exists: true, changes: make(chan struct{})}
	join := RemoteClusterJoin{Bootstrap: l, Records: records}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- join.Run(ctx, func(string) {}) }()
	records.changes <- struct{}{} // an unchanged Secret: nothing created
	records.set(false)
	records.changes <- struct{}{} // delete event
	records.changes <- struct{}{} // wait until the runner is back in Changed
	cancel()
	<-done
	records.mu.Lock()
	defer records.mu.Unlock()
	if len(records.created) != 1 || records.created[0] == nil || records.created[0].BootstrapID != f.intent.Slot.ID {
		t.Fatal("recreate on delete", records.created)
	}
}
