package fleet

import (
	"context"
	"testing"

	value "asservat.local/asservat/internal/domain/fleet"
)

type joinRecords struct {
	exists  bool
	created []*value.BootstrapEnvelope
}

func (r *joinRecords) Present(context.Context) (bool, error) { return r.exists, nil }
func (r *joinRecords) Create(_ context.Context, e *value.BootstrapEnvelope) error {
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
