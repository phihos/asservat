package fleet

import (
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"testing"
	"time"
)

// Only already-acknowledged replay is synthesized here. Nil embedded methods
// deliberately fail if policy selection unexpectedly attempts new object work.
// Real SQL/S3 admission and object writes are covered by connector-identity-fast.
type connectorAuditReplay struct {
	app.OperationJournal
	app.OperationAcknowledgements
	app.OperationObjects
	app.ClosedOperationObjects
	app.OperationCompletions
	expected value.OperationIntent
	calls    int
	deny     bool
}

func (f *connectorAuditReplay) ReserveOperation(_ context.Context, in value.OperationIntent) (value.OperationSnapshot, error) {
	f.calls++
	if f.deny || !sameConnectorJSON(in, f.expected) {
		return value.OperationSnapshot{}, app.ErrUnavailable
	}
	r := value.Receipt{Key: value.OperationAuditKey(in.RootID, in.ID, "intent"), ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{1}}
	return value.OperationSnapshot{Intent: in, IntentStarted: true, IntentReceipt: &r}, nil
}
func TestConnectorAuditUsesOriginalAdmittedPolicyWithoutRevisionCache(t *testing.T) {
	f, enroll, _ := newConnectorProcessFixture(t)
	if _, e := enroll.Enroll(context.Background(), f.connectorRenewalFixture.request.ID, f.request); e != nil {
		t.Fatal(e)
	}
	original := f.admission.Intent
	replay := &connectorAuditReplay{}
	gate, e := NewConnectorOperationAuditor(original.Lifecycle.Policy, replay, replay, replay, replay, replay, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	next := original.Lifecycle.Policy
	next.BackingRevision++
	next.ValidUntil = next.ValidUntil.Add(time.Hour)
	next.PolicyDigest[0]++
	next.PolicyID = "20000000-0000-4000-8000-000000000003"
	in := original
	in.Lifecycle = nil
	in, e = app.BindOperationLifecycle(in, next)
	if e != nil {
		t.Fatal(e)
	}
	for _, accepted := range []value.OperationIntent{in, original, in} {
		replay.expected = accepted
		if e = gate.Begin(context.Background(), accepted); e != nil {
			t.Fatal("exact acknowledged original policy lost", e)
		}
	}
	if replay.calls != 3 {
		t.Fatal("policy selection bypassed exact journal", replay.calls)
	}
	replay.deny = true
	if e = gate.Begin(context.Background(), in); e == nil {
		t.Fatal("caller policy supplied admission authority")
	}
	replay.deny = false
	changed := in
	binding := *in.Lifecycle
	changed.Lifecycle = &binding
	changed.Lifecycle.Policy.StoreID = "20000000-0000-4000-8000-000000000004"
	calls := replay.calls
	if e = gate.Begin(context.Background(), changed); e == nil || replay.calls != calls {
		t.Fatal("changed protected store reached journal", e)
	}
	f.now = in.RequestUntil
	if e = gate.Begin(context.Background(), in); e == nil || replay.calls != calls {
		t.Fatal("renewed policy extended original request interval", e)
	}
}
