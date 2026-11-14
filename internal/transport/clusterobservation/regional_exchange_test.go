package clusterobservation

import (
	"bytes"
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// Transport-state fixture only. Actual proof/TLS/EOF behavior is exercised by
// the adapter's real h2 stream tests; this fake supplies no production authority.
type regionalExchangeFixture struct {
	ctx                                                 context.Context
	hello                                               contracts.ClusterObservationHello
	request                                             fleet.ClusterObservationRequest
	owner                                               contracts.OwnerObservationRequest
	frames                                              []contracts.ClusterObservationFrame
	sent                                                []contracts.ClusterObservationFrame
	reads, proofs, metadata, receipts, finishes, closes int
	fail                                                string
	until                                               time.Time
	wrongBound                                          bool
}

func newRegionalExchangeFixture(t *testing.T) *regionalExchangeFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	r := localRequest()
	f := &regionalExchangeFixture{ctx: ctx, request: r, hello: contracts.ClusterObservationHello{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: localID(21), RootID: r.RootID, ClusterID: r.ClusterID}}
	f.until, _ = ctx.Deadline()
	f.owner = contracts.OwnerObservationRequest{Format: contracts.OwnerObservationFormat, RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: writeTime(r.RequestedAt), NotAfter: writeTime(r.NotAfter)}
	appendFrame := func(kind contracts.ClusterObservationFrameKind, b []byte, e error) {
		if e != nil {
			t.Fatal(e)
		}
		f.frames = append(f.frames, contracts.ClusterObservationFrame{Kind: kind, Payload: b})
	}
	for ordinal := 1; ordinal <= 4; ordinal++ {
		b, e := contracts.EncodeClusterObservationProbe(contracts.ClusterObservationProbe{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: f.hello.ExchangeID, Ordinal: ordinal, Owner: contracts.OwnerObservationReply{Format: contracts.OwnerObservationFormat, Request: f.owner}})
		appendFrame(contracts.ClusterObservationProbeFrame, b, e)
		if ordinal == 2 {
			b, e = contracts.EncodeClusterObservationRequest(RequestWire(r))
			appendFrame(contracts.ClusterObservationReadFrame, b, e)
		}
	}
	d, _ := RequestDigest(r)
	b, e := contracts.EncodeClusterObservationReceipt(contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: f.hello.ExchangeID, RequestID: r.ID, Challenge: r.Challenge, RequestDigest: writeDigest(d)})
	appendFrame(contracts.ClusterObservationReceiptFrame, b, e)
	return f
}

func (f *regionalExchangeFixture) Context() context.Context                 { return f.ctx }
func (f *regionalExchangeFixture) Hello() contracts.ClusterObservationHello { return f.hello }
func (f *regionalExchangeFixture) check(ctx context.Context) error {
	d, ok := ctx.Deadline()
	if !ok || d.After(f.until) {
		f.wrongBound = true
		return fleet.ErrUnavailable
	}
	return ctx.Err()
}
func (f *regionalExchangeFixture) Receive(ctx context.Context) (contracts.ClusterObservationFrame, error) {
	if e := f.check(ctx); e != nil {
		return contracts.ClusterObservationFrame{}, e
	}
	if f.reads >= len(f.frames) {
		return contracts.ClusterObservationFrame{}, fleet.ErrUnavailable
	}
	v := f.frames[f.reads]
	f.reads++
	v.Payload = bytes.Clone(v.Payload)
	return v, nil
}
func (f *regionalExchangeFixture) Send(ctx context.Context, v contracts.ClusterObservationFrame) error {
	if e := f.check(ctx); e != nil {
		return e
	}
	f.sent = append(f.sent, contracts.ClusterObservationFrame{Kind: v.Kind, Payload: bytes.Clone(v.Payload)})
	if f.fail == "send" {
		return fleet.ErrUnavailable
	}
	return nil
}
func (f *regionalExchangeFixture) AnswerConnectorObservation(ctx context.Context, p contracts.ClusterObservationProbe) (contracts.ConnectorObservationReply, error) {
	f.proofs++
	if e := f.check(ctx); e != nil {
		return contracts.ConnectorObservationReply{}, e
	}
	if f.fail == "proof" {
		return contracts.ConnectorObservationReply{}, fleet.ErrUnavailable
	}
	return contracts.ConnectorObservationReply{Format: contracts.ConnectorObservationFormat, Request: p.Owner.Request, Ordinal: p.Ordinal, ObservedAt: writeTime(time.Now()), FreshUntil: writeTime(f.until)}, nil
}
func (f *regionalExchangeFixture) ObserveCluster(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	f.metadata++
	if e := f.check(ctx); e != nil {
		return fleet.ClusterObservationResult{}, e
	}
	v := localResult(r)
	if f.fail == "result" {
		v.RequestID = localID(90)
	}
	return v, nil
}
func (f *regionalExchangeFixture) AcceptObservationReceipt(ctx context.Context, r contracts.ClusterObservationReceipt) error {
	f.receipts++
	if e := f.check(ctx); e != nil {
		return e
	}
	d, _ := RequestDigest(f.request)
	if f.fail == "receipt" || r.RequestID != f.request.ID || r.RequestDigest != writeDigest(d) {
		return fleet.ErrUnavailable
	}
	return nil
}
func (f *regionalExchangeFixture) FinishObservation(ctx context.Context) error {
	f.finishes++
	if e := f.check(ctx); e != nil {
		return e
	}
	if f.fail == "terminal" {
		return fleet.ErrUnavailable
	}
	return nil
}
func (f *regionalExchangeFixture) Close() error {
	f.closes++
	if f.fail == "close" {
		return fleet.ErrUnavailable
	}
	return nil
}
