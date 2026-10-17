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
type regionalOperationExchangeFixture struct {
	ctx                                                 context.Context
	hello                                               contracts.ClusterObservationHello
	request                                             fleet.ClusterObservationRequest
	owner                                               contracts.ObservationOperationRequest
	frames                                              []contracts.ClusterObservationFrame
	sent                                                []contracts.ClusterObservationFrame
	reads, proofs, metadata, receipts, finishes, closes int
	fail                                                string
	until                                               time.Time
	wrongBound                                          bool
}

func newRegionalOperationExchangeFixture(t *testing.T) *regionalOperationExchangeFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	r := localRequest()
	f := &regionalOperationExchangeFixture{ctx: ctx, request: r, hello: contracts.ClusterObservationHello{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: localID(21), RootID: r.RootID, ClusterID: r.ClusterID}}
	f.until, _ = ctx.Deadline()
	f.owner = contracts.ObservationOperationRequest{Format: contracts.OwnerObservationOperationFormat, RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: writeTime(r.RequestedAt), NotAfter: writeTime(r.NotAfter)}
	appendFrame := func(kind contracts.ClusterObservationFrameKind, b []byte, e error) {
		if e != nil {
			t.Fatal(e)
		}
		f.frames = append(f.frames, contracts.ClusterObservationFrame{Kind: kind, Payload: b})
	}
	for ordinal := 1; ordinal <= 4; ordinal++ {
		b, e := contracts.EncodeClusterObservationOperationProbe(contracts.ClusterObservationOperationProbe{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: f.hello.ExchangeID, Ordinal: ordinal, Owner: contracts.OwnerObservationOperationReply{Format: contracts.OwnerObservationOperationFormat, Request: f.owner, NativeUntil: writeTime(f.until), RegistrationUntil: writeTime(f.until)}})
		appendFrame(contracts.ClusterObservationProbeFrame, b, e)
		if ordinal == 2 {
			b, e = contracts.EncodeClusterObservationRequest(RequestWire(r))
			appendFrame(contracts.ClusterObservationReadFrame, b, e)
		}
	}
	d, _ := RequestDigest(r)
	b, e := contracts.EncodeClusterObservationReceipt(contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: f.hello.ExchangeID, RequestID: r.ID, Challenge: r.Challenge, RequestDigest: writeDigest(d)})
	appendFrame(contracts.ClusterObservationReceiptFrame, b, e)
	return f
}

func (f *regionalOperationExchangeFixture) Context() context.Context                 { return f.ctx }
func (f *regionalOperationExchangeFixture) Hello() contracts.ClusterObservationHello { return f.hello }
func (f *regionalOperationExchangeFixture) check(ctx context.Context) error {
	d, ok := ctx.Deadline()
	if !ok || d.After(f.until) {
		f.wrongBound = true
		return fleet.ErrUnavailable
	}
	return ctx.Err()
}
func (f *regionalOperationExchangeFixture) Receive(ctx context.Context) (contracts.ClusterObservationFrame, error) {
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
func (f *regionalOperationExchangeFixture) Send(ctx context.Context, v contracts.ClusterObservationFrame) error {
	if e := f.check(ctx); e != nil {
		return e
	}
	f.sent = append(f.sent, contracts.ClusterObservationFrame{Kind: v.Kind, Payload: bytes.Clone(v.Payload)})
	if f.fail == "send" {
		return fleet.ErrUnavailable
	}
	return nil
}
func (f *regionalOperationExchangeFixture) AnswerConnectorObservation(ctx context.Context, p contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error) {
	f.proofs++
	if e := f.check(ctx); e != nil {
		return contracts.ConnectorObservationOperationReply{}, e
	}
	if f.fail == "proof" {
		return contracts.ConnectorObservationOperationReply{}, fleet.ErrUnavailable
	}
	return contracts.ConnectorObservationOperationReply{Format: contracts.ConnectorObservationOperationFormat, Request: p.Owner.Request, Ordinal: p.Ordinal, NativeStartedAt: writeTime(f.request.RequestedAt), NativeUntil: writeTime(f.until), SourceFreshUntil: writeTime(f.until), WorkloadFreshUntil: writeTime(f.until)}, nil
}
func (f *regionalOperationExchangeFixture) ObserveCluster(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
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
func (f *regionalOperationExchangeFixture) AcceptObservationReceipt(ctx context.Context, r contracts.ClusterObservationReceipt) error {
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
func (f *regionalOperationExchangeFixture) FinishObservation(ctx context.Context) error {
	f.finishes++
	if e := f.check(ctx); e != nil {
		return e
	}
	if f.fail == "terminal" {
		return fleet.ErrUnavailable
	}
	return nil
}
func (f *regionalOperationExchangeFixture) Close() error {
	f.closes++
	if f.fail == "close" {
		return fleet.ErrUnavailable
	}
	return nil
}

func TestRegionalObservationOperationExchangeClosedOrderAndOriginalCaller(t *testing.T) {
	f := newRegionalOperationExchangeFixture(t)
	if e := ServeRegionalObservationOperation(f.ctx, f, time.Now); e != nil {
		t.Fatal(e)
	}
	if f.reads != 6 || f.proofs != 4 || f.metadata != 1 || f.receipts != 1 || f.finishes != 1 || f.closes != 1 || f.wrongBound || len(f.sent) != 5 {
		t.Fatal("closed phase counts", f.reads, f.proofs, f.metadata, f.receipts, f.finishes, f.closes, f.wrongBound, len(f.sent))
	}
	want := []contracts.ClusterObservationFrameKind{contracts.ClusterObservationSourceFrame, contracts.ClusterObservationSourceFrame, contracts.ClusterObservationResultFrame, contracts.ClusterObservationSourceFrame, contracts.ClusterObservationSourceFrame}
	for i, v := range f.sent {
		if v.Kind != want[i] {
			t.Fatal("wrong output order", i)
		}
	}
}

func TestRegionalObservationOperationExchangeNeverReplaysFailedPhase(t *testing.T) {
	for _, failure := range []string{"proof", "send", "result", "receipt", "terminal", "close"} {
		t.Run(failure, func(t *testing.T) {
			f := newRegionalOperationExchangeFixture(t)
			f.fail = failure
			if e := ServeRegionalObservationOperation(f.ctx, f, time.Now); e == nil {
				t.Fatal("failed phase reported joined")
			}
			if f.closes != 1 || f.metadata > 1 || f.proofs > 4 || f.receipts > 1 || f.finishes > 1 {
				t.Fatal("phase retried", f)
			}
			if (failure == "proof" || failure == "send") && f.metadata != 0 {
				t.Fatal("metadata after preflight failure")
			}
			if failure == "receipt" && f.finishes != 0 {
				t.Fatal("bad receipt reached completion")
			}
		})
	}
}

func TestRegionalObservationOperationExchangeRejectsChangedWireBeforeMetadata(t *testing.T) {
	for _, mode := range []string{"metadata-first", "receipt-before-final-proof", "probe-replay", "request-changed", "cluster-changed", "future-request", "unknown-format"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegionalOperationExchangeFixture(t)
			switch mode {
			case "metadata-first":
				f.frames[0] = f.frames[2]
			case "receipt-before-final-proof":
				f.frames[3] = f.frames[5]
			case "probe-replay":
				f.frames[1] = f.frames[0]
			case "request-changed", "cluster-changed":
				w, _ := contracts.DecodeClusterObservationRequest(f.frames[2].Payload)
				if mode == "request-changed" {
					w.RequestID = localID(70)
				} else {
					w.ClusterID = localID(71)
				}
				f.frames[2].Payload, _ = contracts.EncodeClusterObservationRequest(w)
			case "future-request", "unknown-format":
				p, _ := contracts.DecodeClusterObservationOperationProbe(f.frames[0].Payload)
				if mode == "future-request" {
					p.Owner.Request.RequestedAt = writeTime(time.Now().Add(time.Minute))
				} else {
					p.Format = "other/v1"
				}
				f.frames[0].Payload, _ = contracts.EncodeClusterObservationOperationProbe(p)
			}
			if e := ServeRegionalObservationOperation(f.ctx, f, time.Now); e == nil || f.closes != 1 || f.finishes != 0 {
				t.Fatal("changed/order wire accepted", e)
			}
			if mode != "receipt-before-final-proof" && f.metadata != 0 {
				t.Fatal("invalid pre-metadata wire read local metadata")
			}
		})
	}
}
