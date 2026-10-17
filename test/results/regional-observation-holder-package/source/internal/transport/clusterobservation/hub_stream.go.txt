package clusterobservation

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// HubObservationStream owns exactly one receiving HTTP/2 body/response pair.
// Only the installed coordinator gets it; no method chooses an endpoint,
// principal or protocol. The holder alone can make it routing-ineligible.
type HubObservationStream struct {
	ctx                            context.Context
	cancel                         context.CancelFunc
	body                           io.ReadCloser
	writer                         http.ResponseWriter
	control                        *http.ResponseController
	hello                          contracts.ClusterObservationHello
	entry                          *hubObservationEntry
	now                            func() time.Time
	mu                             sync.Mutex
	busy, failed, closed, terminal bool
	order                          exchangeOrder
	request                        contracts.OwnerObservationRequest
	digest                         string
	until                          time.Time
	joined                         sync.WaitGroup
}

func newHubObservationStream(ctx context.Context, w http.ResponseWriter, body io.ReadCloser, hello contracts.ClusterObservationHello, helloBytes int, now func() time.Time) (*HubObservationStream, error) {
	if ctx == nil || ctx.Err() != nil || w == nil || body == nil || now == nil {
		return nil, fleet.ErrInvalid
	}
	end, finite := ctx.Deadline()
	if !finite || !now().Before(end) || end.After(now().Add(30*time.Second)) {
		return nil, fleet.ErrInvalid
	}
	root, cancel := context.WithDeadline(ctx, end)
	s := &HubObservationStream{ctx: root, cancel: cancel, body: body, writer: w, control: http.NewResponseController(w), hello: hello, until: end, now: now}
	if s.order.admit(contracts.ClusterObservationHelloFrame, true, helloBytes) != nil {
		cancel()
		return nil, fleet.ErrInvalid
	}
	return s, nil
}

// A phase is single-use and cannot run concurrently with another write/read.
// Every blocking body operation is interrupted by the same original call, then
// joined before its reservation ends. No source/proof is refreshed here.
func (s *HubObservationStream) begin(ctx context.Context) (context.Context, func(bool), error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, fleet.ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.failed || s.busy || s.terminal || s.ctx.Err() != nil || !s.now().Before(s.until) {
		s.mu.Unlock()
		return nil, nil, fleet.ErrUnavailable
	}
	end := s.until
	if d, ok := ctx.Deadline(); ok {
		end = identity.Earlier(end, d)
	} else {
		s.mu.Unlock()
		return nil, nil, fleet.ErrUnavailable
	}
	if !s.now().Before(end) {
		s.mu.Unlock()
		return nil, nil, fleet.ErrUnavailable
	}
	s.until = end
	s.busy = true
	s.joined.Add(1)
	s.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, end)
	rootDone := make(chan struct{})
	stopRoot := context.AfterFunc(s.ctx, func() { cancel(); close(rootDone) })
	ioDone := make(chan struct{})
	stopIO := context.AfterFunc(call, func() { s.interrupt(); close(ioDone) })
	finish := func(success bool) {
		if !stopIO() {
			<-ioDone
		}
		if !stopRoot() {
			<-rootDone
		}
		if call.Err() != nil || !s.now().Before(end) {
			success = false
		}
		cancel()
		s.mu.Lock()
		s.busy = false
		if !success {
			s.failed = true
		}
		s.mu.Unlock()
		if !success {
			s.cancel()
			s.interrupt()
		}
		s.joined.Done()
	}
	if s.control.SetReadDeadline(end) != nil || s.control.SetWriteDeadline(end) != nil || call.Err() != nil {
		finish(false)
		return nil, nil, fleet.ErrUnavailable
	}
	return call, finish, nil
}

func (s *HubObservationStream) interrupt() {
	_ = s.control.SetReadDeadline(time.Now())
	_ = s.control.SetWriteDeadline(time.Now())
	_ = s.body.Close()
}

func (s *HubObservationStream) current(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.failed && s.ctx.Err() == nil && ctx.Err() == nil && s.now().Before(s.until)
}

func (s *HubObservationStream) send(ctx context.Context, kind contracts.ClusterObservationFrameKind, payload []byte) error {
	if !s.current(ctx) || s.order.admit(kind, false, len(payload)) != nil || contracts.WriteClusterObservationFrame(s.writer, contracts.ClusterObservationFrame{Kind: kind, Payload: payload}) != nil || s.control.Flush() != nil || !s.current(ctx) {
		return fleet.ErrUnavailable
	}
	return nil
}
func (s *HubObservationStream) receive(ctx context.Context, kind contracts.ClusterObservationFrameKind) ([]byte, error) {
	if !s.current(ctx) {
		return nil, fleet.ErrUnavailable
	}
	f, err := contracts.ReadClusterObservationFrame(s.body)
	if err != nil || !s.current(ctx) || f.Kind != kind || s.order.admit(f.Kind, true, len(f.Payload)) != nil {
		clear(f.Payload)
		return nil, fleet.ErrUnavailable
	}
	return f.Payload, nil
}

func (s *HubObservationStream) ExchangeConnectorObservation(ctx context.Context, probe contracts.ClusterObservationProbe) (contracts.ConnectorObservationReply, error) {
	var zero contracts.ConnectorObservationReply
	call, finish, err := s.begin(ctx)
	if err != nil {
		return zero, err
	}
	success := false
	defer func() { finish(success) }()
	expected := 0
	switch s.order.next {
	case 1:
		expected = 1
	case 3:
		expected = 2
	case 7:
		expected = 3
	case 9:
		expected = 4
	}
	request := probe.Owner.Request
	start, end := readTime(request.RequestedAt), readTime(request.NotAfter)
	if expected == 0 || probe.Ordinal != expected || probe.Format != contracts.ClusterObservationExchangeFormat || probe.ExchangeID != s.hello.ExchangeID || request.Format != contracts.OwnerObservationFormat || request.RootID != s.hello.RootID || !authorization.UUID(request.ID) || !authorization.UUID(request.Challenge) || probe.Owner.Format != contracts.OwnerObservationFormat || !identity.Fresh(start, end, s.now(), 5*time.Second) {
		return zero, fleet.ErrUnavailable
	}
	if expected == 1 {
		s.request = request
	} else if request != s.request {
		return zero, fleet.ErrUnavailable
	}
	fresh := readTime(probe.Owner.FreshUntil)
	if fresh.IsZero() || fresh.After(end) || !s.now().Before(fresh) {
		return zero, fleet.ErrUnavailable
	}
	bounded, cancel := context.WithDeadline(call, identity.Earlier(end, fresh))
	defer cancel()
	// begin installed the caller deadline; narrowing the actual I/O deadlines
	// also covers a shorter current proof returned inside that original call.
	if s.control.SetReadDeadline(identity.Earlier(s.until, fresh)) != nil || s.control.SetWriteDeadline(identity.Earlier(s.until, fresh)) != nil {
		return zero, fleet.ErrUnavailable
	}
	payload, err := contracts.EncodeClusterObservationProbe(probe)
	if err != nil {
		return zero, fleet.ErrUnavailable
	}
	err = s.send(bounded, contracts.ClusterObservationProbeFrame, payload)
	clear(payload)
	if err != nil {
		return zero, err
	}
	payload, err = s.receive(bounded, contracts.ClusterObservationSourceFrame)
	if err != nil {
		return zero, err
	}
	out, err := contracts.DecodeConnectorObservationReply(payload)
	clear(payload)
	if err != nil || bounded.Err() != nil || !s.now().Before(fresh) {
		return zero, fleet.ErrUnavailable
	}
	// Semantic certificate/source/exporter validation belongs to the current
	// private verifier; framing cannot manufacture a successful proof.
	s.mu.Lock()
	s.until = identity.Earlier(s.until, fresh)
	s.mu.Unlock()
	success = true
	return out, nil
}

func (s *HubObservationStream) ExchangeClusterObservation(ctx context.Context, request fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var zero fleet.ClusterObservationResult
	call, finish, err := s.begin(ctx)
	if err != nil {
		return zero, err
	}
	success := false
	defer func() { finish(success) }()
	if s.order.next != 5 || !request.Valid(s.now()) || request.RootID != s.hello.RootID || request.ClusterID != s.hello.ClusterID || request.ID != s.request.ID || request.Challenge != s.request.Challenge || !request.RequestedAt.Equal(readTime(s.request.RequestedAt)) || !request.NotAfter.Equal(readTime(s.request.NotAfter)) {
		return zero, fleet.ErrUnavailable
	}
	digest, err := RequestDigest(request)
	if err != nil {
		return zero, fleet.ErrUnavailable
	}
	s.digest = writeDigest(digest)
	payload, err := contracts.EncodeClusterObservationRequest(RequestWire(request))
	if err != nil {
		return zero, fleet.ErrUnavailable
	}
	err = s.send(call, contracts.ClusterObservationReadFrame, payload)
	clear(payload)
	if err != nil {
		return zero, err
	}
	payload, err = s.receive(call, contracts.ClusterObservationResultFrame)
	if err != nil {
		return zero, err
	}
	wire, err := contracts.DecodeClusterObservationResult(payload)
	clear(payload)
	if err != nil {
		return zero, fleet.ErrUnavailable
	}
	out, err := ParseResult(wire, request, digest, s.now())
	if err != nil || call.Err() != nil {
		return zero, fleet.ErrUnavailable
	}
	s.mu.Lock()
	s.until = identity.Earlier(s.until, out.Interval.FreshUntil)
	s.mu.Unlock()
	success = true
	return out, nil
}

func (s *HubObservationStream) CompleteClusterObservation(ctx context.Context, receipt contracts.ClusterObservationReceipt) error {
	call, finish, err := s.begin(ctx)
	if err != nil {
		return err
	}
	success := false
	defer func() { finish(success) }()
	if s.order.next != 11 || receipt.Format != contracts.ClusterObservationExchangeFormat || receipt.ExchangeID != s.hello.ExchangeID || receipt.RequestID != s.request.ID || receipt.Challenge != s.request.Challenge || receipt.RequestDigest != s.digest || s.entry == nil || s.entry.detach() != nil {
		return fleet.ErrUnavailable
	}
	payload, err := contracts.EncodeClusterObservationReceipt(receipt)
	if err != nil {
		return fleet.ErrUnavailable
	}
	err = s.send(call, contracts.ClusterObservationReceiptFrame, payload)
	clear(payload)
	if err != nil {
		return err
	}
	var extra [1]byte
	n, err := s.body.Read(extra[:])
	clear(extra[:])
	if n != 0 || err != io.EOF || call.Err() != nil || !s.order.complete() {
		return fleet.ErrUnavailable
	}
	s.mu.Lock()
	s.terminal = true
	s.mu.Unlock()
	success = true
	return nil
}

func (s *HubObservationStream) completed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal && !s.failed && !s.busy
}

func (s *HubObservationStream) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	terminal := s.terminal
	s.cancel()
	s.mu.Unlock()
	if !terminal {
		s.interrupt()
	}
	s.joined.Wait()
	if !s.completed() {
		s.interrupt()
	}
	_ = s.body.Close()
	// Do not force an expired write deadline after positive request EOF. The
	// receiving handler must return normally to emit the response END_STREAM;
	// the listener still owns the original bounded socket and its final join.
	return nil
}
