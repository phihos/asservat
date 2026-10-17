package mtls

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorObservationOperationConnection retains the actual stream and its matching
// private channel as one value. A caller cannot pair an independent TLS state
// or producer with the socket. One phase owns it at a time. Close cancels and
// joins admitted reads, writes and native proof work before releasing the slot.
type ConnectorObservationOperationConnection struct {
	ctx       context.Context
	cancel    context.CancelFunc
	stopChild context.CancelFunc
	raw       net.Conn
	reader    *io.PipeReader
	writer    *io.PipeWriter
	response  io.ReadCloser
	transport *http.Transport
	channel   *ConnectorObservationOperationChannel
	hello     contracts.ClusterObservationHello
	now       func() time.Time
	mu        sync.Mutex
	busy      bool
	closed    bool
	finished  bool
	frames    int
	bytes     int
	until     time.Time
	calls     sync.WaitGroup
	done      chan struct{}
}

func newConnectorObservationOperationConnection(ctx context.Context, cancel, stopChild context.CancelFunc, raw net.Conn, reader *io.PipeReader, writer *io.PipeWriter, response io.ReadCloser, transport *http.Transport, channel *ConnectorObservationOperationChannel, hello contracts.ClusterObservationHello, helloBytes int, now func() time.Time, release func()) *ConnectorObservationOperationConnection {
	until, _ := ctx.Deadline()
	s := &ConnectorObservationOperationConnection{ctx: ctx, cancel: cancel, stopChild: stopChild, raw: raw, reader: reader, writer: writer, response: response, transport: transport, channel: channel, hello: hello, now: now, frames: 1, bytes: helloBytes + 5, until: until, done: make(chan struct{})}
	// This goroutine waits only for shutdown. It reads no source or wire data,
	// refreshes nothing and cannot create a second request or signing attempt.
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		_ = raw.Close()
		_ = writer.CloseWithError(contracts.ErrClusterObservationProtocol)
		_ = reader.CloseWithError(contracts.ErrClusterObservationProtocol)
		_ = response.Close()
		channel.Close()
		s.calls.Wait()
		transport.CloseIdleConnections()
		stopChild()
		cancel()
		release()
		close(s.done)
	}()
	return s
}

func (s *ConnectorObservationOperationConnection) Context() context.Context { return s.ctx }
func (s *ConnectorObservationOperationConnection) Hello() contracts.ClusterObservationHello {
	return s.hello
}
func (s *ConnectorObservationOperationConnection) Close() error {
	if s != nil {
		s.cancel()
		<-s.done
	}
	return nil
}

func (s *ConnectorObservationOperationConnection) begin(ctx context.Context) (context.Context, func(bool), error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, value.ErrUnavailable
	}
	s.mu.Lock()
	end, finite := ctx.Deadline()
	if !finite || ctx.Err() != nil || s.closed || s.busy || s.ctx.Err() != nil || !s.now().Before(s.until) {
		s.mu.Unlock()
		return nil, nil, value.ErrUnavailable
	}
	s.busy = true
	s.calls.Add(1)
	s.until = identity.Earlier(s.until, end)
	until := s.until
	s.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, until)
	done := make(chan struct{})
	stop := context.AfterFunc(call, func() { s.cancel(); close(done) })
	finish := func(success bool) {
		if !stop() {
			<-done
		}
		cancel()
		if !success {
			s.cancel()
		}
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
		s.calls.Done()
	}
	if s.raw.SetDeadline(until) != nil || s.channel.producer.credentials.observationKeysCurrent(call, s.channel.keys) != nil {
		finish(false)
		return nil, nil, value.ErrUnavailable
	}
	return call, finish, nil
}

func (s *ConnectorObservationOperationConnection) current(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.ctx.Err() == nil && ctx.Err() == nil && s.now().Before(s.until) && s.channel.producer.credentials.observationKeysCurrent(ctx, s.channel.keys) == nil
}

func (s *ConnectorObservationOperationConnection) count(f contracts.ClusterObservationFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frames >= contracts.ClusterObservationMaximumFrames || len(f.Payload) < 1 || len(f.Payload) > contracts.ClusterObservationExchangeBytes-s.bytes-5 {
		return false
	}
	s.frames++
	s.bytes += len(f.Payload) + 5
	return true
}

func (s *ConnectorObservationOperationConnection) Receive(ctx context.Context) (contracts.ClusterObservationFrame, error) {
	call, finish, err := s.begin(ctx)
	if err != nil {
		return contracts.ClusterObservationFrame{}, err
	}
	success := false
	defer func() { finish(success) }()
	f, err := contracts.ReadClusterObservationFrame(s.response)
	if err != nil || !s.count(f) || !s.current(call) {
		clear(f.Payload)
		return contracts.ClusterObservationFrame{}, value.ErrUnavailable
	}
	success = true
	return f, nil
}

func (s *ConnectorObservationOperationConnection) Send(ctx context.Context, f contracts.ClusterObservationFrame) error {
	call, finish, err := s.begin(ctx)
	if err != nil {
		return err
	}
	success := false
	defer func() { finish(success) }()
	if !s.count(f) || contracts.WriteClusterObservationFrame(s.writer, f) != nil || !s.current(call) {
		return value.ErrUnavailable
	}
	success = true
	return nil
}

// Every successful application phase can only narrow the live stream's
// original end. No socket operation inherits a new interval from its own start.
func (s *ConnectorObservationOperationConnection) restrict(ctx context.Context, until time.Time) bool {
	s.mu.Lock()
	s.until = identity.Earlier(s.until, until)
	end := s.until
	s.mu.Unlock()
	return s.raw.SetDeadline(end) == nil && s.current(ctx)
}

func (s *ConnectorObservationOperationConnection) AnswerConnectorObservation(ctx context.Context, p contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error) {
	call, finish, err := s.begin(ctx)
	if err != nil {
		return contracts.ConnectorObservationOperationReply{}, err
	}
	success := false
	defer func() { finish(success) }()
	out, err := s.channel.AnswerConnectorObservation(call, p)
	if err != nil {
		return contracts.ConnectorObservationOperationReply{}, answerStep("channel", value.ErrUnavailable, err)
	}
	if !s.restrict(call, identity.Earlier(ownerObservationTime(out.NativeUntil), identity.Earlier(ownerObservationTime(out.SourceFreshUntil), ownerObservationTime(out.WorkloadFreshUntil)))) {
		return contracts.ConnectorObservationOperationReply{}, answerStep("restrict", value.ErrUnavailable, nil)
	}
	success = true
	return out, nil
}

func (s *ConnectorObservationOperationConnection) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	call, finish, err := s.begin(ctx)
	if err != nil {
		return value.ClusterObservationResult{}, err
	}
	success := false
	defer func() { finish(success) }()
	out, err := s.channel.ObserveCluster(call, r)
	if err != nil {
		return value.ClusterObservationResult{}, answerStep("channel", value.ErrUnavailable, err)
	}
	if !s.restrict(call, out.Interval.FreshUntil) {
		return value.ClusterObservationResult{}, answerStep("restrict", value.ErrUnavailable, nil)
	}
	success = true
	return out, nil
}

func (s *ConnectorObservationOperationConnection) AcceptObservationReceipt(ctx context.Context, r contracts.ClusterObservationReceipt) error {
	call, finish, err := s.begin(ctx)
	if err != nil {
		return err
	}
	success := false
	defer func() { finish(success) }()
	if s.channel.AcceptObservationReceipt(call, r) != nil || !s.current(call) {
		return value.ErrUnavailable
	}
	success = true
	return nil
}

// FinishObservation uses only the HTTP end-of-stream markers after the exact
// twelfth frame. A local successful Receipt parse is not a claim that the hub
// received it. Extra bytes, missing EOF or cancellation remain unavailable.
func (s *ConnectorObservationOperationConnection) FinishObservation(ctx context.Context) error {
	call, finish, err := s.begin(ctx)
	if err != nil {
		return err
	}
	success := false
	defer func() { finish(success) }()
	s.channel.mu.Lock()
	received := s.channel.received && !s.channel.failed && !s.channel.closed
	s.channel.mu.Unlock()
	s.mu.Lock()
	complete := s.frames == contracts.ClusterObservationMaximumFrames && !s.finished
	s.finished = true
	s.mu.Unlock()
	if !received || !complete || s.writer.Close() != nil {
		return value.ErrUnavailable
	}
	var extra [1]byte
	n, err := s.response.Read(extra[:])
	if n != 0 || err != io.EOF || !s.current(call) {
		return value.ErrUnavailable
	}
	success = true
	return nil
}
