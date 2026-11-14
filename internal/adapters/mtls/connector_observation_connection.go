package mtls

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ConnectorObservationConnection retains the actual stream and its matching
// private channel as one value. A caller cannot pair an independent TLS state
// or producer with the socket. One phase owns it at a time. Close cancels and
// joins admitted reads, writes and native proof work before releasing the slot.
type ConnectorObservationConnection struct {
	ctx       context.Context
	cancel    context.CancelFunc
	stopChild context.CancelFunc
	raw       net.Conn
	reader    *io.PipeReader
	writer    *io.PipeWriter
	response  io.ReadCloser
	transport *http.Transport
	channel   *ConnectorObservationChannel
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

func newConnectorObservationConnection(ctx context.Context, cancel, stopChild context.CancelFunc, raw net.Conn, reader *io.PipeReader, writer *io.PipeWriter, response io.ReadCloser, transport *http.Transport, channel *ConnectorObservationChannel, hello contracts.ClusterObservationHello, helloBytes int, now func() time.Time, release func()) *ConnectorObservationConnection {
	until, _ := ctx.Deadline()
	s := &ConnectorObservationConnection{ctx: ctx, cancel: cancel, stopChild: stopChild, raw: raw, reader: reader, writer: writer, response: response, transport: transport, channel: channel, hello: hello, now: now, frames: 1, bytes: helloBytes + 5, until: until, done: make(chan struct{})}
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

func (s *ConnectorObservationConnection) Context() context.Context                 { return s.ctx }
func (s *ConnectorObservationConnection) Hello() contracts.ClusterObservationHello { return s.hello }
func (s *ConnectorObservationConnection) Close() error {
	if s != nil {
		s.cancel()
		<-s.done
	}
	return nil
}

func (s *ConnectorObservationConnection) count(f contracts.ClusterObservationFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frames >= contracts.ClusterObservationMaximumFrames || len(f.Payload) < 1 || len(f.Payload) > contracts.ClusterObservationExchangeBytes-s.bytes-5 {
		return false
	}
	s.frames++
	s.bytes += len(f.Payload) + 5
	return true
}
