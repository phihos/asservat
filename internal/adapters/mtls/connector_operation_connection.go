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
