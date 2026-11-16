package connectorlifecycle

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// The tunnel carries a connector's connection to one of the hub's in-cluster
// services (owners, key service, object store) over its hub connection, so a
// workload cluster reaches the hub through one URL (REQ-FED-002). The
// connector keeps its own TLS session with the service inside the tunnel:
// the hub relays bytes and never terminates it.
const (
	TunnelPath   = "/v1/connector-tunnel"
	TunnelHeader = "Asservat-Tunnel"
)

// TunnelTokens verifies a connector token and returns its expiry, which
// ends the tunnel.
type TunnelTokens interface {
	VerifyConnectorUntil(context.Context, string) (value.ConnectorCluster, time.Time, error)
}

// TunnelHandler relays one authenticated connector stream to a target the
// hub allows.
type TunnelHandler struct {
	Tokens TunnelTokens
	// Allowed reports whether host:port is one of the hub's services.
	Allowed func(context.Context, string) bool
	Dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

func (h *TunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fail := func(code int) { w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	target := r.Header.Get(TunnelHeader)
	if h == nil || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != TunnelPath || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 1 || target == "" {
		fail(http.StatusBadRequest)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		fail(http.StatusUnauthorized)
		return
	}
	verify, endVerify := context.WithTimeout(r.Context(), 5*time.Second)
	_, until, err := h.Tokens.VerifyConnectorUntil(verify, token)
	endVerify()
	if err != nil {
		fail(http.StatusUnauthorized)
		return
	}
	if !h.Allowed(r.Context(), target) {
		fail(http.StatusForbidden)
		return
	}
	// The tunnel ends when the token expires; a revoked cluster's next
	// token is refused.
	ctx, cancel := context.WithDeadline(r.Context(), until)
	defer cancel()
	dial, endDial := context.WithTimeout(ctx, 5*time.Second)
	upstream, err := h.Dial(dial, "tcp", target)
	endDial()
	if err != nil {
		fail(http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	control := http.NewResponseController(w)
	if control.EnableFullDuplex() != nil {
		fail(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stop()
	up := make(chan struct{})
	go func() {
		defer close(up)
		_, _ = io.Copy(upstream, r.Body)
		if c, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	_, _ = io.Copy(flushWriter{w, control}, upstream)
	upstream.Close()
	<-up
}

type flushWriter struct {
	w io.Writer
	c *http.ResponseController
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		err = f.c.Flush()
	}
	return n, err
}

// DialTunnel opens a tunnel to address (host:port) over the hub connection.
// The returned conn is a plain byte stream; deadlines close it.
func (c *Client) DialTunnel(ctx context.Context, _, address string) (net.Conn, error) {
	if c == nil || ctx == nil {
		return nil, ErrChannel
	}
	stream, cancel := context.WithCancel(context.WithoutCancel(ctx))
	body, writer := io.Pipe()
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := c.open(stream, TunnelPath, http.Header{TunnelHeader: {address}}, body)
		done <- result{resp, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			cancel()
			writer.Close()
			return nil, r.err
		}
		return &tunnelConn{r: r.resp.Body, w: writer, cancel: cancel, address: address}, nil
	case <-ctx.Done():
		cancel()
		writer.Close()
		return nil, ctx.Err()
	}
}

type tunnelConn struct {
	r       io.ReadCloser
	w       *io.PipeWriter
	cancel  context.CancelFunc
	address string
	mu      sync.Mutex
	timer   *time.Timer
	once    sync.Once
}

func (t *tunnelConn) Read(p []byte) (int, error)  { return t.r.Read(p) }
func (t *tunnelConn) Write(p []byte) (int, error) { return t.w.Write(p) }
func (t *tunnelConn) Close() error {
	t.once.Do(func() {
		t.cancel()
		_ = t.w.Close()
		_ = t.r.Close()
	})
	return nil
}
func (t *tunnelConn) LocalAddr() net.Addr  { return tunnelAddr("connector") }
func (t *tunnelConn) RemoteAddr() net.Addr { return tunnelAddr(t.address) }

// SetDeadline closes the tunnel at t: every caller uses a deadline as the
// connection's end, never to resume after a timeout.
func (t *tunnelConn) SetDeadline(at time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	if !at.IsZero() {
		t.timer = time.AfterFunc(time.Until(at), func() { _ = t.Close() })
	}
	return nil
}
func (t *tunnelConn) SetReadDeadline(at time.Time) error  { return t.SetDeadline(at) }
func (t *tunnelConn) SetWriteDeadline(at time.Time) error { return t.SetDeadline(at) }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "asservat-tunnel" }
func (a tunnelAddr) String() string  { return string(a) }
