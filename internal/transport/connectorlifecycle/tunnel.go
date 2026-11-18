package connectorlifecycle

import (
	"context"
	"encoding/json"
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
	Owners func(context.Context, value.OwnerBinding) ([]string, error)
	// Allowed reports whether host:port is one of the hub's services.
	Allowed func(context.Context, string) bool
	Dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

func (h *TunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fail := func(code int) { w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	target := r.Header.Get(TunnelHeader)
	if h == nil || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != TunnelPath || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values(TunnelHeader)) != 1 || target == "" {
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
	// The tunnel ends when the token expires; a revoked cluster's next
	// token is refused.
	ctx, cancel := context.WithDeadline(r.Context(), until)
	defer cancel()
	dial, endDial := context.WithTimeout(ctx, 5*time.Second)
	addresses, ok := h.destinations(dial, target)
	if !ok {
		endDial()
		fail(http.StatusForbidden)
		return
	}
	upstream, err := h.dialEndpoints(dial, addresses)
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

// A connector supplies an owner binding, never a Pod address. The federation
// dials the current Kubernetes endpoint and installed native port for that owner.
func (h *TunnelHandler) destinations(ctx context.Context, target string) ([]string, bool) {
	locator, owner := strings.CutPrefix(target, "owner/")
	if !owner {
		return []string{target}, h.Allowed(ctx, target)
	}
	var binding value.OwnerBinding
	if h.Owners == nil || json.Unmarshal([]byte(locator), &binding) != nil || !binding.Valid() {
		return nil, false
	}
	addresses, err := h.Owners(ctx, binding)
	return addresses, err == nil && len(addresses) > 0
}

// Share the original dial window between the endpoint's address families. An
// unreachable first family cannot consume the time needed to try the second.
func (h *TunnelHandler) dialEndpoints(ctx context.Context, addresses []string) (net.Conn, error) {
	until, _ := ctx.Deadline()
	for len(addresses) > 1 {
		call, cancel := context.WithTimeout(ctx, time.Until(until)/time.Duration(len(addresses)))
		conn, err := h.Dial(call, "tcp", addresses[0])
		cancel()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		addresses = addresses[1:]
	}
	return h.Dial(ctx, "tcp", addresses[0])
}

// DialOwner tunnels to the specific replica with a waiting caller.
func (c *Client) DialOwner(ctx context.Context, binding value.OwnerBinding) (net.Conn, error) {
	if !binding.Valid() {
		return nil, ErrChannel
	}
	locator, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	return c.DialTunnel(ctx, "tcp", "owner/"+string(locator))
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
// The returned conn has net.Pipe semantics: separate read and write
// deadlines that fail the blocked call with os.ErrDeadlineExceeded and keep
// the stream open.
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
	var resp *http.Response
	select {
	case r := <-done:
		if r.err != nil {
			cancel()
			writer.Close()
			return nil, r.err
		}
		resp = r.resp
	case <-ctx.Done():
		cancel()
		writer.Close()
		return nil, ctx.Err()
	}
	local, remote := net.Pipe()
	go func() {
		_, _ = io.Copy(writer, remote)
		_ = writer.Close()
	}()
	go func() {
		_, _ = io.Copy(remote, resp.Body)
		_ = remote.Close()
	}()
	return &tunnelConn{Conn: local, stop: func() { cancel(); _ = writer.Close(); _ = resp.Body.Close(); _ = remote.Close() }}, nil
}

// tunnelConn is the caller's end of a net.Pipe whose other end relays the
// tunnel stream; Close also ends the stream.
type tunnelConn struct {
	net.Conn
	once sync.Once
	stop func()
}

func (t *tunnelConn) Close() error {
	_ = t.Conn.SetDeadline(time.Time{}) // stops the pipe's deadline timers
	err := t.Conn.Close()
	t.once.Do(t.stop)
	return err
}
