package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/contextstart"
	"golang.org/x/net/netutil"
)

// ServerCredentials is supplied by the owning process. In hub composition this
// is the existing activated OwnerCredentials server key. Connector server keys
// have their own protected producer; a connector clientAuth leaf cannot serve.
type ServerCredentials interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Serve takes ownership of one separate private listener after validation. It
// serves the exact native Handler with h2/TLS1.3 only. Handshake admission does
// not replace the handler's current per-frame SQL, proof and serving checks.
func Serve(ctx context.Context, listener net.Listener, roots *x509.CertPool, credentials ServerCredentials, handler *Handler, connections int) error {
	return serve(ctx, listener, roots, nil, credentials, handler, nil, connections, 0)
}

// ClientRoots returns the current client-certificate roots for one handshake.
type ClientRoots func(time.Time) (*x509.CertPool, error)

// ServeWorker is Serve for the acquisition worker's own path in the hub
// (ADR-204 decision 9). Client roots are resolved for each handshake from the
// current download profile's issuer roots, so a removed trust takes effect on
// the next connection; an unavailable set refuses the handshake. These roots
// only pre-authenticate TLS: the handler's admission still verifies the exact
// worker, profile, Pod token and operation for every frame.
func ServeWorker(ctx context.Context, listener net.Listener, roots ClientRoots, credentials ServerCredentials, handler *Handler, connections int) error {
	if roots == nil || handler == nil || handler.path != contracts.NativeWorkerPath {
		return contracts.ErrNativeProtocol
	}
	return serve(ctx, listener, nil, roots, credentials, handler, nil, connections, 0)
}

// ServeWithContextStart shares the accepted native port between exactly two
// private purposes. The same serving identity and connector roots apply at TLS;
// each handler independently proves its exact current operation. Purpose socket
// reservations are disjoint and remain charged until the owned socket and its
// handler have joined. No request chooses an endpoint, lifetime or handler.
func ServeWithContextStart(ctx context.Context, listener net.Listener, roots *x509.CertPool, credentials ServerCredentials, handler *Handler, starts *contextstart.Handler, nativeConnections, startConnections int) error {
	if starts == nil || startConnections < 1 || startConnections > 64 || nativeConnections < 1 || nativeConnections+startConnections > 64 {
		return contracts.ErrNativeProtocol
	}
	return serve(ctx, listener, roots, nil, credentials, handler, starts, nativeConnections, startConnections)
}

// Exactly one of roots (fixed) and current (per handshake) supplies ClientCAs.
func serve(ctx context.Context, listener net.Listener, roots *x509.CertPool, current ClientRoots, credentials ServerCredentials, handler *Handler, starts *contextstart.Handler, nativeConnections, startConnections int) error {
	connections := nativeConnections + startConnections
	if ctx == nil || ctx.Err() != nil || listener == nil || (roots == nil) == (current == nil) || roots != nil && len(roots.Subjects()) == 0 || credentials == nil || handler == nil || nativeConnections < 1 || connections > 64 || cap(handler.slots) > nativeConnections {
		return contracts.ErrNativeProtocol
	}
	host, _, err := net.SplitHostPort(handler.host)
	if err != nil || host == "" {
		return contracts.ErrNativeProtocol
	}
	// TLS omits SNI for literal IP addresses. Every DNS-configured private
	// route instead requires its one exact original serving name. A certificate
	// with an optional bootstrap SAN must not widen these existing purposes.
	sni := host
	if net.ParseIP(host) != nil {
		sni = ""
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	// A projection worker request may park and then serve its operation for up
	// to the evidence-read window, so native connections reside up to 30 s.
	residency := 30 * time.Second
	prelude := time.Duration(0)
	if starts != nil {
		residency, prelude = 30*time.Second, 2*time.Second
	}
	owned := &nativeListener{Listener: netutil.LimitListener(listener, connections), root: root, residency: residency, prelude: prelude}
	nativeSlots := make(chan struct{}, nativeConnections)
	startSlots := make(chan struct{}, startConnections)
	defer owned.Close()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true, NextProtos: []string{"h2"}}
	if roots != nil {
		config.ClientCAs = roots.Clone()
	}
	// net/http may prepare compatibility ALPN entries internally. Enforce the
	// private protocol on the completed handshake before any HTTP request.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if root.Err() != nil || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || state.ServerName != sni || len(state.VerifiedChains) == 0 {
			return contracts.ErrNativeProtocol
		}
		return nil
	}
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName != sni || root.Err() != nil {
			return nil, contracts.ErrNativeProtocol
		}
		offersH2 := false
		for _, protocol := range hello.SupportedProtos {
			if protocol == "h2" {
				offersH2 = true
				break
			}
		}
		if !offersH2 {
			return nil, contracts.ErrNativeProtocol
		}
		connection, ok := hello.Conn.(*nativeConn)
		if !ok || connection.ctx.Err() != nil {
			return nil, contracts.ErrNativeProtocol
		}
		cert, e := credentials.GetCertificate(hello)
		if e != nil || cert == nil || cert.PrivateKey == nil || len(cert.Certificate) < 1 || len(cert.Certificate) > 4 {
			return nil, contracts.ErrNativeProtocol
		}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		now := time.Now()
		if e != nil || leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(host) != nil || root.Err() != nil || connection.ctx.Err() != nil {
			return nil, contracts.ErrNativeProtocol
		}
		// A handshake cannot extend the accepted socket's original end. Certificate
		// expiry also closes blocked I/O even if no application frame is pending.
		if connection.shorten(leaf.NotAfter) != nil {
			return nil, contracts.ErrNativeProtocol
		}
		return cert, nil
	}
	if current != nil {
		// Client roots of this one handshake; the selected config keeps every
		// callback above, including the exact-name certificate checks.
		base := config.Clone()
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello == nil || hello.ServerName != sni || root.Err() != nil {
				return nil, contracts.ErrNativeProtocol
			}
			pool, e := current(time.Now())
			if e != nil || pool == nil || len(pool.Subjects()) == 0 {
				return nil, contracts.ErrNativeProtocol
			}
			selected := base.Clone()
			selected.ClientCAs = pool
			return selected, nil
		}
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	server := &http.Server{TLSConfig: config, Protocols: protocols, HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 1, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096, MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerConnection: 64 << 10, MaxReceiveBufferPerStream: 64 << 10}, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: residency, WriteTimeout: residency, IdleTimeout: time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	server.BaseContext = func(net.Listener) context.Context { return root }
	server.ConnContext = func(_ context.Context, c net.Conn) context.Context {
		if t, ok := c.(*tls.Conn); ok {
			if b, ok := t.NetConn().(*nativeConn); ok {
				return context.WithValue(b.ctx, nativeConnectionKey{}, b)
			}
		}
		denied, stop := context.WithCancel(root)
		stop()
		return denied
	}
	// StateIdle does not mean HTTP/2's buffered END_STREAM is on the socket.
	// Let net/http finish its response and graceful GOAWAY before closing the
	// transport. The atomic request guard still forbids a second conversation;
	// original socket deadlines and joined purpose reservations remain binding.
	server.SetKeepAlivesEnabled(false)
	var mu sync.Mutex
	var requests sync.WaitGroup
	closing := false
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, ok := r.Context().Value(nativeConnectionKey{}).(*nativeConn)
		if !ok || !connection.beginRequest() {
			// One conversation per accepted socket, including denied requests. HTTP/2
			// concurrency limits alone would permit unbounded sequential attempts.
			if ok {
				_ = connection.Close()
			}
			return
		}
		defer close(connection.handlerDone)
		if r.TLS == nil || r.TLS.ServerName != sni || r.Host != handler.host {
			unavailable(w)
			return
		}
		selected, lifetime, slots := http.Handler(handler), 30*time.Second, nativeSlots
		if starts != nil && r.RequestURI == contracts.APIContextStartPath {
			selected, lifetime, slots = starts, 30*time.Second, startSlots
		} else if r.RequestURI != handler.path {
			unavailable(w)
			return
		}
		select {
		case slots <- struct{}{}:
			connection.mu.Lock()
			connection.release = func() { <-slots }
			connection.mu.Unlock()
		default:
			unavailable(w)
			return
		}
		if connection.finishPrelude() != nil || connection.shorten(connection.accepted.Add(lifetime)) != nil {
			return
		}
		connection.mu.Lock()
		until := connection.until
		connection.mu.Unlock()
		call, end := context.WithDeadline(r.Context(), until)
		interrupted := make(chan struct{})
		stopCall := context.AfterFunc(call, func() {
			connection.cancel()
			_ = connection.Conn.Close()
			close(interrupted)
		})
		defer func() {
			if !stopCall() {
				<-interrupted
			}
			end()
		}()
		mu.Lock()
		if closing || root.Err() != nil || call.Err() != nil {
			mu.Unlock()
			unavailable(w)
			return
		}
		requests.Add(1)
		mu.Unlock()
		defer requests.Done()
		selected.ServeHTTP(w, r.WithContext(call))
	})
	callback := make(chan struct{})
	stop := context.AfterFunc(root, func() { _ = server.Close(); close(callback) })
	err = server.Serve(tls.NewListener(owned, config))
	cancel()
	_ = server.Close()
	if !stop() {
		<-callback
	}
	mu.Lock()
	closing = true
	mu.Unlock()
	// Close cancels and interrupts all owned I/O. Do not return process/listener
	// ownership until every accepted handler actually joins. A timeout is not
	// proof that a stalled child terminated.
	requests.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return contracts.ErrNativeProtocol
	}
	return err
}

type nativeListener struct {
	net.Listener
	root               context.Context
	residency, prelude time.Duration
}

func (l *nativeListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	accepted := time.Now()
	residency := l.residency
	if residency == 0 {
		residency = 10 * time.Second
	}
	until := accepted.Add(residency)
	ctx, cancel := context.WithDeadline(l.root, until)
	c := &nativeConn{Conn: raw, ctx: ctx, cancel: cancel, accepted: accepted, until: until, callback: make(chan struct{}), handlerDone: make(chan struct{})}
	if l.prelude > 0 {
		c.preludeDone = make(chan struct{})
		timer := time.AfterFunc(time.Until(accepted.Add(l.prelude)), func() {
			cancel()
			_ = raw.Close()
			close(c.preludeDone)
		})
		c.stopPrelude = timer.Stop
	}
	c.stop = context.AfterFunc(ctx, func() { _ = raw.Close(); close(c.callback) })
	if ctx.Err() != nil || raw.SetDeadline(until) != nil {
		_ = c.Close()
		return nil, contracts.ErrNativeProtocol
	}
	return c, nil
}

type nativeConn struct {
	net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	accepted    time.Time
	until       time.Time
	stopPrelude func() bool
	preludeDone chan struct{}
	handlerDone chan struct{}
	release     func()
	closing     bool
	stop        func() bool
	callback    chan struct{}
	once        sync.Once
	err         error
	request     atomic.Bool
}

type nativeConnectionKey struct{}

// beginRequest and Close serialize the boundary before any purpose slot can be
// acquired. A close racing the first HTTP request must either join that request
// or prevent it; it cannot complete and leave a later slot permanently charged.
func (c *nativeConn) beginRequest() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closing && c.ctx.Err() == nil && c.request.CompareAndSwap(false, true)
}

func (c *nativeConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closing = true
		requested := c.request.Load()
		c.mu.Unlock()
		c.cancel()
		_ = c.finishPrelude()
		c.err = c.Conn.Close()
		if !c.stop() {
			<-c.callback
		}
		if requested {
			<-c.handlerDone
		}
		c.mu.Lock()
		release := c.release
		c.release = nil
		c.mu.Unlock()
		if release != nil {
			release()
		}
	})
	return c.err
}

// finishPrelude joins the fixed original TLS/header timer. A timer that already
// fired cannot be replaced by observing a valid path or by a later TLS result.
func (c *nativeConn) finishPrelude() error {
	c.mu.Lock()
	stop, done := c.stopPrelude, c.preludeDone
	c.stopPrelude = nil
	c.mu.Unlock()
	if stop != nil && !stop() {
		<-done
	}
	return c.ctx.Err()
}

func (c *nativeConn) shorten(until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until.Before(c.until) {
		c.until = until
	}
	return c.Conn.SetDeadline(c.until)
}
func (c *nativeConn) limit(t time.Time) time.Time {
	if t.IsZero() || c.until.Before(t) {
		return c.until
	}
	return t
}
func (c *nativeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetDeadline(c.limit(t))
}
func (c *nativeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetReadDeadline(c.limit(t))
}
func (c *nativeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetWriteDeadline(c.limit(t))
}
