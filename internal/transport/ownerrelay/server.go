package ownerrelay

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
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"golang.org/x/net/netutil"
)

// ServerCredentials is supplied by the process-owned server key. Closing the
// shared credential pair remains its supervisor's responsibility; Serve owns
// all sockets and request contexts created from the supplied listener.
type ServerCredentials interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	ServingCertificate() (value.OwnerCertificate, error)
}

// Serve has one fixed HTTP/1.1, TLS 1.3 profile. No default mux, access logging,
// HTTP/2, resumption, hijacking, unbounded graceful drain or plaintext listener.
func Serve(ctx context.Context, listener net.Listener, roots *x509.CertPool, credentials ServerCredentials, handler *Handler, connections int) error {
	if ctx == nil || listener == nil || roots == nil || len(roots.Subjects()) == 0 || credentials == nil || handler == nil || connections < 1 || connections > 64 {
		return value.ErrInvalid
	}
	cert, err := credentials.ServingCertificate()
	if err != nil || !cert.Valid(handler.now()) || cert.Usage != "server" || cert.Binding != handler.binding || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	owned := &lifetimeListener{Listener: netutil.LimitListener(listener, connections), root: root, credentials: credentials, binding: handler.binding, now: handler.now}
	defer owned.Close()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots.Clone(), GetCertificate: credentials.GetCertificate, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	var mu sync.Mutex
	var requests sync.WaitGroup
	closing := false
	server := &http.Server{TLSConfig: config, Protocols: protocols, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	server.BaseContext = func(net.Listener) context.Context { return root }
	server.ConnContext = func(_ context.Context, c net.Conn) context.Context {
		// tls.NewListener must remain outermost so net/http sees actual TLS.
		if t, ok := c.(*tls.Conn); ok {
			if b, ok := t.NetConn().(*lifetimeConn); ok {
				return b.ctx
			}
		}
		denied, end := context.WithCancel(root)
		end()
		return denied
	}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if closing || root.Err() != nil {
			mu.Unlock()
			w.Header().Set("Connection", "close")
			w.WriteHeader(503)
			return
		}
		requests.Add(1)
		mu.Unlock()
		defer requests.Done()
		handler.ServeHTTP(w, r)
	})
	closed := make(chan struct{})
	stop := context.AfterFunc(root, func() { _ = server.Close(); close(closed) })
	err = server.Serve(tls.NewListener(owned, config))
	cancel()
	_ = server.Close()
	if !stop() {
		<-closed
	}
	mu.Lock()
	closing = true
	mu.Unlock()
	joined := make(chan struct{})
	go func() { requests.Wait(); close(joined) }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-joined:
	case <-timer.C:
		return value.ErrUnavailable
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return value.ErrUnavailable
	}
	return err
}

type lifetimeListener struct {
	net.Listener
	root        context.Context
	credentials ServerCredentials
	binding     value.OwnerBinding
	now         func() time.Time
}

func (l *lifetimeListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cert, err := l.credentials.ServingCertificate()
	now := l.now()
	if err != nil || l.root.Err() != nil || !cert.Valid(now) || cert.Binding != l.binding || cert.Usage != "server" {
		raw.Close()
		return nil, value.ErrUnavailable
	}
	until := earlier(now.Add(35*time.Second), cert.NotAfter)
	ctx, cancel := context.WithDeadline(l.root, until)
	c := &lifetimeConn{Conn: raw, ctx: ctx, cancel: cancel, until: until}
	context.AfterFunc(ctx, func() { _ = c.Close() })
	return c, nil
}

type lifetimeConn struct {
	net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	until  time.Time
	once   sync.Once
	err    error
}

func (c *lifetimeConn) Close() error {
	c.once.Do(func() { c.cancel(); c.err = c.Conn.Close() })
	return c.err
}
func (c *lifetimeConn) limit(t time.Time) time.Time {
	if t.IsZero() {
		return c.until
	}
	return earlier(t, c.until)
}
func (c *lifetimeConn) SetDeadline(t time.Time) error     { return c.Conn.SetDeadline(c.limit(t)) }
func (c *lifetimeConn) SetReadDeadline(t time.Time) error { return c.Conn.SetReadDeadline(c.limit(t)) }
func (c *lifetimeConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.limit(t))
}
