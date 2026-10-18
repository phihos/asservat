package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"golang.org/x/net/netutil"
)

// ServerCredentials is the owning process's serving key for the one
// worker-facing name. Serve never loads, selects or renews a key itself.
type ServerCredentials interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Socket residency from accept: TLS and headers (5s), the handler's own
// thirty-second operation, and its final write.
const serveResidency = 40 * time.Second

// Serve is the private enrollment listener ADR-072 requires: TLS 1.3 and
// HTTP/1.1 only, one fixed server name and HTTP authority, no client
// certificate (the dedicated Pod token is the initial proof), no session
// resumption, keep-alive, redirect or other route, a 20 KiB header ceiling
// for the bounded projected token, bounded sockets and an absolute socket
// lifetime that a certificate expiry can only shorten. It takes ownership of
// listener and returns only after every started handler has returned.
func Serve(ctx context.Context, listener net.Listener, authority string, credentials ServerCredentials, handler *Handler, connections int) error {
	host, port, err := net.SplitHostPort(authority)
	n, perr := strconv.Atoi(port)
	if ctx == nil || ctx.Err() != nil || listener == nil || err != nil || perr != nil || n < 1 || n > 65535 || host == "" || net.ParseIP(host) != nil || credentials == nil || handler == nil || connections < 1 || connections > 64 {
		return artifact.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	owned := &lifetimeListener{Listener: netutil.LimitListener(listener, connections), root: root}
	defer owned.Close()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.NoClientCert, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName != host || root.Err() != nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		connection, ok := hello.Conn.(*lifetimeConn)
		if !ok || connection.ctx.Err() != nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		cert, e := credentials.GetCertificate(hello)
		if e != nil || cert == nil || cert.PrivateKey == nil || len(cert.Certificate) < 1 || len(cert.Certificate) > 4 {
			return nil, artifact.ErrDownloadUnavailable
		}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		now := time.Now()
		if e != nil || leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(host) != nil || root.Err() != nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		// A handshake cannot extend the accepted socket's original end.
		if connection.shorten(leaf.NotAfter) != nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		return cert, nil
	}
	config.VerifyConnection = func(s tls.ConnectionState) error {
		if root.Err() != nil || s.Version != tls.VersionTLS13 || s.DidResume || s.ServerName != host || len(s.PeerCertificates) != 0 || s.NegotiatedProtocol != "" && s.NegotiatedProtocol != "http/1.1" {
			return artifact.ErrDownloadUnavailable
		}
		return nil
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	server := &http.Server{TLSConfig: config, Protocols: protocols, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: serveResidency, WriteTimeout: serveResidency, IdleTimeout: time.Second, MaxHeaderBytes: 20 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	server.BaseContext = func(net.Listener) context.Context { return root }
	server.ConnContext = func(_ context.Context, c net.Conn) context.Context {
		if t, ok := c.(*tls.Conn); ok {
			if b, ok := t.NetConn().(*lifetimeConn); ok {
				return b.ctx
			}
		}
		denied, stop := context.WithCancel(root)
		stop()
		return denied
	}
	// One request per socket: each enrollment opens a fresh handshake that
	// rechecks the current serving certificate before the Pod token is sent.
	server.SetKeepAlivesEnabled(false)
	var mu sync.Mutex
	var active sync.WaitGroup
	closing := false
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if closing || root.Err() != nil || r.Context().Err() != nil {
			mu.Unlock()
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		active.Add(1)
		mu.Unlock()
		defer active.Done()
		// Both the socket and request use the one fixed name, not merely Host.
		if r.TLS == nil || r.TLS.ServerName != host || r.Host != authority {
			w.Header().Set("Cache-Control", "no-store, private")
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		handler.ServeHTTP(w, r)
	})
	done := make(chan struct{})
	stop := context.AfterFunc(root, func() { _ = server.Close(); close(done) })
	err = server.Serve(tls.NewListener(owned, config))
	cancel()
	_ = server.Close()
	if !stop() {
		<-done
	}
	mu.Lock()
	closing = true
	mu.Unlock()
	// Close cancelled every request context and closed every socket. Do not
	// return listener ownership until every started handler has returned.
	active.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return artifact.ErrDownloadUnavailable
	}
	return err
}

type lifetimeListener struct {
	net.Listener
	root context.Context
}

func (l *lifetimeListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	until := time.Now().Add(serveResidency)
	ctx, cancel := context.WithDeadline(l.root, until)
	c := &lifetimeConn{Conn: raw, ctx: ctx, cancel: cancel, until: until}
	context.AfterFunc(ctx, func() { _ = c.Close() })
	if raw.SetDeadline(until) != nil {
		// A closed socket fails its handshake; the server keeps accepting.
		_ = c.Close()
	}
	return c, nil
}

type lifetimeConn struct {
	net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	until  time.Time
	once   sync.Once
	err    error
}

func (c *lifetimeConn) Close() error {
	c.once.Do(func() { c.cancel(); c.err = c.Conn.Close() })
	return c.err
}
func (c *lifetimeConn) shorten(until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until.Before(c.until) {
		c.until = until
	}
	return c.Conn.SetDeadline(c.until)
}
func (c *lifetimeConn) limit(t time.Time) time.Time {
	if t.IsZero() || c.until.Before(t) {
		return c.until
	}
	return t
}
func (c *lifetimeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetDeadline(c.limit(t))
}
func (c *lifetimeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetReadDeadline(c.limit(t))
}
func (c *lifetimeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetWriteDeadline(c.limit(t))
}
