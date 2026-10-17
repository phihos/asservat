package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ServerNameRouter splits one TCP listener by the TLS ClientHello server name
// without terminating TLS (ADR-190 step 6). Each child listener feeds an
// unchanged server that keeps its own TLS configuration, client
// authentication and connection slots. An unknown name, a slow or oversized
// ClientHello, or a child that is closed closes the connection. Nothing is
// written to the client before its own server takes over.
type ServerNameRouter struct {
	listener net.Listener
	ctx      context.Context
	children map[string]*routedListener
	peeks    chan struct{}
}

// Bounds on the unauthenticated peek: a ClientHello fits in one record.
const (
	serverNamePeekTimeout = 2 * time.Second
	serverNamePeekBytes   = 16 << 10
	serverNamePeeks       = 16
)

var errServerNamePeeked = errors.New("server name peeked")

func NewServerNameRouter(ctx context.Context, listener net.Listener, names ...string) (*ServerNameRouter, error) {
	if ctx == nil || listener == nil || len(names) < 1 || len(names) > 4 {
		return nil, contracts.ErrNativeProtocol
	}
	r := &ServerNameRouter{listener: listener, ctx: ctx, children: map[string]*routedListener{}, peeks: make(chan struct{}, serverNamePeeks)}
	for _, name := range names {
		if r.children[name] != nil {
			return nil, contracts.ErrNativeProtocol
		}
		r.children[name] = &routedListener{addr: listener.Addr(), conns: make(chan net.Conn), done: make(chan struct{})}
	}
	return r, nil
}

// Listener is the child for name; it must be one of the router's names.
func (r *ServerNameRouter) Listener(name string) net.Listener { return r.children[name] }

// Run accepts until the listener closes or ctx ends, then closes every child.
func (r *ServerNameRouter) Run() error {
	var classify sync.WaitGroup
	defer func() {
		r.listener.Close()
		classify.Wait()
		for _, child := range r.children {
			_ = child.Close()
		}
	}()
	stop := context.AfterFunc(r.ctx, func() { r.listener.Close() })
	defer stop()
	for {
		select {
		case r.peeks <- struct{}{}:
		case <-r.ctx.Done():
			return r.ctx.Err()
		}
		conn, err := r.listener.Accept()
		if err != nil {
			<-r.peeks
			if r.ctx.Err() != nil {
				return r.ctx.Err()
			}
			return err
		}
		classify.Add(1)
		go func() {
			defer classify.Done()
			r.route(conn)
		}()
	}
}

func (r *ServerNameRouter) route(conn net.Conn) {
	name, replay, ok := peekServerName(conn)
	<-r.peeks
	child := r.children[name]
	if !ok || child == nil {
		conn.Close()
		return
	}
	select {
	case child.conns <- replay:
	case <-child.done:
		conn.Close()
	case <-r.ctx.Done():
		conn.Close()
	}
}

// peekServerName lets crypto/tls parse the ClientHello from a read-only copy
// and stops at the server name. The returned connection replays the bytes.
func peekServerName(conn net.Conn) (string, net.Conn, bool) {
	if conn.SetReadDeadline(time.Now().Add(serverNamePeekTimeout)) != nil {
		return "", nil, false
	}
	var seen bytes.Buffer
	var name string
	peeked := false
	err := tls.Server(readOnlyConn{conn, io.TeeReader(io.LimitReader(conn, serverNamePeekBytes), &seen)}, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		name, peeked = hello.ServerName, true
		return nil, errServerNamePeeked
	}}).Handshake()
	if !peeked || !errors.Is(err, errServerNamePeeked) || conn.SetReadDeadline(time.Time{}) != nil {
		return "", nil, false
	}
	return name, &replayConn{Conn: conn, reader: io.MultiReader(&seen, conn)}, true
}

// readOnlyConn discards the peek's own handshake writes (its alert).
type readOnlyConn struct {
	net.Conn
	reader io.Reader
}

func (c readOnlyConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c readOnlyConn) Write(b []byte) (int, error) { return 0, errServerNamePeeked }

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type routedListener struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *routedListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *routedListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}
func (l *routedListener) Addr() net.Addr { return l.addr }
