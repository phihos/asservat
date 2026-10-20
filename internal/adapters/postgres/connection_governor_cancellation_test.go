package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This speaks the actual pgx startup/query/cancel protocol over loopback. It
// deliberately leaves one query unanswered; no external database is needed.
type governorProtocolServer struct {
	listener net.Listener
	tls      *tls.Config
	blocked  chan struct{}
	ended    chan struct{}
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	starts   atomic.Int32
	cancels  atomic.Int32
	blocks   atomic.Int32
	ends     atomic.Int32
}

func newGovernorProtocolServer(t *testing.T, encrypted bool) (*governorProtocolServer, *tls.Config) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &governorProtocolServer{listener: listener, blocked: make(chan struct{}, 1), ended: make(chan struct{}, 1), conns: make(map[net.Conn]struct{})}
	var clientTLS *tls.Config
	if encrypted {
		certServer := httptest.NewTLSServer(http.NotFoundHandler())
		s.tls = certServer.TLS.Clone()
		roots := x509.NewCertPool()
		roots.AddCert(certServer.Certificate())
		clientTLS = &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
		certServer.Close()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[conn] = struct{}{}
			s.mu.Unlock()
			s.wg.Add(1)
			go s.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s, clientTLS
}

func (s *governorProtocolServer) serve(raw net.Conn) {
	defer s.wg.Done()
	defer func() {
		_ = raw.Close()
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
	}()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := raw
	backend := pgproto3.NewBackend(conn, conn)
	message, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := message.(*pgproto3.SSLRequest); ok {
		if s.tls == nil {
			return
		}
		if _, err = raw.Write([]byte("S")); err != nil {
			return
		}
		conn = tls.Server(raw, s.tls)
		backend = pgproto3.NewBackend(conn, conn)
		message, err = backend.ReceiveStartupMessage()
		if err != nil {
			return
		}
	}
	switch message.(type) {
	case *pgproto3.CancelRequest:
		s.cancels.Add(1)
		return // EOF acknowledges the finite cancellation exchange.
	case *pgproto3.StartupMessage:
	default:
		return
	}
	id := s.starts.Add(1)
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: uint32(id), SecretKey: []byte{1, 2, 3, 4}})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if backend.Flush() != nil {
		return
	}
	for {
		message, err := backend.Receive()
		if err != nil {
			return
		}
		switch message := message.(type) {
		case *pgproto3.Terminate:
			s.ends.Add(1)
			s.ended <- struct{}{}
			return
		case *pgproto3.Query:
			command, status := "SELECT 1", byte('I')
			switch strings.ToLower(message.String) {
			case "select blocked":
				s.blocks.Add(1)
				select {
				case s.blocked <- struct{}{}:
				default:
				}
				continue
			case "begin":
				command, status = "BEGIN", 'T'
			case "rollback":
				command = "ROLLBACK"
			}
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte(command)})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: status})
			if backend.Flush() != nil {
				return
			}
		default:
			return
		}
	}
}

type governorSocketCounts struct {
	active atomic.Int32
	peak   atomic.Int32
	dials  atomic.Int32
}

func (c *governorSocketCounts) dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	c.dials.Add(1)
	n := c.active.Add(1)
	for old := c.peak.Load(); n > old && !c.peak.CompareAndSwap(old, n); old = c.peak.Load() {
	}
	return &governorCountedSocket{Conn: conn, counts: c}, nil
}

type governorCountedSocket struct {
	net.Conn
	counts *governorSocketCounts
	once   sync.Once
	err    error
	closed atomic.Bool
}

func (c *governorCountedSocket) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.closed.Store(true)
		// Keep counting the socket until the actual underlying Close returns.
		c.counts.active.Add(-1)
	})
	return c.err
}

func governorRawSocket(conn *pgx.Conn) *governedConn {
	raw := conn.PgConn().Conn()
	if encrypted, ok := raw.(*tls.Conn); ok {
		raw = encrypted.NetConn()
	}
	return raw.(*governedConn)
}

func governorProtocolPool(t *testing.T, s *governorProtocolServer, clientTLS *tls.Config, counts *governorSocketCounts, hot bool, beforeClose func(*pgx.Conn)) *pgxpool.Pool {
	t.Helper()
	config := governedTestConfig(t, counts.dial)
	config.ConnConfig.Host = "127.0.0.1"
	config.ConnConfig.Port = uint16(s.listener.Addr().(*net.TCPAddr).Port)
	config.ConnConfig.TLSConfig = clientTLS
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	config.BeforeClose = beforeClose
	hotSlots := 0
	if hot {
		hotSlots = 1
	}
	governor, err := NewSQLConnectionGovernor(1, hotSlots)
	if err != nil {
		t.Fatal(err)
	}
	if err = governor.Govern(config, hot); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestSQLConnectionGovernorCanceledQueryReleasesSocketBeforeNextTransaction(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		protocol := "tcp"
		if encrypted {
			protocol = "tls"
		}
		for _, expired := range []bool{false, true} {
			ending := "cancel"
			if expired {
				ending = "deadline"
			}
			t.Run(protocol+"/"+ending, func(t *testing.T) {
				s, clientTLS := newGovernorProtocolServer(t, encrypted)
				counts := &governorSocketCounts{}
				var hooks, closedBeforeHook atomic.Int32
				pool := governorProtocolPool(t, s, clientTLS, counts, true, func(conn *pgx.Conn) {
					hooks.Add(1)
					if governorRawSocket(conn).Conn.(*governorCountedSocket).closed.Load() {
						closedBeforeHook.Add(1)
					}
				})
				setup, stopSetup := context.WithTimeout(context.Background(), 2*time.Second)
				defer stopSetup()
				first, err := pool.Acquire(setup)
				if err != nil {
					t.Fatal(err)
				}
				original := first.Conn()
				physical := governorRawSocket(original)
				cleanup := original.PgConn().CleanupDone()
				// Also make a failing pre-fix test terminate promptly: its
				// known retained socket is closed before pool.Close joins it.
				t.Cleanup(func() { _ = physical.Close() })
				if _, err = first.Exec(setup, "select 1"); err != nil {
					first.Release()
					t.Fatal(err)
				}
				first.Release()
				current, err := pool.Acquire(setup)
				if err != nil {
					t.Fatal(err)
				}
				if current.Conn() != original || s.starts.Load() != 1 || hooks.Load() != 0 {
					current.Release()
					t.Fatal("healthy hot connection was not reused")
				}
				query, cancel := context.WithCancel(context.Background())
				expected := error(context.Canceled)
				if expired {
					cancel()
					query, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
					expected = context.DeadlineExceeded
				}
				defer cancel()
				result := make(chan error, 1)
				go func() {
					_, err := current.Exec(query, "select blocked")
					result <- err
				}()
				select {
				case <-s.blocked:
				case <-setup.Done():
					cancel()
					<-result
					current.Release()
					t.Fatal("query did not reach the server")
				}
				if !expired {
					cancel()
				}
				if err = <-result; !errors.Is(err, expected) {
					current.Release()
					t.Fatalf("cancellation classification changed: %v", err)
				}
				current.Release()
				next, stopNext := context.WithTimeout(context.Background(), time.Second)
				defer stopNext()
				tx, err := pool.BeginTx(next, pgx.TxOptions{})
				if err != nil {
					t.Fatalf("next BeginTx missed its original one-second deadline after canceled query: %v", err)
				}
				select {
				case <-cleanup:
				default:
					_ = tx.Rollback(next)
					t.Fatal("next transaction started before original cleanup joined")
				}
				if err = tx.Rollback(next); err != nil {
					t.Fatal(err)
				}
				pool.Close()
				select {
				case <-s.ended:
				case <-next.Done():
					t.Fatal("healthy hot connection did not send Terminate")
				}
				if got := counts.peak.Load(); got != 1 {
					t.Fatalf("physical socket cap exceeded, including cancellation socket: %d", got)
				}
				if counts.active.Load() != 0 || counts.dials.Load() != 3 || s.starts.Load() != 2 || s.cancels.Load() != 1 || s.blocks.Load() != 1 {
					t.Fatalf("unexpected lifecycle: active=%d dials=%d startups=%d cancel=%d originalQueries=%d",
						counts.active.Load(), counts.dials.Load(), s.starts.Load(), s.cancels.Load(), s.blocks.Load())
				}
				if hooks.Load() != 2 || closedBeforeHook.Load() != 0 || s.ends.Load() != 1 {
					t.Fatalf("prior hook or healthy graceful close changed: hooks=%d closedBeforeHook=%d terminate=%d",
						hooks.Load(), closedBeforeHook.Load(), s.ends.Load())
				}
			})
		}
	}
}

func TestSQLConnectionGovernorHealthyColdConnectionClosesGracefully(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		protocol := "tcp"
		if encrypted {
			protocol = "tls"
		}
		t.Run(protocol, func(t *testing.T) {
			s, clientTLS := newGovernorProtocolServer(t, encrypted)
			counts := &governorSocketCounts{}
			var hooks, closedBeforeHook atomic.Int32
			pool := governorProtocolPool(t, s, clientTLS, counts, false, func(conn *pgx.Conn) {
				hooks.Add(1)
				if governorRawSocket(conn).Conn.(*governorCountedSocket).closed.Load() {
					closedBeforeHook.Add(1)
				}
			})
			call, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := pool.Acquire(call)
			if err != nil {
				t.Fatal(err)
			}
			cleanup := conn.Conn().PgConn().CleanupDone()
			if _, err = conn.Exec(call, "select 1"); err != nil {
				conn.Release()
				t.Fatal(err)
			}
			conn.Release()
			select {
			case <-cleanup:
			case <-call.Done():
				t.Fatal("healthy cold connection did not close within original call")
			}
			pool.Close()
			select {
			case <-s.ended:
			case <-call.Done():
				t.Fatal("healthy cold connection did not send Terminate")
			}
			if hooks.Load() != 1 || closedBeforeHook.Load() != 0 || s.ends.Load() != 1 || s.cancels.Load() != 0 || counts.active.Load() != 0 || counts.peak.Load() != 1 {
				t.Fatalf("cold cleanup changed: hooks=%d closedBeforeHook=%d terminate=%d cancel=%d active=%d peak=%d",
					hooks.Load(), closedBeforeHook.Load(), s.ends.Load(), s.cancels.Load(), counts.active.Load(), counts.peak.Load())
			}
		})
	}
}
