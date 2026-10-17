package integration

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type fleetObservationCommitLoss struct {
	armed, lost atomic.Bool
	holdLock    atomic.Bool
	lockAborted chan struct{}
	releaseLock chan struct{}
	releaseOnce sync.Once
}

func (f *fleetObservationCommitLoss) release() { f.releaseOnce.Do(func() { close(f.releaseLock) }) }

// This serialized fixture executes exactly one one-column integer statement:
// the fixed observation producer. Basis/read/clock statements have different
// arity/types. Accept only its closed disposition 3, never arbitrary error text.
func fleetObservationLockDisposition(body []byte) bool {
	if len(body) < 6 || binary.BigEndian.Uint16(body[:2]) != 1 {
		return false
	}
	n := binary.BigEndian.Uint32(body[2:6])
	if n == 4 && len(body) == 10 {
		return binary.BigEndian.Uint32(body[6:]) == 3
	}
	return n == 1 && len(body) == 7 && body[6] == '3'
}

// An owned test-only TLS bridge drops exactly one successful PostgreSQL COMMIT
// CommandComplete. Actual SQL has committed; the client receives no commit
// acknowledgement. No protocol payload, credentials or SQL are logged.
func fleetObservationLostCommitConfig(t *testing.T, original, backend *pgx.ConnConfig) (*pgx.ConnConfig, *fleetObservationCommitLoss) {
	t.Helper()
	fault := &fleetObservationCommitLoss{lockAborted: make(chan struct{}), releaseLock: make(chan struct{})}
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(cert.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[raw] = struct{}{}
			mu.Unlock()
			work.Add(1)
			go func() {
				defer work.Done()
				defer raw.Close()
				defer func() { mu.Lock(); delete(connections, raw); mu.Unlock() }()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				var ssl [8]byte
				if _, err := io.ReadFull(raw, ssl[:]); err != nil || !bytes.Equal(ssl[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
					return
				}
				if _, err := raw.Write([]byte("S")); err != nil {
					return
				}
				conn := tls.Server(raw, cert.TLS.Clone())
				if conn.Handshake() != nil {
					return
				}
				defer conn.Close()
				up, err := net.DialTimeout("tcp", net.JoinHostPort(backend.Host, strconv.Itoa(int(backend.Port))), time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				_ = raw.SetDeadline(time.Time{})
				sent := make(chan struct{})
				go func() { _, _ = io.Copy(up, conn); _ = up.Close(); close(sent) }()
				defer func() { _ = conn.Close(); _ = up.Close(); <-sent }()
				for {
					var head [5]byte
					if _, err := io.ReadFull(up, head[:]); err != nil {
						return
					}
					length := binary.BigEndian.Uint32(head[1:])
					if length < 4 || length > 1<<20 {
						return
					}
					body := make([]byte, length-4)
					if _, err := io.ReadFull(up, body); err != nil {
						return
					}
					if head[0] == 'D' && fleetObservationLockDisposition(body) && fault.holdLock.Swap(false) {
						close(fault.lockAborted)
						<-fault.releaseLock
					}
					if head[0] == 'C' && bytes.Equal(body, []byte("COMMIT\x00")) && fault.armed.Swap(false) {
						fault.lost.Store(true)
						return
					}
					if _, err := conn.Write(head[:]); err != nil {
						return
					}
					if _, err := conn.Write(body); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		fault.release()
		mu.Lock()
		for connection := range connections {
			_ = connection.Close()
		}
		mu.Unlock()
		work.Wait()
	})
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	out := original.Copy()
	out.Host, out.Port = host, uint16(number)
	out.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1", RootCAs: roots}
	out.Fallbacks = nil
	return out, fault
}

func TestFleetObservationLockDispositionIsClosed(t *testing.T) {
	for _, tc := range []struct {
		body []byte
		want bool
	}{
		{[]byte{0, 1, 0, 0, 0, 4, 0, 0, 0, 3}, true}, {[]byte{0, 1, 0, 0, 0, 1, '3'}, true},
		{[]byte{0, 1, 0, 0, 0, 4, 0, 0, 0, 1}, false}, {[]byte{0, 1, 0, 0, 0, 1, '0'}, false},
		{[]byte{0, 2, 0, 0, 0, 4, 0, 0, 0, 3}, false}, {[]byte{0, 1, 0, 0, 0, 4, 0, 0, 0, 3, 0}, false},
		{[]byte{0, 1, 255, 255, 255, 255}, false}, {[]byte("C55P03\x00"), false},
	} {
		if got := fleetObservationLockDisposition(tc.body); got != tc.want {
			t.Fatal("unexpected disposition classification")
		}
	}
}
