package mtls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/worker"
)

type workerDeliveryListener struct {
	conn  net.Conn
	taken atomic.Bool
	done  chan struct{}
	once  sync.Once
}

func (l *workerDeliveryListener) Accept() (net.Conn, error) {
	if !l.taken.Swap(true) {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *workerDeliveryListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *workerDeliveryListener) Addr() net.Addr { return l.conn.LocalAddr() }

type workerDeliveryConn struct {
	net.Conn
	watch   atomic.Bool
	writing chan struct{}
}

func (c *workerDeliveryConn) Write(b []byte) (int, error) {
	if c.watch.Load() {
		select {
		case c.writing <- struct{}{}:
		default:
		}
	}
	return c.Conn.Write(b)
}

func TestOwnerForwarderThroughWorkerTLSResponse(t *testing.T) {
	for _, mode := range []string{"complete", "owner-cancel-during-write"} {
		t.Run(mode, func(t *testing.T) {
			f := newForwardLab(t, "valid")
			h, err := worker.NewHandler(ownerTestID, f.forwarder, time.Now, 1)
			if err != nil {
				t.Fatal(err)
			}
			serverEnd, clientEnd := net.Pipe()
			observed := &workerDeliveryConn{Conn: serverEnd, writing: make(chan struct{}, 1)}
			listener := &workerDeliveryListener{conn: observed, done: make(chan struct{})}
			served := make(chan struct{})
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(served)
				h.ServeHTTP(w, r)
			})}
			done := make(chan error, 1)
			go func() {
				done <- server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetCertificate: f.server.GetCertificate, SessionTicketsDisabled: true}))
			}()
			name, _ := OwnerServerName(f.binding)
			client := tls.Client(clientEnd, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.ca.roots, ServerName: name})
			t.Cleanup(func() {
				// Close the raw pipe first: a TLS close_notify cannot block cleanup.
				clientEnd.Close()
				server.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("worker server not joined")
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			observed.watch.Store(true)
			in := contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: ownerTestID, SessionID: ownerTestID, WorkerID: ownerTestID, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), CSR: f.csr}
			b, _ := json.Marshal(in)
			request, _ := http.NewRequest("POST", "https://"+name+contracts.WorkerEnrollmentPath, bytes.NewReader(b))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer synthetic.pod.token")
			client.SetDeadline(time.Now().Add(3 * time.Second))
			if err := request.Write(client); err != nil {
				t.Fatal(err)
			}
			select {
			case <-observed.writing:
			case <-time.After(time.Second):
				t.Fatal("no downstream certificate write")
			}
			if f.released.Load() != 0 {
				t.Fatal("owner released before worker write completed")
			}
			if mode == "owner-cancel-during-write" {
				f.cancelOwner()
			} else {
				response, err := http.ReadResponse(bufio.NewReader(client), request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 {
					t.Fatal("worker response failed", err)
				}
				out, err := contracts.DecodeWorkerEnrollmentResponse(bytes.NewReader(body))
				if err != nil || out.Nonce != in.Nonce || len(out.Certificate) == 0 {
					t.Fatal("worker result invalid", err)
				}
			}
			select {
			case <-served:
			case <-time.After(time.Second):
				t.Fatal("downstream blocked write was not interrupted")
			}
			limit := time.After(time.Second)
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for f.released.Load() == 0 {
				select {
				case <-tick.C:
				case <-limit:
					t.Fatal("remote owner not released")
				}
			}
			if f.requests.Load() != 1 || f.released.Load() != 1 || len(f.forwarder.slots) != 0 {
				t.Fatal("ownership leak or replay")
			}
		})
	}
}
