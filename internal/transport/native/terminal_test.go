package native_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

// A real h2 peer can close normally as soon as it receives the positive final
// marker. A blocking SQL/current check after flushing that marker is too late:
// it both exposes an unqualified success and races the peer's normal cleanup.
type terminalAdmission struct {
	flushed      atomic.Bool
	afterFlush   atomic.Int32
	afterEntered chan struct{}
	outcome      chan error
	joined       chan struct{}
	kind         contracts.NativeFrameKind
	denyBefore   bool
	denied       atomic.Bool
	failFlush    bool
	shortWrite   bool
}
type terminalConversation struct {
	gate      *evidence.NativeFrameGate
	admission *terminalAdmission
}

func (a *terminalAdmission) OpenNative(ctx context.Context, _ *tls.ConnectionState, _ contracts.NativeHello) (native.Conversation, error) {
	now := time.Now()
	operation := value.NativeOperation{Reference: value.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: nativeID, Fence: 1}, Kind: value.NativePrepare, HubPodUID: nativeID, HubProcessEpoch: nativeID, WorkerPodUID: nativeID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: artifact.Digest{2}, ParentID: nativeID, Generation: 1, StartedAt: now, Until: now.Add(4 * time.Second)}
	operation = syntheticProcessingPath(operation)
	lease := value.NativeLease{Operation: operation, Certificate: artifact.Digest{3}, Sequence: 1, ObservedAt: now, Until: operation.Until}
	gate, err := evidence.NewNativeFrameGate(ctx, func(check context.Context) (value.NativeLease, error) {
		if a.denied.Load() {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		if a.flushed.Load() {
			a.afterFlush.Add(1)
			if a.afterEntered != nil {
				a.afterEntered <- struct{}{}
			}
			<-check.Done() // reproduce a real SQL check interrupted by normal peer close
			return value.NativeLease{}, check.Err()
		}
		return lease, nil
	}, time.Now)
	if err != nil {
		return nil, err
	}
	return &terminalConversation{gate, a}, nil
}
func (c *terminalConversation) Gate() *evidence.NativeFrameGate { return c.gate }
func (c *terminalConversation) Serve(ctx context.Context, s native.Stream) error {
	if c.admission.denyBefore {
		c.admission.denied.Store(true)
	}
	err := s.Send(ctx, contracts.NativeFrame{Kind: c.admission.kind, Payload: []byte(`{"phase":"closed"}`)})
	c.admission.outcome <- err
	return err
}
func (c *terminalConversation) Close() error {
	c.gate.Close()
	err := c.gate.Wait(context.Background())
	close(c.admission.joined)
	return err
}

type terminalWriter struct {
	http.ResponseWriter
	admission *terminalAdmission
	final     bool
}

func (w *terminalWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *terminalWriter) Write(b []byte) (int, error) {
	if len(b) == 5 && b[0] == byte(w.admission.kind) {
		w.final = true
	}
	if w.final && len(b) != 5 && w.admission.shortWrite {
		return len(b) - 1, nil
	}
	return w.ResponseWriter.Write(b)
}
func (w *terminalWriter) FlushError() error {
	if w.final && w.admission.failFlush {
		return errors.New("synthetic flush failure")
	}
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err == nil && w.final {
		w.admission.flushed.Store(true)
	}
	return err
}
func terminalClient(t *testing.T, a *terminalAdmission) *mtls.NativeClient {
	t.Helper()
	serverCert, clientCert, roots := testCertificates(t)
	var handler http.Handler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(&terminalWriter{ResponseWriter: w, admission: a}, r)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	var err error
	handler, err = native.NewHandler(contracts.NativeWorkerPath, parsed.Host, a, 1)
	if err != nil {
		t.Fatal(err)
	}
	client, err := mtls.NewNativeClient(server.URL+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func TestNativeFinalMarkerDoesNotStartAuthorityWorkAfterFlush(t *testing.T) {
	a := &terminalAdmission{kind: contracts.NativeDoneFrame, outcome: make(chan error, 1), joined: make(chan struct{})}
	client := terminalClient(t, a)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Open(ctx, workerHello())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	frame, err := stream.Receive(ctx)
	clear(frame.Payload)
	if err != nil || frame.Kind != contracts.NativeDoneFrame {
		t.Fatal("positive final marker", err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-a.outcome:
		if err != nil {
			t.Fatal("normal peer close invalidated already flushed final marker", err)
		}
	case <-time.After(time.Second):
		t.Fatal("final marker started blocking authority work after flush")
	}
	select {
	case <-a.joined:
	case <-time.After(time.Second):
		t.Fatal("final conversation did not join")
	}
	if a.afterFlush.Load() != 0 {
		t.Fatal("authority work started after positive marker")
	}
}

func TestNativeTerminalOrderingKeepsCurrentAndWriteFailures(t *testing.T) {
	for _, mode := range []string{"known-denial", "partial-write", "flush-failure", "data-post-check"} {
		t.Run(mode, func(t *testing.T) {
			a := &terminalAdmission{kind: contracts.NativeDoneFrame, outcome: make(chan error, 1), joined: make(chan struct{})}
			switch mode {
			case "known-denial":
				a.denyBefore = true
			case "partial-write":
				a.shortWrite = true
			case "flush-failure":
				a.failFlush = true
			case "data-post-check":
				a.kind = contracts.NativeDataFrame
				a.afterEntered = make(chan struct{}, 1)
			}
			client := terminalClient(t, a)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := client.Open(ctx, workerHello())
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			frame, err := stream.Receive(ctx)
			clear(frame.Payload)
			if mode == "data-post-check" {
				if err != nil || frame.Kind != contracts.NativeDataFrame {
					t.Fatal("synthetic data not delivered", err)
				}
				select {
				case <-a.afterEntered:
				case <-time.After(time.Second):
					t.Fatal("data post-write current check did not start")
				}
			} else if err == nil {
				t.Fatal("failed final marker became a complete frame")
			}
			stream.Close()
			select {
			case err = <-a.outcome:
				if err == nil {
					t.Fatal("failed send claimed success")
				}
			case <-time.After(time.Second):
				t.Fatal("failed send did not join")
			}
			select {
			case <-a.joined:
			case <-time.After(time.Second):
				t.Fatal("failed conversation did not join")
			}
			if mode == "data-post-check" && a.afterFlush.Load() != 1 {
				t.Fatal("data lost its post-write current check")
			}
		})
	}
}
