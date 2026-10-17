package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	workertransport "asservat.local/asservat/internal/transport/worker"
)

type lifetimeExchange struct {
	owner    context.Context
	fixture  *workerChannelFixture
	delivery *fixtureWorkerDelivery
	closed   chan struct{}
}

func (f *lifetimeExchange) BeginWorkerEnrollment(ctx context.Context, i, s, w string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	c, e := f.fixture.EnrollWorker(ctx, i, s, w, token, csr)
	if e != nil {
		return nil, e
	}
	f.delivery = &fixtureWorkerDelivery{ctx: f.owner, cert: c, cancel: func() { close(f.closed) }}
	return f.delivery, nil
}

type blockedEnrollmentResponse struct {
	header             http.Header
	entered, interrupt chan struct{}
	once               sync.Once
	mu                 sync.Mutex
	deadline           time.Time
}

func (w *blockedEnrollmentResponse) Header() http.Header             { return w.header }
func (w *blockedEnrollmentResponse) WriteHeader(int)                 {}
func (w *blockedEnrollmentResponse) SetReadDeadline(time.Time) error { return nil }
func (w *blockedEnrollmentResponse) SetWriteDeadline(d time.Time) error {
	w.mu.Lock()
	w.deadline = d
	w.mu.Unlock()
	if !d.IsZero() && !time.Now().Before(d) {
		w.once.Do(func() { close(w.interrupt) })
	}
	return nil
}
func (w *blockedEnrollmentResponse) Write([]byte) (int, error) {
	close(w.entered)
	<-w.interrupt
	return 0, errors.New("synthetic blocked transport")
}
func (w *blockedEnrollmentResponse) Flush() {}

func TestWorkerCredentialDeliveryRetainsOwnerLifetimeThroughWrite(t *testing.T) {
	for _, mode := range []string{"cancel", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newWorkerChannelFixture(t)
			lifetime := time.Second
			if mode == "expiry" {
				lifetime = 100 * time.Millisecond
			}
			owner, cancel := context.WithTimeout(context.Background(), lifetime)
			defer cancel()
			exchange := &lifetimeExchange{owner: owner, fixture: fixture, closed: make(chan struct{})}
			handler, e := workertransport.NewHandler(fixture.target.InstallationID, exchange, time.Now, 1)
			if e != nil {
				t.Fatal(e)
			}
			key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if e != nil {
				t.Fatal(e)
			}
			input := contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: channelInstallation, SessionID: channelSession, WorkerID: channelWorker, Nonce: strings.Repeat("A", 43), CSR: csr}
			body, _ := json.Marshal(input)
			request := httptest.NewRequest(http.MethodPost, "https://control.invalid"+contracts.WorkerEnrollmentPath, bytes.NewReader(body))
			request.URL.Scheme, request.URL.Host = "", ""
			request.RequestURI = contracts.WorkerEnrollmentPath
			request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer synthetic.first.token")
			writer := &blockedEnrollmentResponse{header: make(http.Header), entered: make(chan struct{}), interrupt: make(chan struct{})}
			defer writer.once.Do(func() { close(writer.interrupt) })
			done := make(chan struct{})
			go func() { handler.ServeHTTP(writer, request); close(done) }()
			select {
			case <-writer.entered:
			case <-time.After(time.Second):
				t.Fatal("response never reached write")
			}
			writer.mu.Lock()
			deadline := writer.deadline
			writer.mu.Unlock()
			original, _ := owner.Deadline()
			if deadline.IsZero() || deadline.After(original) {
				t.Fatal("response extended owner deadline")
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("owner stop did not interrupt blocked write")
			}
			select {
			case <-exchange.closed:
			default:
				t.Fatal("delivery ownership not released")
			}
			writer.mu.Lock()
			reset := writer.deadline
			writer.mu.Unlock()
			if !reset.IsZero() {
				t.Fatal("deadline callback escaped handler cleanup")
			}
		})
	}
}
