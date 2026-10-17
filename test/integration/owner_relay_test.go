package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	authorization "asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/ownerrelay"
)

// Native issuer/registration/protection/Ready checks and real process-owned TLS
// terminate in an explicit unavailable synthetic operation. SQL exact receiving
// is qualified separately; this is not a composed native worker relay yet.
type nativeRelayOperation struct{ calls atomic.Int32 }

func (o *nativeRelayOperation) BeginOwnedWorkerEnrollment(context.Context, authorization.WorkerOwnerLease, []byte, []byte) (evidence.WorkerEnrollmentDelivery, error) {
	o.calls.Add(1)
	return nil, artifact.ErrDownloadUnavailable
}
func nativeOwnerRelay(t *testing.T, parent context.Context, binding value.OwnerBinding, roots *x509.CertPool, server, client *mtls.OwnerCredentials, verifier *mtls.OwnerPeerVerifier, gate *app.OwnerAuthenticator) func(int) {
	t.Helper()
	op := &nativeRelayOperation{}
	peers := &mtls.OwnerRequestPeers{Verifier: verifier, Authenticator: gate, Server: server}
	handler, err := ownerrelay.NewHandler(binding, peers, op, time.Now, 1)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan error, 1)
	go func() { done <- ownerrelay.Serve(ctx, listener, roots, server, handler, 4) }()
	name, _ := mtls.OwnerServerName(binding)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name, GetClientCertificate: client.GetClientCertificate}}
	httpClient := &http.Client{Transport: tr, Timeout: 12 * time.Second}
	t.Cleanup(func() {
		cancel()
		tr.CloseIdleConnections()
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Errorf("native relay exit: %v", e)
			}
		case <-time.After(6 * time.Second):
			t.Error("native relay did not terminate")
		}
	})
	return func(expected int) {
		t.Helper()
		now := time.Now().UTC()
		before := op.calls.Load()
		in := contracts.OwnerRelayRequest{Format: contracts.OwnerRelayFormat, Locator: contracts.OwnerRelayLocator{RequestID: binding.PodUID, PodUID: binding.PodUID, ProcessEpoch: binding.ProcessEpoch, Fence: 1, Started: now, Until: now.Add(20 * time.Second)}, Enrollment: contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: binding.InstallationID, SessionID: binding.PodUID, WorkerID: binding.PodUID, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), CSR: bytes.Repeat([]byte{1}, 32)}}
		b, _ := json.Marshal(in)
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://"+listener.Addr().String()+contracts.OwnerRelayPath, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer synthetic.connector.pod.token")
		resp, e := httpClient.Do(req)
		if e != nil {
			t.Fatal("native relay", e)
		}
		resp.Body.Close()
		if resp.StatusCode != expected {
			t.Fatalf("native relay: got %d want %d", resp.StatusCode, expected)
		}
		calls := before
		if expected == 503 {
			calls++
		}
		if op.calls.Load() != calls {
			t.Fatal("native peer denial reached operation")
		}
	}
}
