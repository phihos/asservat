package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Uses the native Pod proof and real SQL/OpenBao/S3 enrollment path. The test
// process owns the keys and listener; this is not an executable inside the Pod.
func exerciseNativeOwnerCredentials(t *testing.T, ctx context.Context, binding value.OwnerBinding, roots *x509.CertPool, verifier *mtls.OwnerPeerVerifier, coordinator app.OwnerEnrollmentCoordinator, issuers map[string]*countedOwnerIssuer, registry app.OwnerCertificateRegistry) ([]*mtls.OwnerConnection, *mtls.OwnerCredentials, *mtls.OwnerCredentials) {
	t.Helper()
	serverEnrollment, clientEnrollment := coordinator, coordinator
	serverEnrollment.Issuer = issuers["server"]
	clientEnrollment.Issuer = issuers["client"]
	server, err := mtls.NewOwnerCredentials(binding, "server", roots, &serverEnrollment, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	client, err := mtls.NewOwnerCredentials(binding, "client", roots, &clientEnrollment, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err = server.Enroll(ctx); err != nil {
		t.Fatal("process-owned server enrollment", err)
	}
	if err = client.Enroll(ctx); err != nil {
		t.Fatal("process-owned client enrollment", err)
	}
	s, err := server.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	sreg, err := registry.ReadOwnerRegistration(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	creg, err := registry.ReadOwnerRegistration(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if sreg.Enrollment.PublicKeyDigest == creg.Enrollment.PublicKeyDigest {
		t.Fatal("server/client keys shared")
	}
	// Recreating a credential owner with a used process epoch must not replace
	// its enrolled key, including while the original process is alive.
	replacement, err := mtls.NewOwnerCredentials(binding, "server", roots, &serverEnrollment, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	calls := issuers["server"].calls.Load()
	if err = replacement.Enroll(ctx); err == nil || issuers["server"].calls.Load() != calls {
		t.Fatal("replacement key inherited process enrollment", err)
	}
	states := make(chan *mtls.OwnerConnection, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, e := mtls.NewOwnerClientConnection(verifier, r.TLS)
		if e != nil {
			w.WriteHeader(403)
			return
		}
		states <- peer
		w.WriteHeader(204)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetCertificate: server.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	name, _ := mtls.OwnerServerName(binding)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name, GetClientCertificate: client.GetClientCertificate}}
	t.Cleanup(transport.CloseIdleConnections)
	h := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := h.Get(srv.URL)
	if err != nil {
		t.Fatal("process-owned actual TLS", err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("TLS status", response.StatusCode)
	}
	peer, err := mtls.NewOwnerServerConnection(verifier, response.TLS, binding)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case clientPeer := <-states:
		t.Log("process-owned separate keys enrolled/activated through native proof and real providers; actual mutual TLS callbacks passed; replacement key rejected before provider signing")
		return []*mtls.OwnerConnection{peer, clientPeer}, server, client
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(time.Second):
		t.Fatal("missing actual TLS state")
	}
	return nil, nil, nil
}
