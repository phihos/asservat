package integration

import (
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Only this fixture renews the independently supplied installation recovery
// observation. It never clears suspension/recovery_blocked or changes epochs.
type nativeOwnerConfiguration struct {
	current      app.OwnerConfigurationReader
	lab          *ownerConfigLab
	installation string
}

func (s nativeOwnerConfiguration) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	if e := renewSyntheticFleetObservation(ctx, s.lab.admin, s.lab.observation, 30*time.Second, false); e != nil {
		return value.OwnerConfigurationObservation{}, e
	}
	return s.current.ReadOwnerConfiguration(ctx)
}

type nativeOwnerAudit struct {
	*objectstore.OwnerEnrollmentAuditObjects
	after func(context.Context) error
}

func (s *nativeOwnerAudit) WriteOwnerCertificate(ctx context.Context, c audit.OwnerCertificate) (audit.Receipt, error) {
	r, e := s.OwnerEnrollmentAuditObjects.WriteOwnerCertificate(ctx, c)
	if e != nil {
		return r, e
	}
	if s.after != nil {
		hook := s.after
		s.after = nil
		if e = hook(ctx); e != nil {
			return audit.Receipt{}, e
		}
	}
	return r, nil
}

func exerciseNativeOwnerActivation(t *testing.T, ctx context.Context, f fixture, admin kubernetes.Interface, pool value.OwnerPool, accepted app.OwnerConfigurationReader, lab *ownerConfigLab, guard *kube.OwnerWorkloadProtection, endpoints app.OwnerEndpointReader, proofs app.OwnerEnrollmentProofReader, serverRequest value.OwnerEnrollmentRequest, serverKey ed25519.PrivateKey) func(string) {
	t.Helper()
	config, e := accepted.ReadOwnerConfiguration(ctx)
	if e != nil {
		t.Fatal(e)
	}
	roots, _, e := mtls.OwnerTrustRoots(config.Configuration.IssuerRoots, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	v, e := mtls.NewOwnerPeerVerifier(roots, pool.InstallationID, pool.ClusterID, pool.IssuerEpoch, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	ledgerFor := func(role string) *postgres.OwnerEnrollments {
		c := lab.writerPool.Config()
		c.ConnConfig.User = "owner_enrollment_" + role + "runtime"
		c.ConnConfig.Password = "synthetic-owner-enrollment"
		if role != "" {
			c.ConnConfig.Password += "-" + role[:len(role)-1]
		}
		pg, e := pgxpool.NewWithConfig(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(pg.Close)
		s, e := postgres.NewOwnerEnrollments(ctx, pg, pool.InstallationID, pool.ClusterID, pool.NamespaceUID, config.Configuration.Revision.UID, custodyID)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	writer, ack, activation, registry, cleanup := ledgerFor(""), ledgerFor("audit_"), ledgerFor("activate_"), ledgerFor("read_"), ledgerFor("cleanup_")
	bridge := tlsBridge(t, f.KMS)
	request(t, f.KMS, "synthetic-root", "sys/mounts/owner-native-audit", map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", "owner-native-audit/keys/records", map[string]any{"type": "aes256-gcm96"}, 200)
	tokenFor := func(name, policy string) string {
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": policy}, 204)
		return request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	}
	seal, e := kms.NewSealer(bridge.URL, tokenFor("native-owner-audit-seal", `path "owner-native-audit/encrypt/records" { capabilities=["update"] }`), "owner-native-audit", "records", bridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	open, e := kms.NewOpener(bridge.URL, tokenFor("native-owner-audit-open", `path "owner-native-audit/decrypt/records" { capabilities=["update"] }`), "owner-native-audit", "records", bridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	audits := &nativeOwnerAudit{OwnerEnrollmentAuditObjects: &objectstore.OwnerEnrollmentAuditObjects{Store: lab.audit.Store, Seal: seal, Open: open}}
	uri, _ := mtls.OwnerURI(serverRequest.Binding)
	name, _ := mtls.OwnerServerName(serverRequest.Binding)
	ownedBinding := serverRequest.Binding
	ownedBinding.ProcessEpoch = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	ownedURI, _ := mtls.OwnerURI(ownedBinding)
	ownedName, _ := mtls.OwnerServerName(ownedBinding)
	issuers := map[string]*countedOwnerIssuer{}
	for _, usage := range []string{"server", "client"} {
		role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allow_localhost": false, "allowed_uri_sans": []string{uri.String()}, "key_type": "any", "server_flag": usage == "server", "client_flag": usage == "client", "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "1h", "ttl": "20m"}
		role["allowed_uri_sans"] = []string{uri.String(), ownedURI.String()}
		if usage == "server" {
			role["allowed_domains"] = []string{name, ownedName}
			role["allow_bare_domains"] = true
		}
		request(t, f.KMS, "synthetic-root", "owner-native-pki/roles/"+usage, role, 200)
		token := tokenFor("native-owner-sign-"+usage, `path "owner-native-pki/sign/`+usage+`" { capabilities=["update"] }`)
		signer, e := kms.NewOwnerCertificateIssuer(bridge.URL, token, "owner-native-pki", usage, pool.InstallationID, pool.ClusterID, pool.IssuerEpoch, usage, roots, bridge.Client(), time.Now)
		if e != nil {
			t.Fatal(e)
		}
		issuers[usage] = &countedOwnerIssuer{provider: signer}
	}
	service := &app.OwnerEnrollmentCoordinator{Verifier: v, Proofs: proofs, Ledger: writer, Activation: activation, Audit: audits, Acknowledgements: ack, Issuer: issuers["server"], Now: time.Now}
	serverCert, e := service.Enroll(ctx, serverRequest)
	if e != nil {
		var registrations, attempts, signed, active int
		_ = lab.admin.QueryRow(ctx, "SELECT count(*) FROM hub_owner_enrollment WHERE installation_id=$1", pool.InstallationID).Scan(&registrations)
		_ = lab.admin.QueryRow(ctx, "SELECT count(*),count(c.certificate_json),count(c.activated_at) FROM hub_owner_certificate c JOIN hub_owner_enrollment e ON e.id=c.enrollment_id WHERE e.installation_id=$1", pool.InstallationID).Scan(&attempts, &signed, &active)
		t.Fatalf("native pre-Ready server activation: %v; registrations=%d attempts=%d providerCalls=%d signed=%d activated=%d", e, registrations, attempts, issuers["server"].calls.Load(), signed, active)
	}
	if _, e = registry.ReadOwnerRegistration(ctx, serverCert.Certificate); e != nil {
		t.Fatal("activated server registry", e)
	}
	// The actual administrator source changes between stored signing and final
	// activation. A receipt does not allow the old proof to survive suspension.
	setConfig := func(change func(*contracts.OwnerConfiguration)) {
		t.Helper()
		obj, e := admin.CoreV1().ConfigMaps(pool.Namespace).Get(ctx, "owner-pool", meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		var wire contracts.OwnerConfiguration
		if json.Unmarshal([]byte(obj.Data["owner-pool.json"]), &wire) != nil {
			t.Fatal("fixture owner config")
		}
		change(&wire)
		wire.Revision++
		b, _ := json.Marshal(wire)
		obj.Data["owner-pool.json"] = string(b)
		if _, e = admin.CoreV1().ConfigMaps(pool.Namespace).Update(ctx, obj, meta.UpdateOptions{}); e != nil {
			t.Fatal(e)
		}
	}
	_, clientKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	clientCSR, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, clientKey)
	if e != nil {
		t.Fatal(e)
	}
	clientRequest := serverRequest
	clientRequest.Usage = "client"
	clientRequest.CSRDER = clientCSR
	service.Issuer = issuers["client"]
	audits.after = func(context.Context) error {
		setConfig(func(c *contracts.OwnerConfiguration) { c.Suspended = true })
		return nil
	}
	if _, e = service.Enroll(ctx, clientRequest); e == nil || issuers["client"].calls.Load() != 1 {
		t.Fatal("source suspension during certificate audit did not prevent activation", e)
	}
	var raw []byte
	var activated bool
	if e = lab.admin.QueryRow(ctx, "SELECT certificate_json,activated_at IS NOT NULL FROM hub_owner_certificate c JOIN hub_owner_enrollment e ON e.id=c.enrollment_id WHERE e.installation_id=$1 AND e.pod_uid=$2 AND e.process_epoch=$3 AND e.usage='client'", pool.InstallationID, serverRequest.Binding.PodUID, serverRequest.Binding.ProcessEpoch).Scan(&raw, &activated); e != nil || activated {
		t.Fatal("suspended enrollment activated", e)
	}
	var stored value.IssuedOwnerCertificate
	if json.Unmarshal(raw, &stored) != nil || !stored.Certificate.Valid(time.Now()) {
		t.Fatal("signed result lost on suspension")
	}
	setConfig(func(c *contracts.OwnerConfiguration) { c.Suspended = false })
	if _, e = accepted.ReadOwnerConfiguration(ctx); e != nil {
		t.Fatal(e)
	}
	serverConnection, clientConnection := nativeOwnerTLSConnections(t, serverCert, stored, serverKey, clientKey, roots, v)
	gate := &app.OwnerAuthenticator{Registry: registry, Routes: &app.OwnerRoutes{Configurations: accepted, Endpoints: endpoints, Now: time.Now}, Protection: guard, Now: time.Now}
	if _, e = gate.AuthenticateOwner(ctx, clientConnection); e == nil {
		t.Fatal("CA-signed unaudited activation accepted")
	}
	clientCert, e := service.Enroll(ctx, clientRequest)
	if e != nil || !bytes.Equal(clientCert.DER, stored.DER) || issuers["client"].calls.Load() != 1 {
		t.Fatal("native proof resume re-signed or failed", e)
	}
	if _, e = registry.ReadOwnerRegistration(ctx, clientCert.Certificate); e != nil {
		t.Fatal(e)
	}
	owned, ownedServer, ownedClient := exerciseNativeOwnerCredentials(t, ctx, ownedBinding, roots, v, *service, issuers, registry)
	readiness := app.OwnerStartupReadiness{Binding: ownedBinding, Pool: pool, Server: ownedServer, Client: ownedClient, Registry: registry, Proofs: proofs, Now: time.Now}
	connections := append([]*mtls.OwnerConnection{serverConnection, clientConnection}, owned...)
	relayCheck := nativeOwnerRelay(t, ctx, ownedBinding, roots, ownedServer, ownedClient, v, gate)
	t.Log("native Pod/token/CSR, protected accepted configuration, SQL spend, real scoped OpenBao signing/audit and activation composed before Ready; source suspension fenced activation and resume reused the exact leaf")
	return func(phase string) {
		t.Helper()
		switch phase {
		case "before-ready":
			if until, e := readiness.Check(ctx); e != nil || !time.Now().Before(until) {
				t.Fatal("pre-Ready protected startup proof unavailable", e)
			}
			relayCheck(403)
			if _, e := gate.CheckOwnerClient(ctx, ownedClient); e == nil {
				t.Fatal("unavailable owner remained a local client")
			}
			if _, e = accepted.ReadOwnerConfiguration(ctx); e != nil {
				t.Fatal(e)
			}
			for _, conn := range connections {
				if _, e = gate.AuthenticateOwner(ctx, conn); e == nil {
					t.Fatal("unready owner authenticated for forwarding")
				}
			}
		case "ready":
			if until, e := readiness.Check(ctx); e != nil || !time.Now().Before(until) {
				t.Fatal("current startup proof unavailable", e)
			}
			if _, e = accepted.ReadOwnerConfiguration(ctx); e != nil {
				t.Fatal(e)
			}
			for _, conn := range connections {
				if peer, e := gate.AuthenticateOwner(ctx, conn); e != nil || !peer.Valid(time.Now()) {
					t.Fatal("ready activated peer rejected", e)
				}
			}
			relayCheck(503) // Authenticated transport reaches only the synthetic operation.
			if until, e := gate.CheckOwnerClient(ctx, ownedClient); e != nil || !time.Now().Before(until) {
				t.Fatal("native current local client", e)
			}
			// A still-valid TLS session cannot retain roots removed from current config.
			request(t, f.KMS, "synthetic-root", "sys/mounts/owner-native-other", map[string]any{"type": "pki"}, 204)
			alternate := request(t, f.KMS, "synthetic-root", "owner-native-other/root/generate/internal", map[string]any{"common_name": "synthetic-other-owner-root", "ttl": "1h", "key_type": "ec", "key_bits": 256}, 200)
			root, _ := pem.Decode([]byte(alternate["data"].(map[string]any)["certificate"].(string)))
			if root == nil {
				t.Fatal("alternate root")
			}
			setConfig(func(c *contracts.OwnerConfiguration) { c.IssuerRoots = [][]byte{root.Bytes} })
			if _, e = accepted.ReadOwnerConfiguration(ctx); e != nil {
				t.Fatal(e)
			}
			for _, conn := range connections {
				if _, e = gate.AuthenticateOwner(ctx, conn); e == nil {
					t.Fatal("reused TLS session retained removed root")
				}
			}
			relayCheck(403)
			if _, e := readiness.Check(ctx); e == nil {
				t.Fatal("readiness retained removed roots")
			}
			if _, e := gate.CheckOwnerClient(ctx, ownedClient); e == nil {
				t.Fatal("unavailable owner remained a local client")
			}
			setConfig(func(c *contracts.OwnerConfiguration) { c.IssuerRoots = config.Configuration.IssuerRoots })
			if _, e = accepted.ReadOwnerConfiguration(ctx); e != nil {
				t.Fatal(e)
			}
			reg, e := registry.ReadOwnerRegistration(ctx, clientCert.Certificate)
			if e != nil {
				t.Fatal(e)
			}
			if e = cleanup.RetireOwnerEnrollment(ctx, reg.Enrollment); e != nil {
				t.Fatal(e)
			}
			if _, e = gate.AuthenticateOwner(ctx, clientConnection); e == nil {
				t.Fatal("reused TLS session retained retired registration")
			}
			if _, e = gate.AuthenticateOwner(ctx, serverConnection); e != nil {
				t.Fatal("client retirement invalidated independent server", e)
			}
			// A missed protection reader is not replaced by successful certificate/SQL.
			original := gate.Protection
			gate.Protection = ownerProtectionUnavailable{}
			if _, e = gate.AuthenticateOwner(ctx, serverConnection); e == nil {
				t.Fatal("unavailable namespace protection accepted")
			}
			gate.Protection = original
		case "deleted":
			if _, e := readiness.Check(ctx); e == nil {
				t.Fatal("readiness retained deleted Pod")
			}
			relayCheck(403)
			if _, e := gate.CheckOwnerClient(ctx, ownedClient); e == nil {
				t.Fatal("unavailable owner remained a local client")
			}
			if _, e = accepted.ReadOwnerConfiguration(ctx); e != nil {
				t.Fatal(e)
			}
			if _, e = gate.AuthenticateOwner(ctx, serverConnection); e == nil {
				t.Fatal("deleted Pod retained forwarding identity")
			}
			service.Issuer = issuers["server"]
			calls := issuers["server"].calls.Load()
			if _, e = service.Enroll(ctx, serverRequest); e == nil || issuers["server"].calls.Load() != calls {
				t.Fatal("deleted Pod renewed enrollment", e)
			}
		default:
			t.Fatal("unknown phase")
		}
	}
}

type ownerProtectionUnavailable struct{}

func (ownerProtectionUnavailable) ReadOwnerProtection(context.Context, value.OwnerPool) (value.OwnerProtection, error) {
	return value.OwnerProtection{}, errors.New("synthetic protection outage")
}

// Actual loopback TLS is owned by the test process, not served by the pause
// Pod. The same verified snapshots are reused across later revocation checks.
func nativeOwnerTLSConnections(t *testing.T, server, client value.IssuedOwnerCertificate, serverKey, clientKey ed25519.PrivateKey, roots *x509.CertPool, v *mtls.OwnerPeerVerifier) (*mtls.OwnerConnection, *mtls.OwnerConnection) {
	t.Helper()
	chain := func(c value.IssuedOwnerCertificate) [][]byte { return append([][]byte{c.DER}, c.ChainDER...) }
	states := make(chan *mtls.OwnerConnection, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, e := mtls.NewOwnerClientConnection(v, r.TLS)
		if e != nil {
			w.WriteHeader(403)
			return
		}
		states <- conn
		w.WriteHeader(204)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: chain(server), PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	name, _ := mtls.OwnerServerName(server.Certificate.Binding)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name, Certificates: []tls.Certificate{{Certificate: chain(client), PrivateKey: clientKey}}}, MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, e := httpClient.Get(srv.URL)
	if e != nil {
		t.Fatal("native issued mTLS", e)
	}
	_, e = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if e != nil || response.StatusCode != 204 {
		t.Fatal("actual mTLS status", e, response.StatusCode)
	}
	conn, e := mtls.NewOwnerServerConnection(v, response.TLS, server.Certificate.Binding)
	if e != nil {
		t.Fatal(e)
	}
	select {
	case peer := <-states:
		return conn, peer
	case <-time.After(time.Second):
		t.Fatal("missing actual TLS state")
	}
	return nil, nil
}
