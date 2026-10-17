package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type enrollmentAuthorityFunc func(context.Context, string, string) (value.EnrollmentAuthority, error)

func (f enrollmentAuthorityFunc) AuthorizeEnrollment(ctx context.Context, token, profile string) (value.EnrollmentAuthority, error) {
	return f(ctx, token, profile)
}

type countingCertificateIssuer struct {
	issuer fleetapp.CertificateIssuer
	calls  atomic.Int64
}

func (c *countingCertificateIssuer) SignConnector(ctx context.Context, p value.CertificateIssuePermit, csr []byte) (value.IssuedCertificate, error) {
	c.calls.Add(1)
	return c.issuer.SignConnector(ctx, p, csr)
}

func testAuditedEnrollmentWithRealProvider(t *testing.T, f fixture, b value.PeerBinding, csr []byte, private ed25519.PrivateKey, issuer fleetapp.CertificateIssuer, roots *x509.CertPool, unregistered value.IssuedCertificate) {
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	u, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	poolFor := func(user, password string) *pgxpool.Pool {
		t.Helper()
		c, err := pgxpool.ParseConfig("postgres://" + user + ":" + password + "@" + address + "/custody_test?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		c.ConnConfig.TLSConfig = tlsConfig
		c.ConnConfig.Fallbacks = nil
		c.MaxConns = 2
		p, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	claimPool := poolFor("enrollment_claim_runtime", "synthetic-enrollment-claim")
	auditPool := poolFor("enrollment_audit_runtime", "synthetic-enrollment-audit")
	signPool := poolFor("enrollment_sign_runtime", "synthetic-enrollment-sign")
	activationPool := poolFor("enrollment_activate_runtime", "synthetic-enrollment-activate")
	readPool := poolFor("peer_read_runtime", "synthetic-peer-read")
	request(t, f.KMS, "synthetic-root", "sys/mounts/enrollment-transit", map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", "enrollment-transit/keys/audit", map[string]any{"type": "aes256-gcm96"}, 200)
	tokens := map[string]string{}
	for _, op := range []string{"encrypt", "decrypt"} {
		name := "enrollment-" + op
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": `path "enrollment-transit/` + op + `/audit" { capabilities=["update"] }`}, 204)
		tokens[op] = request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	}
	keyBridge := tlsBridge(t, f.KMS)
	seal, err := kms.NewSealer(keyBridge.URL, tokens["encrypt"], "enrollment-transit", "audit", keyBridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	open, err := kms.NewOpener(keyBridge.URL, tokens["decrypt"], "enrollment-transit", "audit", keyBridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	storageBridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "enrollment-provider-audit"
	storageAdmin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(storageBridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: storageBridge.Client()})
	if _, err = storageAdmin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err = storageAdmin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.New(storageBridge.URL, "us-east-1", bucket, creds, storageBridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	key, err := mtls.EnrollmentKey(csr)
	if err != nil {
		t.Fatal(err)
	}
	a := value.EnrollmentAuthority{InstallationID: b.InstallationID, IssuerEpoch: b.IssuerEpoch, DeliveryProfile: "operator-channel", Actor: identity.Principal{Issuer: "https://identity.example.test", Subject: "synthetic-operator", ClientID: "console", Kind: identity.Human}, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, AdministrationRevision: identity.Revision{UID: "fleet", Generation: 1, Digest: artifact.Digest{2}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}
	if _, err = admin.Exec(ctx, `INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,$3,1,$4,false,false,$5,$6)`, b.InstallationID, b.IssuerEpoch, a.AdministrationRevision.UID, a.AdministrationRevision.Digest[:], now, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := seedSyntheticFleetObservation(ctx, admin, b.InstallationID); err != nil {
		t.Fatal(err)
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/enrollment-bootstrap", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, 204)
	if err = waitFixtureKV(ctx, f.KMS, "enrollment-bootstrap"); err != nil {
		t.Fatal(err)
	}
	request(t, f.KMS, "synthetic-root", "enrollment-bootstrap/config", map[string]any{"cas_required": true, "max_versions": 1, "delete_version_after": "5m"}, 204)
	request(t, f.KMS, "synthetic-root", "sys/policies/acl/enrollment-bootstrap", map[string]any{"policy": `path "enrollment-bootstrap/data/connector/` + b.InstallationID + `/*" { capabilities=["create","read"] }`}, 204)
	channelToken := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{"enrollment-bootstrap"}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	channel, err := kms.NewBootstrapChannel(keyBridge.URL, channelToken, "enrollment-bootstrap", "connector", a.DeliveryProfile, b.InstallationID, keyBridge.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{uuid.NewString(), b.ClusterID, b.PeerID}
	reserve, err := postgres.NewBootstrapReservations(ctx, poolFor("bootstrap_reserve_runtime", "synthetic-bootstrap-reserve"), b.InstallationID, func() string { out := ids[0]; ids = ids[1:]; return out })
	if err != nil {
		t.Fatal(err)
	}
	records, err := postgres.NewBootstrapIssues(ctx, poolFor("bootstrap_record_runtime", "synthetic-bootstrap-record"), b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	issueAudits, err := postgres.NewBootstrapIssues(ctx, poolFor("bootstrap_audit_runtime", "synthetic-bootstrap-audit"), b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	issueActivation, err := postgres.NewBootstrapIssues(ctx, poolFor("bootstrap_activate_runtime", "synthetic-bootstrap-activate"), b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	// Protected trust and human identity are synthetic in this provider fixture;
	// the credential, reservation, audit, activation and claim are actual adapters.
	authority := enrollmentAuthorityFunc(func(_ context.Context, token, profile string) (value.EnrollmentAuthority, error) {
		if token != "synthetic-operator" || profile != a.DeliveryProfile {
			return value.EnrollmentAuthority{}, value.ErrDenied
		}
		current := a
		current.CheckedAt = time.Now().UTC()
		current.ValidUntil = current.CheckedAt.Add(5 * time.Second)
		return current, nil
	})
	bootstrap := fleetapp.BootstrapIssuer{Authority: authority, Reservations: reserve, Credentials: channel, Records: records, Audits: issueAudits, Objects: &objectstore.BootstrapIssueObjects{Store: store, Seal: seal, Open: open}, Activation: issueActivation, Now: time.Now}
	input := fleetapp.BootstrapInput{KeyDigest: artifact.Digest{1}, DisplayName: "synthetic cluster", Region: "eu-test", DeliveryProfile: a.DeliveryProfile}
	issuedBootstrap, err := bootstrap.Issue(ctx, "synthetic-operator", input)
	if err != nil || !issuedBootstrap.Issued || issuedBootstrap.Credential == nil {
		t.Fatal("audited bootstrap issuance", err)
	}
	again, err := bootstrap.Issue(ctx, "synthetic-operator", input)
	if err != nil || again.Slot.ID != issuedBootstrap.Slot.ID || !again.Slot.NotAfter.Equal(issuedBootstrap.Slot.NotAfter) {
		t.Fatal("bootstrap replay changed identity or expiry", err)
	}
	// Model the operator's configured secret-channel read without printing it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyBridge.URL+"/v1/enrollment-bootstrap/data/connector/"+b.InstallationID+"/"+issuedBootstrap.Slot.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", channelToken)
	response, err := keyBridge.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Data struct {
			Data struct {
				Secret string `json:"secret"`
			} `json:"data"`
		} `json:"data"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&stored)
	response.Body.Close()
	if response.StatusCode != 200 || decodeErr != nil {
		t.Fatal("operator channel unavailable")
	}
	secretDigest, err := mtls.BootstrapDigest(b.InstallationID, issuedBootstrap.Slot.ID, stored.Data.Data.Secret)
	stored.Data.Data.Secret = ""
	if err != nil || secretDigest != issuedBootstrap.Credential.SecretDigest {
		t.Fatal("wrong delivered credential")
	}
	claim := value.EnrollmentClaim{InstallationID: b.InstallationID, BootstrapID: issuedBootstrap.Slot.ID, SecretDigest: secretDigest, PublicKeyDigest: key}
	claims, err := postgres.NewEnrollmentClaims(ctx, claimPool, b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	claimAudits, err := postgres.NewEnrollmentClaimAudits(ctx, auditPool, b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := postgres.NewEnrollmentSigning(ctx, signPool, b.InstallationID, uuid.NewString)
	if err != nil {
		t.Fatal(err)
	}
	certificateAudits, err := postgres.NewEnrollmentCertificateAudits(ctx, auditPool, b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := postgres.NewEnrollmentActivation(ctx, activationPool, b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingCertificateIssuer{issuer: issuer}
	service := fleetapp.ConnectorEnrollment{Proof: mtls.EnrollmentProof{}, Claims: claims, ClaimAudits: claimAudits, ClaimObjects: &objectstore.EnrollmentClaimObjects{Store: store, Seal: seal, Open: open}, Signing: signing, Issuer: counting, CertificateAudits: certificateAudits, CertificateObjects: &objectstore.EnrollmentCertificateObjects{Store: store, Seal: seal, Open: open}, Activation: activation, Now: time.Now}
	issued, err := service.Enroll(ctx, claim, csr)
	if err != nil {
		t.Fatal("real-provider enrollment", err)
	}
	retry, err := service.Enroll(ctx, claim, csr)
	if err != nil || !bytes.Equal(issued.DER, retry.DER) || counting.calls.Load() != 1 {
		t.Fatal("recovered enrollment re-signed", err)
	}
	registry, err := postgres.NewPeerRegistry(ctx, readPool, b.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	qualifyConnectorHistoricalVersions(t, ctx, admin, signing, activation, claim)
	authenticate := fleetapp.PeerAuthenticator{Registry: registry, Now: time.Now}
	verifier, err := mtls.NewPeerVerifier(roots, b.InstallationID, value.ConnectorPeer, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := verifier.Verify(r.TLS)
		if err != nil {
			w.WriteHeader(403)
			return
		}
		if _, err = authenticate.AuthenticatePeer(r.Context(), peer); err != nil {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	clientFor := func(c value.IssuedCertificate) *http.Client {
		transport := server.Client().Transport.(*http.Transport).Clone()
		t.Cleanup(transport.CloseIdleConnections)
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: append([][]byte{c.DER}, c.ChainDER...), PrivateKey: private}}
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	check := func(c *http.Client, status int) {
		t.Helper()
		r, err := c.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != status {
			t.Fatal("current peer admission", r.StatusCode, status)
		}
	}
	check(clientFor(unregistered), 403)
	registered := clientFor(issued)
	check(registered, 204)
	if _, err = admin.Exec(ctx, "UPDATE fleet_peer SET enabled=false WHERE installation_id=$1", b.InstallationID); err != nil {
		t.Fatal(err)
	}
	check(registered, 403) // Reuses its TLS connection; registration is still checked.
	if _, err = service.Enroll(ctx, claim, csr); err == nil {
		t.Fatal("replay revived revoked registration")
	}
	if counting.calls.Load() != 1 {
		t.Fatal("revocation attempted another provider call")
	}
}
