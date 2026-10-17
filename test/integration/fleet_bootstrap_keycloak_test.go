package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fixtureFleetSettings stands in for the guarded fleet.json reader (which
// needs Kubernetes); every read returns a fresh five-second observation.
type fixtureFleetSettings struct {
	mu       sync.Mutex
	settings value.Administration
}

func (s *fixtureFleetSettings) FleetAdministration(context.Context) (value.Administration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.settings
	out.ObservedAt = time.Now().UTC()
	out.FreshUntil = out.ObservedAt.Add(5 * time.Second)
	return out, nil
}

// qualifyFleetBootstrapIssuance runs the ADR-193 issuance route with an
// actual Keycloak browser session (ADR-193 step 4e). The product route,
// session/CSRF checks, current identity, enrollment decision, SQL reservation
// ceilings, OpenBao KV delivery and encrypted S3 audit are real. The fleet
// settings reader, the trust row and the issuance logins are fixture setup.
func (f *kcFixture) qualifyFleetBootstrapIssuance(t *testing.T, ctx context.Context, admin *pgxpool.Pool, sessions browser.SessionHandler, origin, cookie, csrf, clientID, group string, seal *kms.Sealer, open *kms.Opener) {
	t.Helper()
	if f.S3 == "" {
		t.Fatal("owned S3 store missing from the identity fixture")
	}
	installation, epoch := uuid.NewString(), uuid.NewString()
	trust := identity.Revision{UID: "synthetic-fleet-settings", Generation: 1, Digest: artifact.Digest{61}}
	now := time.Now().UTC()
	if _, err := admin.Exec(ctx, `INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,$3,1,$4,false,false,$5,$6)`, installation, epoch, trust.UID, trust.Digest[:], now, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := seedSyntheticFleetObservation(ctx, admin, installation); err != nil {
		t.Fatal(err)
	}
	const profile = "regional-installer"
	mount := "fleet-bootstrap-" + strings.ReplaceAll(installation[:8], "-", "")
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+mount, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, 204)
	if err := waitFixtureKV(ctx, f.KMS, mount); err != nil {
		t.Fatal(err)
	}
	request(t, f.KMS, "synthetic-root", mount+"/config", map[string]any{"cas_required": true, "max_versions": 1, "delete_version_after": "5m"}, 204)
	request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+mount, map[string]any{"policy": `path "` + mount + `/data/connector/` + installation + `/*" { capabilities=["create","read"] }`}, 204)
	token := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{mount}, "no_default_policy": true, "ttl": "10m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	keys := tlsBridge(t, f.KMS)
	channel, err := kms.NewBootstrapChannel(keys.URL, token, mount, "connector", profile, installation, keys.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	storage := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "fleet-issuance-" + installation[:8]
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(storage.URL), UsePathStyle: true, Credentials: creds, HTTPClient: storage.Client(), RetryMaxAttempts: 1})
	if _, err = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.New(storage.URL, "us-east-1", bucket, creds, storage.Client())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, backend.Host)
	pool := func(duty string) *pgxpool.Pool {
		c, err := pgxpool.ParseConfig("postgres://bootstrap_" + duty + "_runtime:synthetic-bootstrap-" + duty + "@" + address + "/custody_test?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		c.ConnConfig.TLSConfig, c.ConnConfig.Fallbacks, c.MaxConns = tlsConfig, nil, 1
		p, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	reserve, err := postgres.NewBootstrapReservations(ctx, pool("reserve"), installation, uuid.NewString)
	if err != nil {
		t.Fatal(err)
	}
	var issues [3]*postgres.BootstrapIssues
	for i, duty := range []string{"record", "audit", "activate"} {
		if issues[i], err = postgres.NewBootstrapIssues(ctx, pool(duty), installation); err != nil {
			t.Fatal(err)
		}
	}
	settings := &fixtureFleetSettings{settings: value.Administration{InstallationID: installation, IssuerEpoch: epoch, Issuer: f.Issuer, Revision: trust, Clients: []string{clientID}, Groups: []string{group}, DeliveryProfiles: []string{profile}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 4, MaxClusters: 4}}
	service := &fleetapp.FleetBootstrapIssuance{Settings: settings, Reservations: reserve, Credentials: channel, Records: issues[0], Audits: issues[1], Objects: &objectstore.BootstrapIssueObjects{Store: store, Seal: seal, Open: open}, Activation: issues[2], Now: time.Now}
	handler, err := browser.NewFleetHandler(sessions, service)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := url.Parse(origin)
	issue := func(key string) (int, map[string]string) {
		// Origin-form target as a server receives it; an absolute URL is refused.
		r := httptest.NewRequest(http.MethodPost, browser.FleetBootstrapPath, strings.NewReader(`{"displayName":"synthetic region","region":"eu-test","deliveryProfile":"`+profile+`"}`))
		r.Host, r.TLS = host.Host, &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(&http.Cookie{Name: browser.SessionCookie, Value: cookie})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	intents := func() (n int) {
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM fleet_bootstrap_intent WHERE installation_id=$1", installation).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// A member of only another group is no fleet operator: refused before
	// any reservation or provider work.
	settings.mu.Lock()
	settings.settings.Groups = []string{uuid.NewString()}
	settings.mu.Unlock()
	if status, _ := issue("fleet-operator-key-0001"); status != http.StatusForbidden || intents() != 0 {
		t.Fatal("non-operator issuance", status)
	}
	settings.mu.Lock()
	settings.settings.Groups = []string{group}
	settings.mu.Unlock()
	status, first := issue("fleet-operator-key-0001")
	var issued bool
	if status == http.StatusCreated {
		_ = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM fleet_bootstrap WHERE installation_id=$1 AND id=$2)", installation, first["bootstrapID"]).Scan(&issued)
	}
	if !issued || first["deliveryProfile"] != profile || first["issuerEpoch"] != epoch {
		t.Fatal("operator issuance", status, first)
	}
	if status, again := issue("fleet-operator-key-0001"); status != http.StatusCreated || again["bootstrapID"] != first["bootstrapID"] || intents() != 1 {
		t.Fatal("replay changed the slot", status)
	}
	// maxActiveBootstraps=1: a second distinct request exceeds the ceiling.
	if status, _ := issue("fleet-operator-key-0002"); status != http.StatusTooManyRequests || intents() != 1 {
		t.Fatal("ceiling not enforced", status)
	}
	t.Logf("fleet issuance with actual Keycloak session: bootstrap issued, replay stable, non-operator 403, ceiling 429")
}
