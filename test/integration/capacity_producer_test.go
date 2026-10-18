package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The ordinary harness does not select this test. It requires its own fresh
// owned fleet database and uses actual initial SQL/S3/OpenBao activation before
// actual capacity setup. Kubernetes witness/guard/metadata and physical-history
// qualifications remain explicitly synthetic. No history coverage is returned.
func TestCapacityProducerWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, qualifyCapacityProducerSQL)
}

type capacityProducerCheck func(*testing.T, context.Context, *pgxpool.Pool, string, *tls.Config, value.InstallationWitnessScope, string, value.Administration, *objectstore.AuthorityObjects)

func withCapacityProducerFixture(t *testing.T, qualify capacityProducerCheck) {
	var f fixture
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run selected owned fleet fixture for SQL54")
	}
	b, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	ctx, end := context.WithTimeout(context.Background(), 5*time.Minute)
	defer end()
	admin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	// Dedicated owned database only; there must be no earlier installation state.
	var count int
	if e = admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM fleet_trust)+(SELECT count(*) FROM fleet_initial_activation)").Scan(&count); e != nil || count != 0 {
		t.Fatal("fixture not pristine", e)
	}
	_, e = admin.Exec(ctx, `CREATE ROLE initial_prepare LOGIN PASSWORD 'synthetic-initial';
 CREATE ROLE initial_audit LOGIN PASSWORD 'synthetic-initial';
 CREATE ROLE initial_activate LOGIN PASSWORD 'synthetic-initial';
 GRANT USAGE ON SCHEMA public TO initial_prepare,initial_audit,initial_activate;
 GRANT SELECT,MAINTAIN ON ALL TABLES IN SCHEMA public TO initial_prepare,initial_activate;
 GRANT INSERT ON fleet_initial_activation TO initial_prepare;
 GRANT UPDATE(singleton) ON fleet_initial_activation TO initial_prepare;
 GRANT INSERT(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until) ON fleet_trust TO initial_prepare;
 GRANT SELECT ON goose_db_version,fleet_initial_activation TO initial_audit;
 GRANT UPDATE(audit_receipt_json) ON fleet_initial_activation TO initial_audit;
 GRANT UPDATE(activated_at) ON fleet_initial_activation TO initial_activate;
 GRANT UPDATE(suspended,recovery_blocked,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) ON fleet_trust TO initial_activate;
 GRANT INSERT(installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) ON fleet_observation TO initial_activate;`)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	pools := map[string]*pgxpool.Pool{}
	for _, name := range []string{"prepare", "audit", "activate"} {
		cfg, e := pgxpool.ParseConfig("postgres://initial_" + name + ":synthetic-initial@" + address + "/custody_test?sslmode=disable")
		if e != nil {
			t.Fatal(e)
		}
		cfg.ConnConfig.TLSConfig = tlsConfig
		cfg.ConnConfig.Fallbacks = nil
		cfg.MaxConns = 4
		p, e := pgxpool.NewWithConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(p.Close)
		pools[name] = p
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/initial-transit", map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", "initial-transit/keys/audit", map[string]any{"type": "aes256-gcm96"}, 200)
	tokens := map[string]string{}
	for _, op := range []string{"encrypt", "decrypt"} {
		name := "initial-" + op
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": `path "initial-transit/` + op + `/audit" { capabilities=["update"] }`}, 204)
		tokens[op] = request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	}
	keyBridge := tlsBridge(t, f.KMS)
	seal, e := kms.NewSealer(keyBridge.URL, tokens["encrypt"], "initial-transit", "audit", keyBridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	open, e := kms.NewOpener(keyBridge.URL, tokens["decrypt"], "initial-transit", "audit", keyBridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "initial-installation"
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	if _, e = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); e != nil {
		t.Fatal(e)
	}
	// This fixture also composes current owner audit, whose acknowledged receipts require immutable versions.
	if _, e = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}

	store, e := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	objects := &objectstore.InitialInstallationObjects{Store: store, Seal: seal, Open: open}
	type lab struct {
		scope          value.InstallationWitnessScope
		w              *initialWitnessFixture
		a              *initialAdminFixture
		prep, ack, act *postgres.InitialInstallations
		service        app.InitialInstaller
	}
	setup := func(t *testing.T) *lab {
		t.Helper()
		s := &lab{scope: value.InstallationWitnessScope{InstallationID: custodyID(), IssuerEpoch: custodyID(), ClusterID: custodyID(), Namespace: "control", NamespaceUID: custodyID(), Name: "witness", UID: custodyID(), WriterAccount: "installer", WriterAccountUID: custodyID()}}
		s.w = &initialWitnessFixture{scope: s.scope}
		s.a = &initialAdminFixture{a: value.Administration{InstallationID: s.scope.InstallationID, IssuerEpoch: s.scope.IssuerEpoch, Issuer: "https://id.example.test", Revision: identity.Revision{UID: "initial-fleet", Generation: 1, Digest: artifact.Digest{1}}, Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}}
		for name, dst := range map[string]**postgres.InitialInstallations{"prepare": &s.prep, "audit": &s.ack, "activate": &s.act} {
			var e error
			*dst, e = postgres.NewInitialInstallations(ctx, pools[name], s.scope, artifact.Digest{2})
			if e != nil {
				t.Fatal(e)
			}
		}
		s.service = app.InitialInstaller{Witness: s.w, Consume: s.w, Administration: s.a, Preparation: s.prep, Objects: objects, Acknowledgements: s.ack, Activation: s.act, Now: time.Now}

		return s
	}

	s := setup(t)
	s.a.a.Revision.UID = custodyID()
	record, err := s.service.Activate(ctx)
	if err != nil {
		t.Fatal("capacity prerequisite audited activation unavailable", err)
	}
	current, err := s.a.FleetAdministration(ctx)
	if err != nil {
		t.Fatal("synthetic original administration unavailable")
	}
	qualify(t, ctx, admin, address, tlsConfig, s.scope, record.Claim.ID, current, &objectstore.AuthorityObjects{Store: store, Seal: seal, Open: open})
	t.Log("actual initial activation and SQL54 purpose facets; source/probe/history inputs synthetic, no window reuse or installed remote observer")
}
