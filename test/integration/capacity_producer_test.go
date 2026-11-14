package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
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
// owned fleet database and seeds the trust root as setup does before
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
	// Later fixture helpers register role cleanup against this borrowed pool.
	// Keep its owner alive until those LIFO cleanups have completed.
	t.Cleanup(admin.Close)
	// Dedicated owned database only; there must be no earlier installation state.
	var count int
	if e = admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM fleet_trust)+(SELECT count(*) FROM fleet_initial_activation)").Scan(&count); e != nil || count != 0 {
		t.Fatal("fixture not pristine", e)
	}
	u, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
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
	// The trust root is seeded as `asservat setup` seeds it.
	scope := value.InstallationWitnessScope{InstallationID: custodyID(), IssuerEpoch: custodyID(), ClusterID: custodyID(), Namespace: "control", NamespaceUID: custodyID(), Name: "witness", UID: custodyID(), WriterAccount: "installer", WriterAccountUID: custodyID()}
	seed := admin.Config().ConnConfig.Copy()
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	n, _ := strconv.Atoi(port)
	seed.Host, seed.Port, seed.Fallbacks = host, uint16(n), nil
	seed.TLSConfig = tlsConfig.Clone()
	seed.TLSConfig.MinVersion = tls.VersionTLS13
	now := time.Now()
	current := value.Administration{InstallationID: scope.InstallationID, IssuerEpoch: scope.IssuerEpoch, Issuer: "https://id.example.test", Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if e = postgres.SeedInstallation(ctx, seed, current); e != nil {
		t.Fatal("capacity prerequisite trust seed unavailable", e)
	}
	qualify(t, ctx, admin, address, tlsConfig, scope, custodyID(), current, &objectstore.AuthorityObjects{Store: store, Seal: seal, Open: open})
	t.Log("setup trust seed and SQL54 purpose facets; source/probe/history inputs synthetic, no window reuse or installed remote observer")
}
