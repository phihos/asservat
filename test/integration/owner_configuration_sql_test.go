package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

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

type ownerConfigLab struct {
	observation                   syntheticFleetBinding
	admin, writerPool, readerPool *pgxpool.Pool
	writer, reader                *postgres.OwnerConfigurations
	audit                         *objectstore.OwnerEnrollmentAuditObjects
}

// Real SQL/S3; trust activation and wrapping roots are explicitly synthetic.
// This helper is also used with the real admission-qualified Kubernetes source.
func ownerConfigurationLab(t *testing.T, ctx context.Context, f fixture, c value.OwnerConfiguration) *ownerConfigLab {
	t.Helper()
	l := &ownerConfigLab{}
	var e error
	l.admin, e = pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(l.admin.Close)
	_, e = l.admin.Exec(ctx, "INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'synthetic-owner-configuration',1,$3)", c.Pool.InstallationID, c.Pool.IssuerEpoch, bytes.Repeat([]byte{42}, 32))
	if e != nil {
		t.Fatal(e)
	}
	l.observation, e = readSyntheticFleetBinding(ctx, l.admin, c.Pool.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	makeLedger := func(role, password string) (*pgxpool.Pool, *postgres.OwnerConfigurations) {
		t.Helper()
		pc, e := pgxpool.ParseConfig("postgres://" + role + ":" + password + "@" + address + "/custody_test?sslmode=disable")
		if e != nil {
			t.Fatal(e)
		}
		pc.ConnConfig.TLSConfig = tlsConfig
		pc.ConnConfig.Fallbacks = nil
		pc.MaxConns = 4
		p, e := pgxpool.NewWithConfig(ctx, pc)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(p.Close)
		v, e := postgres.NewOwnerConfigurations(ctx, p, c.Pool.InstallationID, c.Pool.ClusterID, c.Pool.NamespaceUID, c.Revision.UID)
		if e != nil {
			t.Fatal(e)
		}
		return p, v
	}
	l.writerPool, l.writer = makeLedger("owner_configuration_runtime", "synthetic-owner-configuration")
	l.readerPool, l.reader = makeLedger("owner_configuration_read_runtime", "synthetic-owner-configuration-read")
	return l
}

func ownerEnrollmentLab(t *testing.T, ctx context.Context, f fixture, c value.OwnerConfiguration) *ownerConfigLab {
	t.Helper()
	l := ownerConfigurationLab(t, ctx, f, c)
	var e error
	tls := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &tls.URL, UsePathStyle: true, Credentials: creds, HTTPClient: tls.Client(), RetryMaxAttempts: 1})
	bucket := "owner-configuration-" + custodyID()
	if _, e = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal(e)
	}
	// Active owner audit requires real immutable versions, including legacy input formats.
	if _, e = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	store, e := objectstore.NewVersionedAudit(tls.URL, "us-east-1", bucket, creds, tls.Client())
	if e != nil {
		t.Fatal(e)
	}
	material := make([]byte, 32)
	if _, e = rand.Read(material); e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(material)
	clear(material)
	if e != nil {
		t.Fatal(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	keys := authorityTestKeys{a: aead}
	l.audit = &objectstore.OwnerEnrollmentAuditObjects{Store: store, Seal: keys, Open: keys}
	return l
}

// Older component fixtures synthesize the order of API responses. Production
// takes its resource version directly from the ConfigMap collection.
func fixtureOwnerVersion(at time.Time) string { return strconv.FormatInt(at.UnixNano(), 10) }
func (l *ownerConfigLab) observe(ctx context.Context, o value.OwnerConfigurationObservation) error {
	return l.writer.ApplyOwnerConfiguration(ctx, fixtureOwnerVersion(o.ObservedAt), o)
}
func (l *ownerConfigLab) fence(ctx context.Context, at time.Time) error {
	return l.writer.ApplyOwnerConfiguration(ctx, fixtureOwnerVersion(at), value.OwnerConfigurationObservation{})
}

type refreshedOwnerConfiguration struct {
	source app.OwnerConfigurationReader
	lab    *ownerConfigLab
}

func (s refreshedOwnerConfiguration) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	o, err := s.source.ReadOwnerConfiguration(ctx)
	if err != nil {
		if e := s.lab.fence(ctx, time.Now()); e != nil {
			return o, e
		}
		return o, err
	}
	if err = s.lab.observe(ctx, o); err != nil {
		return o, err
	}
	return s.lab.reader.ReadOwnerConfiguration(ctx)
}

func TestEnrollmentOwnerConfigurationWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run make custody-integration for owned SQL/S3")
	}
	var f fixture
	b, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(b)
	ctx, end := context.WithTimeout(context.Background(), 30*time.Second)
	defer end()
	c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: custodyID(), ClusterID: custodyID(), IssuerEpoch: custodyID(), Namespace: "hub", NamespaceUID: custodyID(), Service: "owner", ServiceUID: custodyID(), Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 8443}, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{[]byte("synthetic public CA input; X509 qualification tested separately")}}
	l := ownerConfigurationLab(t, ctx, f, c)
	observation := func(c value.OwnerConfiguration) value.OwnerConfigurationObservation {
		n := time.Now().UTC().Truncate(time.Microsecond)
		return value.OwnerConfigurationObservation{Configuration: c, ObservedAt: n, FreshUntil: n.Add(4 * time.Second)}
	}
	denied := func(reason string) {
		t.Helper()
		if _, e := l.reader.ReadOwnerConfiguration(ctx); e == nil {
			t.Fatal(reason)
		}
	}
	accept := func(c value.OwnerConfiguration) value.OwnerConfigurationObservation {
		t.Helper()
		o := observation(c)
		if e := l.observe(ctx, o); e != nil {
			t.Fatal("observe", e)
		}
		return o
	}
	denied("missing configuration usable")
	// Persist an outage before any successful observation; old delayed work is
	// rejected even when a new adapter instance starts after the outage.
	old := observation(c)
	if e = l.fence(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = l.observe(ctx, old); e != nil {
		t.Fatal(e)
	} else {
		denied("delayed pre-outage observation accepted")
	}
	o := observation(c)
	if e := l.observe(ctx, o); e != nil {
		t.Fatal(e)
	}
	current, e := l.reader.ReadOwnerConfiguration(ctx)
	if e != nil || !current.Configuration.Equal(c) || !current.Valid(time.Now()) || current.FreshUntil.After(o.FreshUntil) {
		t.Fatal("accepted original observation", e)
	}
	checkAudit := func(config value.OwnerConfiguration, want int) {
		t.Helper()
		body, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		err = l.admin.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE operation_id=$1 AND operation='observe_owner_configuration'
			AND issuer=$2 AND subject=$3 AND reason=$4 AND input_digest=sha256($5::bytea) AND effect='accepted'`, config.Revision.UID, config.Pool.InstallationID, config.Pool.ClusterID, strconv.FormatInt(config.Revision.Generation, 10), body).Scan(&count)
		if err != nil || count != want {
			t.Fatal("revision audit", count, want, err)
		}
	}
	checkAudit(c, 1)
	extended := o
	extended.FreshUntil = extended.FreshUntil.Add(time.Microsecond)
	if e = l.observe(ctx, extended); e == nil {
		t.Fatal("same observation extended")
	}
	// A replacement SQL reader keeps the source pin and cannot extend its original cutoff.
	restarted, e := postgres.NewOwnerConfigurations(ctx, l.readerPool, c.Pool.InstallationID, c.Pool.ClusterID, c.Pool.NamespaceUID, c.Revision.UID)
	if e != nil {
		t.Fatal(e)
	}
	if again, e := restarted.ReadOwnerConfiguration(ctx); e != nil || !again.Configuration.Equal(c) || !again.Valid(time.Now()) || again.FreshUntil.After(o.FreshUntil) {
		t.Fatal("restart changed acceptance", e)
	}
	// Actual concurrent transactions may replay an observation, never create a
	// different accepted revision or require another key wrap for its audit.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			errs <- l.observe(ctx, o)
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal("concurrent replay", e)
		}
	}
	// Same-generation mutation and rollback must commit an immediate fence,
	// rather than returning an error that rolls the denial back.
	checkAudit(c, 1)
	changed := c.Clone()
	changed.Pool.Port++
	if e = l.observe(ctx, observation(changed)); !errors.Is(e, value.ErrConflict) {
		t.Fatal("mutation", e)
	}
	denied("mutation left old trust fresh")
	o = accept(c)
	c2 := c.Clone()
	c2.Revision.Generation++
	c2.Revision.Digest = artifact.Digest{3}
	// Reject this synthetic event at the destination table. The same transaction
	// must leave the previous head current, with no new revision or event.
	reject := "ALTER TABLE audit_event ADD CONSTRAINT test_owner_reject CHECK (operation_id <> '" + c.Revision.UID + "'::uuid OR reason <> '2') NOT VALID"
	if _, e = l.admin.Exec(ctx, reject); e != nil {
		t.Fatal(e)
	}
	defer l.admin.Exec(context.Background(), "ALTER TABLE audit_event DROP CONSTRAINT IF EXISTS test_owner_reject")
	if e = l.observe(ctx, observation(c2)); e == nil {
		t.Fatal("configuration committed after audit insert failed")
	}
	checkAudit(c2, 0)
	var revisions int
	if e = l.admin.QueryRow(ctx, "SELECT count(*) FROM hub_owner_configuration_revision WHERE source_uid=$1 AND generation=2", c.Revision.UID).Scan(&revisions); e != nil || revisions != 0 {
		t.Fatal("failed revision survived", revisions, e)
	}
	if got, err := l.reader.ReadOwnerConfiguration(ctx); err != nil || !got.Configuration.Equal(c) {
		t.Fatal("failed audit replaced the previous head", err)
	}
	if _, e = l.admin.Exec(ctx, "ALTER TABLE audit_event DROP CONSTRAINT test_owner_reject"); e != nil {
		t.Fatal(e)
	}
	accept(c2)
	checkAudit(c2, 1)
	if e = l.observe(ctx, observation(c)); !errors.Is(e, value.ErrConflict) {
		t.Fatal("rollback", e)
	}
	denied("rollback left old trust fresh")
	o = accept(c2)
	if e = l.fence(ctx, o.ObservedAt.Add(-time.Microsecond)); e != nil {
		t.Fatal(e)
	}
	if _, e = l.reader.ReadOwnerConfiguration(ctx); e != nil {
		t.Fatal("obsolete failure fenced newer observation", e)
	}
	if e = l.fence(ctx, o.ObservedAt); e != nil {
		t.Fatal(e)
	}
	if e = l.observe(ctx, o); e == nil {
		t.Fatal("same-time replay undid fence")
	}
	denied("fenced observation usable")
	accept(c2)
	// Source replacement is not ordinary refresh or automatic recovery.
	other := c2.Clone()
	other.Revision.UID = custodyID()
	replacement, e := postgres.NewOwnerConfigurations(ctx, l.writerPool, c.Pool.InstallationID, c.Pool.ClusterID, c.Pool.NamespaceUID, other.Revision.UID)
	if e != nil {
		t.Fatal(e)
	}
	if e = replacement.ApplyOwnerConfiguration(ctx, fixtureOwnerVersion(time.Now()), observation(other)); e == nil {
		t.Fatal("source replacement silently accepted")
	}
	for name, p := range map[string]*pgxpool.Pool{"writer": l.writerPool, "reader": l.readerPool} {
		for _, sql := range []string{"DELETE FROM hub_owner_configuration", "UPDATE hub_owner_configuration SET source_uid=gen_random_uuid()", "UPDATE hub_owner_configuration_revision SET snapshot_json=decode('00','hex')"} {
			if _, e = p.Exec(ctx, sql); e == nil {
				t.Fatalf("%s bypassed immutable source: %s", name, sql)
			}
		}
	}
	if _, e = l.readerPool.Exec(ctx, "UPDATE hub_owner_configuration SET generation=generation+1"); e == nil {
		t.Fatal("reader advanced revision")
	}
	if _, e = l.writerPool.Exec(ctx, "UPDATE audit_event SET reason='changed' WHERE operation_id=$1", c.Revision.UID); e == nil {
		t.Fatal("source role rewrote its audit")
	}
	c3 := c2.Clone()
	c3.Revision.Generation++
	c3.Revision.Digest = artifact.Digest{4}
	c3.Suspended = true
	accept(c3)
	denied("suspended configuration usable")
	c4 := c3.Clone()
	c4.Revision.Generation++
	c4.Revision.Digest = artifact.Digest{5}
	c4.Suspended = false
	accept(c4)
	accept(c4)
	// The reader checks original expiry after an actual blocking row lock.
	short := observation(c4)
	short.FreshUntil = short.ObservedAt.Add(200 * time.Millisecond)
	if e = l.observe(ctx, short); e != nil {
		t.Fatal(e)
	}
	tx, e := l.admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, "SELECT 1 FROM hub_owner_configuration WHERE installation_id=$1 FOR UPDATE", c.Pool.InstallationID); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, e := l.reader.ReadOwnerConfiguration(ctx); result <- e }()
	// Prove that the request reached PostgreSQL's lock wait before expiry.
	for {
		var waiting bool
		if e = l.admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='owner_configuration_read_runtime' AND wait_event_type='Lock')").Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		if !time.Now().Before(short.FreshUntil) {
			t.Fatal("reader did not reach lock before expiry")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(time.Until(short.FreshUntil) + 20*time.Millisecond)
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-result; e == nil {
		t.Fatal("expiry during lock wait ignored")
	}
	accept(c4)
	// A Kubernetes baseline can remain unchanged across an idle interval. SQL
	// gives each caller its own bounded observation, capped by the accepted CA.
	durable := observation(c4)
	durable.FreshUntil = durable.ObservedAt.Add(time.Minute)
	if e = l.observe(ctx, durable); e != nil {
		t.Fatal(e)
	}
	time.Sleep(5100 * time.Millisecond)
	op, err := l.reader.ReadOwnerConfiguration(ctx)
	if err != nil || !op.Valid(time.Now()) || op.ObservedAt.Before(durable.ObservedAt.Add(5*time.Second)) || op.FreshUntil.After(op.ObservedAt.Add(5*time.Second)) {
		t.Fatal("idle durable owner source did not serve bounded operation", op.ObservedAt, op.FreshUntil, err)
	}
	var baseline time.Time
	if e = l.admin.QueryRow(ctx, "SELECT observed_at FROM hub_owner_configuration WHERE installation_id=$1", c.Pool.InstallationID).Scan(&baseline); e != nil || !baseline.Before(op.ObservedAt.Add(-5*time.Second)) {
		t.Fatal("idle baseline changed", baseline, durable.ObservedAt, e)
	}
	// More than 1024 actual revisions remain auditable and the source is usable.
	if _, e = l.writerPool.Exec(ctx, `INSERT INTO hub_owner_configuration_revision(installation_id,cluster_id,source_uid,generation,snapshot_json)
		SELECT installation_id,cluster_id,source_uid,n,snapshot_json FROM hub_owner_configuration_revision
		CROSS JOIN generate_series(5,1024) n WHERE installation_id=$1 AND generation=4`, c.Pool.InstallationID); e != nil {
		t.Fatal(e)
	}
	next := c4.Clone()
	next.Revision.Generation = 1025
	accept(next)
	checkAudit(next, 1)
	if got, err := l.reader.ReadOwnerConfiguration(ctx); err != nil || !got.Configuration.Equal(next) {
		t.Fatal("later configuration unavailable", err)
	}
	checkOwnerTakeoverAndDeletion(t, ctx, l, next)
}
