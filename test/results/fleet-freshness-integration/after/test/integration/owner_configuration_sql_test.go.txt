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
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ownerConfigLab struct {
	observation                            syntheticFleetBinding
	admin, writerPool, ackPool, readerPool *pgxpool.Pool
	writer, ack, reader                    *postgres.OwnerConfigurations
	audit                                  *objectstore.OwnerConfigurationAuditObjects
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
	_, e = l.admin.Exec(ctx, "INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'synthetic-owner-configuration',1,$3,false,false,statement_timestamp(),statement_timestamp()+interval '30 seconds')", c.Pool.InstallationID, c.Pool.IssuerEpoch, bytes.Repeat([]byte{42}, 32))
	if e != nil {
		t.Fatal(e)
	}
	l.observation, e = seedSyntheticFleetObservation(ctx, l.admin, c.Pool.InstallationID)
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
	l.ackPool, l.ack = makeLedger("owner_configuration_audit_runtime", "synthetic-owner-configuration-audit")
	l.readerPool, l.reader = makeLedger("owner_configuration_read_runtime", "synthetic-owner-configuration-read")
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
	l.audit = &objectstore.OwnerConfigurationAuditObjects{Store: store, Seal: keys, Open: keys}
	return l
}

type refreshedOwnerConfiguration struct {
	observer *app.OwnerConfigurationObserver
	current  *postgres.OwnerConfigurations
}

func (s refreshedOwnerConfiguration) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	if e := s.observer.Observe(ctx); e != nil {
		return value.OwnerConfigurationObservation{}, e
	}
	return s.current.ReadOwnerConfiguration(ctx)
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
	accept := func(c value.OwnerConfiguration) (value.OwnerConfigurationObservation, audit.Receipt) {
		t.Helper()
		o := observation(c)
		if _, _, e := l.writer.ObserveOwnerConfiguration(ctx, o); e != nil {
			t.Fatal("observe", e)
		}
		r, e := l.audit.WriteOwnerConfiguration(ctx, c)
		if e != nil {
			t.Fatal("audit", e)
		}
		if e = l.ack.AcknowledgeOwnerConfiguration(ctx, c, r); e != nil {
			t.Fatal("acknowledge", e)
		}
		return o, r
	}
	denied("missing configuration usable")
	// Persist an outage before any successful observation; old delayed work is
	// rejected even when a new adapter instance starts after the outage.
	old := observation(c)
	if e = l.writer.FenceOwnerConfiguration(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, old); e == nil {
		t.Fatal("delayed pre-outage observation accepted")
	}
	o := observation(c)
	if _, ack, e := l.writer.ObserveOwnerConfiguration(ctx, o); e != nil || ack {
		t.Fatal("first observation", e)
	}
	denied("unaudited configuration usable")
	r, e := l.audit.WriteOwnerConfiguration(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	if e = l.writer.AcknowledgeOwnerConfiguration(ctx, c, r); e == nil {
		t.Fatal("observer acknowledged its own audit")
	}
	if e = l.ack.AcknowledgeOwnerConfiguration(ctx, c, r); e != nil {
		t.Fatal(e)
	}
	current, e := l.reader.ReadOwnerConfiguration(ctx)
	if e != nil || !current.Configuration.Equal(c) || !current.ObservedAt.Equal(o.ObservedAt) || !current.FreshUntil.Equal(o.FreshUntil) {
		t.Fatal("accepted original observation", e)
	}
	if r2, e := l.audit.WriteOwnerConfiguration(ctx, c); e != nil || r2 != r {
		t.Fatal("audit replay changed receipt", e)
	}
	if rr, ack, e := l.writer.ObserveOwnerConfiguration(ctx, o); e != nil || !ack || rr != r {
		t.Fatal("acknowledged observation replay", e)
	}
	extended := o
	extended.FreshUntil = extended.FreshUntil.Add(time.Microsecond)
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, extended); e == nil {
		t.Fatal("same observation extended")
	}
	// A replacement SQL reader preserves the exact source pin and deadline.
	restarted, e := postgres.NewOwnerConfigurations(ctx, l.readerPool, c.Pool.InstallationID, c.Pool.ClusterID, c.Pool.NamespaceUID, c.Revision.UID)
	if e != nil {
		t.Fatal(e)
	}
	if again, e := restarted.ReadOwnerConfiguration(ctx); e != nil || !again.FreshUntil.Equal(current.FreshUntil) {
		t.Fatal("restart changed acceptance", e)
	}
	// Actual concurrent transactions may replay an observation, never create a
	// different accepted revision or require another key wrap for its audit.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			rr, ack, e := l.writer.ObserveOwnerConfiguration(ctx, o)
			if e == nil && (!ack || rr != r) {
				e = errors.New("lost audit receipt")
			}
			errs <- e
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
	changed := c.Clone()
	changed.Pool.Port++
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, observation(changed)); !errors.Is(e, value.ErrConflict) {
		t.Fatal("mutation", e)
	}
	denied("mutation left old trust fresh")
	o, r = accept(c)
	c2 := c.Clone()
	c2.Revision.Generation++
	c2.Revision.Digest = artifact.Digest{3}
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, observation(c2)); e != nil {
		t.Fatal(e)
	}
	denied("new unaudited revision left old trust usable")
	if e = l.ack.AcknowledgeOwnerConfiguration(ctx, c, r); e != nil {
		t.Fatal(e)
	}
	denied("late old audit revived configuration")
	accept(c2)
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, observation(c)); !errors.Is(e, value.ErrConflict) {
		t.Fatal("rollback", e)
	}
	denied("rollback left old trust fresh")
	o, _ = accept(c2)
	if e = l.writer.FenceOwnerConfiguration(ctx, o.ObservedAt.Add(-time.Microsecond)); e != nil {
		t.Fatal(e)
	}
	if _, e = l.reader.ReadOwnerConfiguration(ctx); e != nil {
		t.Fatal("obsolete failure fenced newer observation", e)
	}
	if e = l.writer.FenceOwnerConfiguration(ctx, o.ObservedAt); e != nil {
		t.Fatal(e)
	}
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, o); e == nil {
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
	if _, _, e = replacement.ObserveOwnerConfiguration(ctx, observation(other)); e == nil {
		t.Fatal("source replacement silently accepted")
	}
	for name, p := range map[string]*pgxpool.Pool{"writer": l.writerPool, "audit": l.ackPool, "reader": l.readerPool} {
		for _, sql := range []string{"DELETE FROM hub_owner_configuration", "UPDATE hub_owner_configuration SET source_uid=gen_random_uuid()", "UPDATE fleet_trust SET recovery_blocked=false", "UPDATE hub_owner_configuration_revision SET snapshot_json=decode('00','hex')"} {
			if _, e = p.Exec(ctx, sql); e == nil {
				t.Fatalf("%s bypassed immutable source: %s", name, sql)
			}
		}
	}
	if _, e = l.readerPool.Exec(ctx, "UPDATE hub_owner_configuration SET generation=generation+1"); e == nil {
		t.Fatal("reader advanced revision")
	}
	if _, e = l.ackPool.Exec(ctx, "UPDATE hub_owner_configuration_revision SET audit_receipt_json=decode('00','hex')"); e == nil {
		t.Fatal("ack overwrote receipt")
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
	if _, e = l.admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", c.Pool.InstallationID); e != nil {
		t.Fatal(e)
	}
	denied("blocked recovery usable")
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, observation(c4)); e == nil {
		t.Fatal("observer cleared recovery")
	}
	if e = l.writer.FenceOwnerConfiguration(ctx, time.Now()); e != nil {
		t.Fatal("negative fence requires active recovery", e)
	}
	if _, e = l.admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", c.Pool.InstallationID); e != nil {
		t.Fatal(e)
	}
	if restored, err := replaceSyntheticFleetObservationAfterActivation(ctx, l.admin, c.Pool.InstallationID); err != nil {
		t.Fatal(err)
	} else {
		l.observation = restored
	}
	denied("recovery reset revived fenced config")
	accept(c4)
	// The reader checks original expiry after an actual blocking row lock.
	short := observation(c4)
	short.FreshUntil = short.ObservedAt.Add(200 * time.Millisecond)
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, short); e != nil {
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
	// SQL enforces the finite history even when a caller bypasses the Go
	// capacity check. These extra snapshots are synthetic, unaudited history.
	if _, e = l.writerPool.Exec(ctx, "INSERT INTO hub_owner_configuration_revision(installation_id,cluster_id,source_uid,generation,snapshot_json) SELECT installation_id,cluster_id,source_uid,n,snapshot_json FROM hub_owner_configuration_revision CROSS JOIN generate_series(5,1024) n WHERE installation_id=$1 AND generation=4", c.Pool.InstallationID); e != nil {
		t.Fatal("fill bounded history", e)
	}
	if _, e = l.writerPool.Exec(ctx, "INSERT INTO hub_owner_configuration_revision(installation_id,cluster_id,source_uid,generation,snapshot_json) SELECT installation_id,cluster_id,source_uid,1025,snapshot_json FROM hub_owner_configuration_revision WHERE installation_id=$1 AND generation=4", c.Pool.InstallationID); e == nil {
		t.Fatal("database accepted history above limit")
	}
	next := c4.Clone()
	next.Revision.Generation = 1025
	if _, _, e = l.writer.ObserveOwnerConfiguration(ctx, observation(next)); !errors.Is(e, value.ErrCapacity) {
		t.Fatal("revision capacity", e)
	}
	denied("full history left previous trust usable after new revision")
	accept(c4)
	if _, e = l.admin.Exec(ctx, "UPDATE fleet_trust SET issuer_epoch=$2 WHERE installation_id=$1", c.Pool.InstallationID, custodyID()); e != nil {
		t.Fatal(e)
	}
	denied("issuer replacement accepted old config")
	t.Log("real SQL/S3 owner acceptance: failure-before-first-read, encrypted audit gating/replay, restart, eight-way replay, mutation/rollback fencing, immutable source/roles/history bound, suspension/recovery/issuer changes, and expiry after proven lock wait")
}
