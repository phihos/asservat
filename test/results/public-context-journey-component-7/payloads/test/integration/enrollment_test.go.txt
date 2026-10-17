package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEnrollmentWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run make custody-integration")
	}
	var f struct{ Postgres, S3 string }
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
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
	c, err := pgxpool.ParseConfig("postgres://enrollment_claim_runtime:synthetic-enrollment-claim@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	c.ConnConfig.TLSConfig = tlsConfig
	c.ConnConfig.Fallbacks = nil
	c.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	setup := func(modes ...string) (value.EnrollmentClaim, *postgres.EnrollmentClaims) {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		claim := value.EnrollmentClaim{InstallationID: uuid.NewString(), BootstrapID: uuid.NewString(), SecretDigest: artifact.Digest{1}, PublicKeyDigest: artifact.Digest{2}}
		epoch := uuid.NewString()
		notBefore, notAfter := now, now.Add(5*time.Minute)
		if len(modes) > 0 {
			if modes[0] == "expired" {
				notBefore, notAfter = now.Add(-time.Minute), now.Add(-time.Second)
			}
			if modes[0] == "expiry-during-lock" {
				notAfter = now.Add(200 * time.Millisecond)
			}
		}
		_, e := admin.Exec(ctx, `INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'fixture',1,$3,false,false,$4,$5)`, claim.InstallationID, epoch, claim.SecretDigest[:], now, now.Add(30*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		if _, err := seedSyntheticFleetObservation(ctx, admin, claim.InstallationID); err != nil {
			t.Fatal(err)
		}
		_, e = admin.Exec(ctx, `INSERT INTO fleet_bootstrap(installation_id,id,cluster_id,peer_id,issuer_epoch,secret_sha256,not_before,not_after,issue_authority_digest,issue_audit_id,issue_audit_key,issue_audit_version,issue_audit_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$6,$9,'bootstrap-issue/v1/' || $1::uuid::text || '/' || $9::uuid::text || '/record','v1',$6)`, claim.InstallationID, claim.BootstrapID, uuid.NewString(), uuid.NewString(), epoch, claim.SecretDigest[:], notBefore, notAfter, uuid.NewString())
		if e != nil {
			t.Fatal(e)
		}
		ledger, e := postgres.NewEnrollmentClaims(ctx, pool, claim.InstallationID)
		if e != nil {
			t.Fatal(e)
		}
		return claim, ledger
	}
	t.Run("encrypted-claim-audit-before-signing", func(t *testing.T) {
		claim, ledger := setup()
		if _, e := ledger.ClaimConnector(ctx, claim); e != nil {
			t.Fatal(e)
		}
		config := c.Copy()
		config.ConnConfig.User = "enrollment_audit_runtime"
		config.ConnConfig.Password = "synthetic-enrollment-audit"
		auditPool, e := pgxpool.NewWithConfig(ctx, config)
		if e != nil {
			t.Fatal(e)
		}
		defer auditPool.Close()
		audits, e := postgres.NewEnrollmentClaimAudits(ctx, auditPool, claim.InstallationID)
		if e != nil {
			t.Fatal(e)
		}
		pending, e := audits.PendingEnrollmentClaims(ctx)
		if e != nil || len(pending) != 1 {
			t.Fatal(pending, e)
		}
		r := pending[0]
		bridge := tlsBridge(t, f.S3)
		creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
		bucket := "enrollment-audit"
		s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
		if _, e = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); e != nil {
			t.Fatal(e)
		}
		if _, e = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
			t.Fatal(e)
		}
		store, e := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
		if e != nil {
			t.Fatal(e)
		}
		raw := make([]byte, 32)
		if _, e = rand.Read(raw); e != nil {
			t.Fatal(e)
		}
		block, e := aes.NewCipher(raw)
		clear(raw)
		if e != nil {
			t.Fatal(e)
		}
		aead, e := cipher.NewGCM(block)
		if e != nil {
			t.Fatal(e)
		}
		keys := authorityTestKeys{aead}
		writer := &objectstore.EnrollmentClaimObjects{Store: store, Open: keys}
		if e = (auditapp.EnrollmentClaimPublisher{Ledger: audits, Objects: writer}).PublishEnrollmentClaims(ctx); e == nil {
			t.Fatal("missing encryption accepted")
		}
		pending, e = audits.PendingEnrollmentClaims(ctx)
		if e != nil || len(pending) != 1 {
			t.Fatal("failed write acknowledged", e)
		}
		writer.Seal = keys
		receipt, e := writer.WriteEnrollmentClaim(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		replay, e := writer.WriteEnrollmentClaim(ctx, r)
		if e != nil || receipt != replay {
			t.Fatal("retry changed stored encrypted audit", e)
		}
		changed := r
		changed.PublicKeyDigest[0]++
		if _, e = writer.WriteEnrollmentClaim(ctx, changed); e == nil {
			t.Fatal("overwrote frozen audit")
		}
		if e = audits.AcknowledgeEnrollmentClaim(ctx, changed, receipt); !errors.Is(e, value.ErrDenied) {
			t.Fatal("changed audit acknowledged", e)
		}
		// Revocation stops issuance, not preservation of what already happened.
		if _, e = admin.Exec(ctx, "UPDATE fleet_bootstrap SET revoked=true WHERE installation_id=$1", claim.InstallationID); e != nil {
			t.Fatal(e)
		}
		if e = (auditapp.EnrollmentClaimPublisher{Ledger: audits, Objects: writer}).PublishEnrollmentClaims(ctx); e != nil {
			t.Fatal(e)
		}
		if e = audits.AcknowledgeEnrollmentClaim(ctx, r, receipt); e != nil {
			t.Fatal("original acknowledgement not idempotent", e)
		}
		pending, e = audits.PendingEnrollmentClaims(ctx)
		if e != nil || len(pending) != 0 {
			t.Fatal("published audit pending", e)
		}
		changedReceipt := receipt
		changedReceipt.SHA256[0]++
		if e = audits.AcknowledgeEnrollmentClaim(ctx, r, changedReceipt); !errors.Is(e, value.ErrDenied) {
			t.Fatal("changed receipt accepted", e)
		}
		for _, sql := range []string{"UPDATE fleet_bootstrap SET claim_acknowledged_at=NULL,claim_audit_digest=NULL,claim_object_key=NULL,claim_object_version=NULL,claim_object_etag=NULL,claim_object_bytes=NULL,claim_object_sha256=NULL WHERE installation_id=$1", "UPDATE fleet_bootstrap SET claim_object_sha256=decode(repeat('ff',32),'hex') WHERE installation_id=$1", "UPDATE fleet_bootstrap SET claimed_at=NULL,public_key_sha256=NULL WHERE installation_id=$1", "UPDATE fleet_peer SET enabled=true WHERE installation_id=$1"} {
			if _, e = auditPool.Exec(ctx, sql, claim.InstallationID); e == nil {
				t.Fatal("audit role rewrote history or authority")
			}
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM fleet_peer WHERE installation_id=$1", claim.InstallationID).Scan(&count); e != nil || count != 0 {
			t.Fatal("audit activated peer", e)
		}
	})
	t.Run("claim-role-cannot-issue-or-enable", func(t *testing.T) {
		for _, sql := range []string{"UPDATE fleet_bootstrap SET revoked=false", "UPDATE fleet_bootstrap SET not_after=clock_timestamp()+interval '5 minutes'", "DELETE FROM fleet_bootstrap", "UPDATE fleet_peer SET enabled=true", "UPDATE fleet_trust SET suspended=false"} {
			if _, e := pool.Exec(ctx, sql); e == nil {
				t.Fatal("claim role expanded authority")
			}
		}
	})
	t.Run("concurrent-identical-retry-and-restart", func(t *testing.T) {
		claim, ledger := setup()
		var wg sync.WaitGroup
		var first, replays atomic.Int64
		var mu sync.Mutex
		peer := ""
		for range 8 {
			wg.Go(func() {
				v, e := ledger.ClaimConnector(ctx, claim)
				if e != nil {
					t.Error(e)
					return
				}
				if v.Replay {
					replays.Add(1)
				} else {
					first.Add(1)
				}
				mu.Lock()
				defer mu.Unlock()
				if peer != "" && peer != v.Binding.PeerID {
					t.Error("retry allocated another peer")
				}
				peer = v.Binding.PeerID
			})
		}
		wg.Wait()
		if first.Load() != 1 || replays.Load() != 7 {
			t.Fatal(first.Load(), replays.Load())
		}
		restarted, e := postgres.NewEnrollmentClaims(ctx, pool, claim.InstallationID)
		if e != nil {
			t.Fatal(e)
		}
		v, e := restarted.ClaimConnector(ctx, claim)
		if e != nil || !v.Replay || v.Binding.PeerID != peer {
			t.Fatal(v, e)
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM fleet_peer WHERE installation_id=$1", claim.InstallationID).Scan(&count); e != nil || count != 0 {
			t.Fatal("claim activated peer authority", count, e)
		}
		for _, sql := range []string{"UPDATE fleet_bootstrap SET claimed_at=NULL,public_key_sha256=NULL WHERE installation_id=$1", "UPDATE fleet_bootstrap SET public_key_sha256=decode(repeat('ff',32),'hex') WHERE installation_id=$1"} {
			if _, e = pool.Exec(ctx, sql, claim.InstallationID); e == nil {
				t.Fatal("SQL role reset consumed claim")
			}
		}
	})
	t.Run("competing-keys-have-one-winner", func(t *testing.T) {
		claim, ledger := setup()
		var wg sync.WaitGroup
		var winners atomic.Int64
		for i := range 2 {
			candidate := claim
			candidate.PublicKeyDigest = artifact.Digest{byte(2 + i)}
			wg.Go(func() {
				_, e := ledger.ClaimConnector(ctx, candidate)
				if e == nil {
					winners.Add(1)
				}
			})
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatal("multiple keys consumed bootstrap", winners.Load())
		}
	})
	for _, mode := range []string{"secret", "replacement-key", "revocation-after-claim", "epoch", "recovery", "stale-trust", "expired", "expiry-during-lock"} {
		t.Run(mode, func(t *testing.T) {
			claim, ledger := setup(mode)
			update := func(sql string, args ...any) {
				t.Helper()
				if _, e := admin.Exec(ctx, sql, args...); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "secret":
				claim.SecretDigest = artifact.Digest{3}
			case "replacement-key", "revocation-after-claim":
				if _, e := ledger.ClaimConnector(ctx, claim); e != nil {
					t.Fatal(e)
				}
				if mode == "replacement-key" {
					claim.PublicKeyDigest = artifact.Digest{3}
				} else {
					update("UPDATE fleet_bootstrap SET revoked=true WHERE installation_id=$1", claim.InstallationID)
				}
			case "epoch":
				update("UPDATE fleet_trust SET issuer_epoch=$2 WHERE installation_id=$1", claim.InstallationID, uuid.NewString())
			case "recovery":
				update("UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", claim.InstallationID)
			case "stale-trust":
				update("UPDATE fleet_observation SET observed_at=clock_timestamp()-interval '30 seconds',fresh_until=clock_timestamp()-interval '1 second' WHERE installation_id=$1", claim.InstallationID)
			case "expired":
			case "expiry-during-lock":
				tx, e := admin.BeginTx(ctx, pgx.TxOptions{})
				if e != nil {
					t.Fatal(e)
				}
				defer tx.Rollback(ctx)
				if _, e = tx.Exec(ctx, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE", claim.InstallationID); e != nil {
					t.Fatal(e)
				}
				done := make(chan error, 1)
				go func() { _, e := ledger.ClaimConnector(ctx, claim); done <- e }()
				time.Sleep(300 * time.Millisecond)
				if e = tx.Commit(ctx); e != nil {
					t.Fatal(e)
				}
				if e = <-done; e == nil {
					t.Fatal("expired waiting claim accepted")
				}
				return
			}
			if _, e := ledger.ClaimConnector(ctx, claim); e == nil {
				t.Fatal("unsafe bootstrap claim accepted", mode)
			}
		})
	}
}
