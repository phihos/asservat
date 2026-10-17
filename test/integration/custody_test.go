package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
)

var custodyIDs atomic.Uint64

func custodyID() string { return fmt.Sprintf("10000000-0000-4000-8000-%012x", custodyIDs.Add(1)) }

// Adapter-facing TLS with a private plaintext fixture hop; not a production
// PostgreSQL TLS/failover qualification. Understand PostgreSQL's SSLRequest.
func pgTLSBridge(t *testing.T, backend string) (string, *tls.Config) {
	t.Helper()
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(cert.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				var pre [8]byte
				if _, e := io.ReadFull(raw, pre[:]); e != nil || !bytes.Equal(pre[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
					return
				}
				if _, e := raw.Write([]byte("S")); e != nil {
					return
				}
				conn := tls.Server(raw, cert.TLS.Clone())
				if conn.Handshake() != nil {
					return
				}
				up, e := net.DialTimeout("tcp", backend, time.Second)
				if e != nil {
					return
				}
				defer up.Close()
				_ = raw.SetDeadline(time.Time{})
				finished := make(chan struct{})
				go func() { _, _ = io.Copy(up, conn); _ = up.Close(); close(finished) }()
				_, _ = io.Copy(conn, up)
				_ = conn.Close()
				<-finished
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done; wg.Wait() })
	ca := x509.NewCertPool()
	ca.AddCert(cert.Certificate())
	return ln.Addr().String(), &tls.Config{RootCAs: ca, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

type fixtureBarrier struct {
	calls atomic.Int64
	fail  bool
}

func (b *fixtureBarrier) CloseAndWait(context.Context, artifact.Registration) error {
	b.calls.Add(1)
	if b.fail {
		return errors.New("synthetic writer has not stopped")
	}
	return nil
}

func TestCustodyWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run make custody-integration for owned real-service fixtures")
	}
	var fixture struct{ Postgres, S3 string }
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &fixture) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(data)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, fixture.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	u, err := url.Parse(fixture.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	cfg, err := pgxpool.ParseConfig("postgres://custody_runtime:synthetic-runtime@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.TLSConfig = tlsConfig
	cfg.ConnConfig.Fallbacks = nil
	cfg.MaxConns = 32
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ledger, err := postgres.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "CREATE TABLE forbidden (id int)"); err == nil {
		t.Fatal("runtime can create tables")
	}
	if _, err = pool.Exec(ctx, "UPDATE goose_db_version SET version_id=1"); err == nil {
		t.Fatal("runtime can modify migration history")
	}
	if _, err = postgres.New(ctx, admin); err == nil {
		t.Fatal("plaintext/admin pool accepted")
	}

	newRegistration := func(allocation, store string) artifact.Registration {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return artifact.Registration{Location: artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: store, AllocationID: allocation, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 1024, AnchorAt: now.Add(-time.Second), WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
	}
	setup := func(t *testing.T, slots int) (string, string, string) {
		t.Helper()
		root, allocation, store := custodyID(), custodyID(), custodyID()
		valid := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
		r := newRegistration(allocation, store)
		_, err := admin.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,$3,$4,$5)", root, store, valid, r.ReservedBytes()*int64(slots), 4*slots)
		if err != nil {
			t.Fatal(err)
		}
		err = ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: allocation, PoolID: root, ScopeID: custodyID(), ServiceClass: "context", PoolRevision: 1, Revision: 1, Bytes: r.ReservedBytes() * int64(slots), Objects: int64(4 * slots), ValidUntil: valid})
		if err != nil {
			t.Fatal(err)
		}
		return root, allocation, store
	}
	charge := func(t *testing.T, allocation string) (int64, int64) {
		t.Helper()
		var b, o int64
		if err := admin.QueryRow(ctx, "SELECT charged_bytes,charged_objects FROM custody_allocation WHERE id=$1", allocation).Scan(&b, &o); err != nil {
			t.Fatal(err)
		}
		return b, o
	}
	t.Run("pool exhaustion is bounded and creates no charge", func(t *testing.T) {
		_, allocation, store := setup(t, 1)
		limitedConfig := cfg.Copy()
		limitedConfig.MaxConns = 1
		limitedPool, err := pgxpool.NewWithConfig(ctx, limitedConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer limitedPool.Close()
		limited, err := postgres.New(ctx, limitedPool)
		if err != nil {
			t.Fatal(err)
		}
		held, err := limitedPool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()
		result := make(chan error, 1)
		go func() {
			_, err := limited.Register(context.Background(), newRegistration(allocation, store))
			result <- err
		}()
		select {
		case err := <-result:
			if !errors.Is(err, privacy.ErrUnavailable) {
				t.Fatal("unbounded admission result", err)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("connection-pool wait exceeded transaction bound")
		}
		if b, o := charge(t, allocation); b != 0 || o != 0 {
			t.Fatal("pool pressure created a charge")
		}
	})
	fakeCopies := func() artifact.Copies {
		var c artifact.Copies
		for i := range c {
			c[i] = artifact.CopyReceipt{ETag: "synthetic", Bytes: 8, SHA256: artifact.Digest(sha256.Sum256([]byte("synthetic")))}
		}
		return c
	}
	parallel := func(n int, f func(int) error) []error {
		out := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() { defer wg.Done(); out[i] = f(i) }()
		}
		wg.Wait()
		return out
	}

	t.Run("last capacity slot and duplicate admission", func(t *testing.T) {
		_, a, s := setup(t, 1)
		var winners atomic.Int64
		results := parallel(32, func(int) error {
			_, err := ledger.Register(ctx, newRegistration(a, s))
			if err == nil {
				winners.Add(1)
			}
			return err
		})
		for _, e := range results {
			if e != nil && !errors.Is(e, privacy.ErrCapacity) {
				t.Fatal(e)
			}
		}
		if winners.Load() != 1 {
			t.Fatalf("winners %d", winners.Load())
		}
		b, o := charge(t, a)
		if b != newRegistration(a, s).ReservedBytes() || o != 4 {
			t.Fatal("overdraw")
		}
		_, a, s = setup(t, 1)
		r := newRegistration(a, s)
		for _, e := range parallel(32, func(int) error { _, err := ledger.Register(ctx, r); return err }) {
			if e != nil {
				t.Fatal(e)
			}
		}
		b, o = charge(t, a)
		if b != r.ReservedBytes() || o != 4 {
			t.Fatal("duplicate charged twice")
		}
		altered := r
		altered.NativeLimit++
		if _, err := ledger.Register(ctx, altered); !errors.Is(err, privacy.ErrConflict) {
			t.Fatalf("digest conflict: %v", err)
		}
		var copies, events int
		if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM custody_copy WHERE attempt_id=$1),(SELECT count(*) FROM custody_event WHERE attempt_id=$1)", r.Location.AttemptID).Scan(&copies, &events); err != nil || copies != 4 || events != 1 {
			t.Fatal("partial or duplicate inventory")
		}
	})
	t.Run("protected backing cannot be overallocated", func(t *testing.T) {
		root, a, s := setup(t, 1)
		err := ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: custodyID(), PoolID: root, ScopeID: custodyID(), ServiceClass: "evidence", PoolRevision: 1, Revision: 1, Bytes: 1, Objects: 1, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)})
		if !errors.Is(err, privacy.ErrCapacity) {
			t.Fatal(err)
		}
		if _, err = ledger.Register(ctx, newRegistration(a, s)); err != nil {
			t.Fatal("protected allocation stolen", err)
		}
		// Two independently backed workloads on the SAME pool: a full noisy
		// workload cannot spend the other workload's bytes or object slots.
		root, store, one, two := custodyID(), custodyID(), custodyID(), custodyID()
		valid := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
		bytesPerAttempt := newRegistration(one, store).ReservedBytes()
		if _, err := admin.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,$3,$4,8)", root, store, valid, 2*bytesPerAttempt); err != nil {
			t.Fatal(err)
		}
		for _, allocation := range []string{one, two} {
			if err := ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: allocation, PoolID: root, ScopeID: custodyID(), ServiceClass: "context", PoolRevision: 1, Revision: 1, Bytes: bytesPerAttempt, Objects: 4, ValidUntil: valid}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := ledger.Register(ctx, newRegistration(one, store)); err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Register(ctx, newRegistration(one, store)); !errors.Is(err, privacy.ErrCapacity) {
			t.Fatal("noisy workload borrowed protected capacity", err)
		}
		if _, err := ledger.Register(ctx, newRegistration(two, store)); err != nil {
			t.Fatal("neighbor on same pool blocked", err)
		}
	})
	t.Run("configuration fence and no counter leaks", func(t *testing.T) {
		_, a, s := setup(t, 1)
		r := newRegistration(a, s)
		r.AllocationRevision = 2
		if _, err := ledger.Register(ctx, r); !errors.Is(err, privacy.ErrFence) {
			t.Fatal(err)
		}
		if b, o := charge(t, a); b != 0 || o != 0 {
			t.Fatal("failed admission charged")
		}
	})
	// Hold a later lock until after the write deadline. These tests fail if the
	// adapter uses transaction-start time or checks only before lock acquisition.
	for _, operation := range []string{"register", "store"} {
		t.Run("post lock expiry "+operation, func(t *testing.T) {
			_, a, s := setup(t, 1)
			r := newRegistration(a, s)
			r.WriteUntil = time.Now().UTC().Truncate(time.Microsecond).Add(450 * time.Millisecond)
			if operation == "store" {
				if _, err := ledger.Register(ctx, r); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if operation == "register" {
				_, err = tx.Exec(ctx, "SELECT id FROM custody_allocation WHERE id=$1 FOR UPDATE", a)
			} else {
				_, err = tx.Exec(ctx, "SELECT id FROM custody_attempt WHERE id=$1 FOR UPDATE", r.Location.AttemptID)
			}
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				if operation == "register" {
					_, err := ledger.Register(ctx, r)
					result <- err
				} else {
					result <- ledger.StoreCopies(ctx, r, fakeCopies())
				}
			}()
			deadline := time.Now().Add(250 * time.Millisecond)
			blocked := false
			for time.Now().Before(deadline) {
				if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='custody_runtime' AND wait_event_type='Lock')").Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("did not observe intended lock wait")
			}
			time.Sleep(time.Until(r.WriteUntil.Add(30 * time.Millisecond)))
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, privacy.ErrExpired) {
				t.Fatalf("late operation accepted: %v", err)
			}
			b, o := charge(t, a)
			if operation == "register" && (b != 0 || o != 0) {
				t.Fatal("expired admission charged")
			}
			if operation == "store" && (b != r.ReservedBytes() || o != 4) {
				t.Fatal("uncertain stored bytes refunded")
			}
		})
	}
	t.Run("stored receipts are immutable and unpublished", func(t *testing.T) {
		_, a, s := setup(t, 1)
		r := newRegistration(a, s)
		if _, err := ledger.Register(ctx, r); err != nil {
			t.Fatal(err)
		}
		c := fakeCopies()
		for _, err := range parallel(16, func(int) error { return ledger.StoreCopies(ctx, r, c) }) {
			if err != nil {
				t.Fatal(err)
			}
		}
		rec, err := ledger.Lookup(ctx, r.Location)
		if err != nil || rec.State != artifact.StoredUnpublished {
			t.Fatal("wrong stored state", err)
		}
		c[0].ETag = "changed"
		if err = ledger.StoreCopies(ctx, r, c); !errors.Is(err, privacy.ErrConflict) {
			t.Fatal(err)
		}
		if b, _ := charge(t, a); b != r.ReservedBytes() {
			t.Fatal("unused/unknown bytes refunded")
		}
	})

	s3TLS := tlsBridge(t, fixture.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	s3Admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &s3TLS.URL, UsePathStyle: true, Credentials: creds, HTTPClient: s3TLS.Client(), RetryMaxAttempts: 1})
	bucket := "custody"
	if _, err := s3Admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err := s3Admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal("fixture versioning unsupported", err)
	}
	store, err := objectstore.New(s3TLS.URL, "us-east-1", bucket, creds, s3TLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("real version marker multipart cleanup and accounting", func(t *testing.T) {
		_, a, s := setup(t, 2)
		r := newRegistration(a, s)
		r.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Second)
		r.WriteUntil = r.ExpiresAt
		r.DeleteBy = r.ExpiresAt.Add(time.Second)
		if _, err := ledger.Register(ctx, r); err != nil {
			t.Fatal(err)
		}
		var receipts artifact.Copies
		for i := range receipts {
			b := []byte(fmt.Sprintf("synthetic opaque ciphertext %d", i))
			v, err := store.PutSmall(ctx, r.Location.Prefix()+artifact.Role(i), b)
			if err != nil {
				t.Fatal(err)
			}
			receipts[i] = artifact.CopyReceipt{VersionID: v.VersionID, ETag: v.ETag, Bytes: v.Bytes, SHA256: v.SHA256}
		}
		bound, err := store.ForCustody(s)
		if err != nil {
			t.Fatal(err)
		}
		bad := receipts
		bad[0].SHA256[0] ^= 1
		custodian := evidence.Custodian{Ledger: ledger, Verifier: bound}
		if err := custodian.VerifyAndStore(ctx, r, bad); !errors.Is(err, artifact.ErrIntegrity) {
			t.Fatal("corruption accepted", err)
		}
		if err := custodian.VerifyAndStore(ctx, r, receipts); err != nil {
			t.Fatal(err)
		}
		wrong, _ := store.ForCustody(custodyID())
		if err := wrong.PurgeAttempt(ctx, r); !errors.Is(err, artifact.ErrInvalid) {
			t.Fatal("wrong backend accepted", err)
		}
		// Synthetic administrative writes model versions left by uncertain/legacy
		// writers. They do not claim the production writer IAM is qualified.
		key := r.Location.Prefix() + "data"
		if _, err := s3Admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader([]byte("synthetic old version"))}); err != nil {
			t.Fatal(err)
		}
		if _, err := s3Admin.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key}); err != nil {
			t.Fatal(err)
		}
		multiKey := r.Location.Prefix() + "index"
		up, err := s3Admin.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &multiKey})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s3Admin.UploadPart(ctx, &s3.UploadPartInput{Bucket: &bucket, Key: &multiKey, UploadId: up.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("synthetic incomplete part"))}); err != nil {
			t.Fatal(err)
		}
		other := "v1/unrelated/data"
		if _, err = s3Admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &other, Body: bytes.NewReader([]byte("unrelated synthetic"))}); err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.ClaimDeletion(ctx, r.Location); !errors.Is(err, privacy.ErrNotDue) {
			t.Fatal(err)
		}
		time.Sleep(time.Until(r.ExpiresAt.Add(20 * time.Millisecond)))
		if err := ledger.StoreCopies(ctx, r, receipts); !errors.Is(err, privacy.ErrExpired) {
			t.Fatal("expired copy accepted", err)
		}
		if err := custodian.VerifyAndStore(ctx, r, receipts); !errors.Is(err, privacy.ErrExpired) {
			t.Fatal("expired verification started", err)
		}
		barrier := &fixtureBarrier{fail: true}
		cleaner := privacy.Cleaner{Ledger: ledger, Barrier: barrier, Purger: bound}
		if err := cleaner.Clean(ctx, r.Location); err == nil {
			t.Fatal("unconfirmed writer stop accepted")
		}
		if b, o := charge(t, a); b != r.ReservedBytes() || o != 4 {
			t.Fatal("barrier failure refunded")
		}
		// Explicit test-only lease expiry to retry without a 30-second wall wait.
		if _, err := admin.Exec(ctx, "UPDATE custody_attempt SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", r.Location.AttemptID); err != nil {
			t.Fatal(err)
		}
		barrier.fail = false
		if err := cleaner.Clean(ctx, r.Location); err != nil {
			t.Fatal("cleanup", err)
		}
		rec, err := ledger.Lookup(ctx, r.Location)
		if err != nil || rec.State != artifact.Deleted {
			t.Fatal("not deleted", err)
		}
		if b, o := charge(t, a); b != 0 || o != 0 {
			t.Fatal("verified deletion did not refund once")
		}
		versions, err := s3Admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: aws.String(r.Location.Prefix())})
		if err != nil || len(versions.Versions)+len(versions.DeleteMarkers) != 0 {
			t.Fatal("versions survived")
		}
		uploads, err := s3Admin.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: aws.String(r.Location.Prefix())})
		if err != nil || len(uploads.Uploads) != 0 {
			t.Fatal("multipart survived")
		}
		if _, err = s3Admin.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &other}); err != nil {
			t.Fatal("deleted neighboring attempt")
		}
		if replay, err := ledger.Register(ctx, r); err != nil || replay.State != artifact.Deleted {
			t.Fatal("replay resurrected attempt", err)
		}
		t.Log("real S3: current and noncurrent versions, delete marker and multipart parts removed; neighbor preserved; writer barrier failure kept charge")
	})
	t.Run("stale deletion worker and overdue allocation isolation", func(t *testing.T) {
		_, a, s := setup(t, 2)
		r := newRegistration(a, s)
		r.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(150 * time.Millisecond)
		r.WriteUntil = r.ExpiresAt
		r.DeleteBy = r.ExpiresAt.Add(20 * time.Millisecond)
		if _, err := ledger.Register(ctx, r); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(r.DeleteBy.Add(10 * time.Millisecond)))
		first, err := ledger.ClaimDeletion(ctx, r.Location)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ledger.Register(ctx, newRegistration(a, s)); !errors.Is(err, privacy.ErrCapacity) {
			t.Fatal("overdue allocation admitted", err)
		}
		_, healthy, hs := setup(t, 1)
		if _, err = ledger.Register(ctx, newRegistration(healthy, hs)); err != nil {
			t.Fatal("unaffected allocation blocked", err)
		}
		if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", r.Location.AttemptID); err != nil {
			t.Fatal(err)
		}
		second, err := ledger.ClaimDeletion(ctx, r.Location)
		if err != nil {
			t.Fatal(err)
		}
		if second.Fence <= first.Fence {
			t.Fatal("fence not incremented")
		}
		if err = ledger.FinishDeletion(ctx, first); !errors.Is(err, privacy.ErrFence) {
			t.Fatal("stale worker released charge", err)
		}
		if b, _ := charge(t, a); b != r.ReservedBytes() {
			t.Fatal("stale completion refunded")
		}
		// Trusted completion injection tests only the SQL facet here. The preceding
		// real S3 test covers the Cleaner/physical-absence path.
		if err = ledger.FinishDeletion(ctx, second); err != nil {
			t.Fatal(err)
		}
		if err = ledger.FinishDeletion(ctx, second); err != nil {
			t.Fatal(err)
		}
		if b, o := charge(t, a); b != 0 || o != 0 {
			t.Fatal("duplicate release")
		}
	})
	t.Run("bounded streaming custody (ADR-166)", func(t *testing.T) {
		qualifyStreamingCustody(t, ctx, admin, ledger, store, s3Admin, bucket, charge)
	})
}
