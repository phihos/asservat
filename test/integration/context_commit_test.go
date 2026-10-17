package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func receipt(o objectstore.Object) artifact.CopyReceipt {
	return artifact.CopyReceipt{VersionID: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
}

func TestContextCommitWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned real-service fixtures")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	var f fixture
	if json.Unmarshal(b, &f) != nil || f.Postgres == "" || len(f.Clusters) != 2 {
		t.Fatal("incomplete context/SQL fixture")
	}
	clear(b)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	u, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	addr, tlsConfig := pgTLSBridge(t, u.Host)
	pcfg, err := pgxpool.ParseConfig("postgres://custody_runtime:synthetic-runtime@" + addr + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pcfg.ConnConfig.TLSConfig = tlsConfig
	pcfg.ConnConfig.Fallbacks = nil
	pcfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ledger, err := postgres.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/commit-transit", map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", "commit-transit/keys/evidence", map[string]any{"type": "aes256-gcm96"}, 200)
	tokens := map[string]string{}
	for name, operation := range map[string]string{"commit-writer": "encrypt", "commit-reader": "decrypt"} {
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": `path "commit-transit/` + operation + `/evidence" { capabilities = ["update"] }`}, 204)
		v := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "15m"}, 200)
		tokens[name] = v["auth"].(map[string]any)["client_token"].(string)
	}
	kmsTLS, s3TLS := tlsBridge(t, f.KMS), tlsBridge(t, f.S3)
	sealer, err := kms.NewSealer(kmsTLS.URL, tokens["commit-writer"], "commit-transit", "evidence", kmsTLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kms.NewOpener(kmsTLS.URL, tokens["commit-reader"], "commit-transit", "evidence", kmsTLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	s3Admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &s3TLS.URL, UsePathStyle: true, Credentials: creds, HTTPClient: s3TLS.Client(), RetryMaxAttempts: 1})
	if _, err = s3Admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("context-commit")}); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.New(s3TLS.URL, "us-east-1", "context-commit", creds, s3TLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	for index, cluster := range f.Clusters {
		t.Run(fmt.Sprintf("cluster-%d", index+1), func(t *testing.T) {
			anchor := time.Now().UTC().Truncate(time.Microsecond)
			d := artifact.Digest(sha256.Sum256([]byte("synthetic collector and accepted-plan identity")))
			poolID, allocationID, storeID := custodyID(), custodyID(), custodyID()
			e := artifact.ContextExpectation{
				Registration: artifact.Registration{Location: artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: storeID, AllocationID: allocationID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: anchor, WriteUntil: anchor.Add(5 * time.Second), ExpiresAt: anchor.Add(10 * time.Second), DeleteBy: anchor.Add(40 * time.Second)},
				CaseID:       custodyID(), OccurrenceID: custodyID(), NodeUID: cluster.NodeUID, NodeBootID: cluster.NodeBootID, PodUID: cluster.Pod.UID, Namespace: cluster.Pod.Namespace, NamespaceUID: cluster.Pod.NamespaceUID, WorkloadUID: cluster.WorkloadUID, CollectorVersion: "synthetic-in-process-test", CollectorImageDigest: d, RecipeDigest: d, PlanDigest: d, CaptureUID: custodyID(), ActionID: "context", DataClass: "metadata", PurposeRef: "synthetic-integration", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "synthetic-team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "synthetic-binding", AssignmentID: custodyID(), BasisDigest: d}}, RequestedAgeSeconds: 10, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: "synthetic-retention", Generation: 1, Digest: d}}, TriggeredAt: anchor,
			}
			validUntil := anchor.Add(time.Hour)
			if _, err := admin.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,$3,$4,4)", poolID, storeID, validUntil, e.Registration.ReservedBytes()); err != nil {
				t.Fatal(err)
			}
			if err := ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: allocationID, PoolID: poolID, ScopeID: custodyID(), ServiceClass: "context", PoolRevision: 1, Revision: 1, Bytes: e.Registration.ReservedBytes(), Objects: 4, ValidUntil: validUntil}); err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.Register(ctx, e.Registration); err != nil {
				t.Fatal(err)
			}
			// All copies are registered before the production writer prepares keys.
			bound, err := store.ForCustody(storeID)
			if err != nil {
				t.Fatal(err)
			}
			producer, err := objectstore.NewContextProducer(bound, sealer, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := producer.PrepareContext(ctx, e)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			config, err := clientcmd.BuildConfigFromFlags("", cluster.Config)
			if err != nil {
				t.Fatal(err)
			}
			config = rest.AnonymousClientConfig(config)
			config.BearerToken = cluster.Token
			collector, err := kube.NewContextClient(config)
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now().UTC()
			native, err := collector.Capture(ctx, cluster.Pod)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(native)
			completed := time.Now().UTC()
			copies, err := prepared.StoreContext(ctx, native, started, completed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = prepared.StoreContext(ctx, native, started, completed); err == nil {
				t.Fatal("prepared writer replayed an attempt")
			}
			verifier, err := objectstore.NewContextVerifier(bound, keys)
			if err != nil {
				t.Fatal(err)
			}
			custodian := evidence.ContextCustodian{Ledger: ledger, Verifier: verifier}
			// A self-consistent encrypted manifest must not choose its own audience.
			foreign := e
			foreign.Audience = append([]artifact.AudienceAssignment(nil), e.Audience...)
			foreign.Audience[0].SubjectID = "different-team"
			if err := custodian.VerifyAndStore(ctx, foreign, copies); err == nil {
				t.Fatal("manifest ignored accepted audience")
			}
			rec, err := ledger.Lookup(ctx, e.Registration.Location)
			if err != nil || rec.State != artifact.Reserved {
				t.Fatal("failed verification changed custody", err)
			}
			if err := custodian.VerifyAndStore(ctx, e, copies); err != nil {
				t.Fatal(err)
			}
			if err := custodian.VerifyAndStore(ctx, e, copies); err != nil {
				t.Fatal("receipt replay", err)
			}
			rec, err = ledger.Lookup(ctx, e.Registration.Location)
			if err != nil || rec.State != artifact.StoredUnpublished || rec.Copies != copies {
				t.Fatal("wrong unpublished receipt", err)
			}
			var events int
			var charged int64
			if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM custody_event WHERE attempt_id=$1),(SELECT charged_bytes FROM custody_allocation WHERE id=$2)", e.Registration.Location.AttemptID, allocationID).Scan(&events, &charged); err != nil || events != 2 || charged != e.Registration.ReservedBytes() {
				t.Fatal("duplicate event or released charge", err)
			}
			// The only persisted digests are ciphertext/opaque request identities.
			var nativeHashRows int
			nativeHash := sha256.Sum256(native)
			if err := admin.QueryRow(ctx, "SELECT count(*) FROM custody_copy WHERE ciphertext_sha256=$1", nativeHash[:]).Scan(&nativeHashRows); err != nil || nativeHashRows != 0 {
				t.Fatal("native hash entered SQL")
			}
			nativeReader, err := objectstore.NewContextNativeReader(bound, keys)
			if err != nil {
				t.Fatal(err)
			}
			for _, lease := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(6 * time.Second)} {
				if body, err := nativeReader.ReadContext(ctx, e, copies, lease); err == nil || len(body) != 0 {
					t.Fatal("invalid disclosure lease returned bytes")
				}
			}
			time.Sleep(time.Until(e.Registration.WriteUntil) + 10*time.Millisecond)
			if err := verifier.VerifyContext(ctx, e, copies); err == nil {
				t.Fatal("verification renewed the acquisition window")
			}
			body, err := nativeReader.ReadContext(ctx, e, copies, time.Now().Add(5*time.Second))
			if err != nil || !bytes.Equal(body, native) || sha256.Sum256(body) != nativeHash {
				t.Fatal("native read after acquisition deadline", err)
			}
			clear(body)
			if body, err := nativeReader.ReadContext(ctx, foreign, copies, time.Now().Add(5*time.Second)); err == nil || len(body) != 0 {
				t.Fatal("wrong retained audience returned plaintext")
			}
			cancelled, stop := context.WithCancel(ctx)
			stop()
			if body, err := nativeReader.ReadContext(cancelled, e, copies, time.Now().Add(5*time.Second)); err == nil || len(body) != 0 {
				t.Fatal("cancelled read returned plaintext")
			}
			time.Sleep(time.Until(e.Registration.ExpiresAt) + 10*time.Millisecond)
			if body, err := nativeReader.ReadContext(ctx, e, copies, time.Now().Add(5*time.Second)); err == nil || len(body) != 0 {
				t.Fatal("expired artifact returned plaintext")
			}
			t.Logf("native=%d, encrypted manifest=%d, envelope=%d bytes; real KMS/S3/full native verification; immutable SQL state=%s; audience mismatch rejected", len(native), copies[2].Bytes, copies[3].Bytes, rec.State)
		})
	}
	t.Run("unscheduled-api-context", func(t *testing.T) {
		qualifyAPIContextAcquisition(t, ctx, f, admin, ledger, sealer, keys, store)
	})
}
