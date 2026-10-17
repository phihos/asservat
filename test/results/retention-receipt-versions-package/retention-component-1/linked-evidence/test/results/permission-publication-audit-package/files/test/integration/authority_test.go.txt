package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Synthetic KMS boundary only. Real encrypted objects and PostgreSQL are used;
// this fixture does not qualify production key custody or Kubernetes acceptance.
type authorityTestKeys struct{ a cipher.AEAD }

func (k authorityTestKeys) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	nonce := make([]byte, k.a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return artifact.SealedKey{}, err
	}
	return artifact.SealedKey{Reference: "synthetic-authority", Ciphertext: base64.StdEncoding.EncodeToString(k.a.Seal(nonce, nonce, b, ad))}, nil
}
func (k authorityTestKeys) Open(ctx context.Context, key artifact.SealedKey, ad []byte) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(key.Ciphertext)
	if err != nil || len(b) < k.a.NonceSize() || key.Reference != "synthetic-authority" {
		return nil, artifact.ErrIntegrity
	}
	return k.a.Open(nil, b[:k.a.NonceSize()], b[k.a.NonceSize():], ad)
}
func TestPermissionAuthorityWithRealServices(t *testing.T) {
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
	pc, err := pgxpool.ParseConfig("postgres://authority_runtime:synthetic-authority@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.TLSConfig = tlsConfig
	pc.ConnConfig.Fallbacks = nil
	pc.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err = pool.Exec(ctx, "UPDATE custody_pool SET paused=true"); err == nil {
		t.Fatal("permission role can change custody")
	}
	if _, err = pool.Exec(ctx, "DELETE FROM permission_assignment"); err == nil {
		t.Fatal("permission role can delete history")
	}
	bridge := tlsBridge(t, fixture.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	bucket := "authority-audit"
	if _, err = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	keys := authorityTestKeys{aead}
	objects := &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}
	type setup struct {
		p      *postgres.Permissions
		b      cfg.PermissionBatch
		target authorization.Target
	}
	fresh := func(b cfg.PermissionBatch) cfg.PermissionBatch {
		now := time.Now().UTC().Truncate(time.Microsecond)
		b.RequestID = custodyID()
		b.ObservedAt = now
		b.FreshUntil = now.Add(5 * time.Second)
		return b
	}
	initialReview := func(cluster string, control cfg.NamespaceRef, d artifact.Digest, now time.Time) cfg.BootstrapReview {
		return cfg.BootstrapReview{Resource: cfg.Resource{ClusterID: cluster, Namespace: control.Name, NamespaceUID: control.UID, Kind: "ConfigMap", UID: custodyID(), ResourceVersion: "review-1", SpecDigest: artifact.Digest{9}}, Reviewer: "synthetic-administrator", BindingsDigest: d, ReviewedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	}
	create := func(t *testing.T) setup {
		t.Helper()
		root, epoch, cluster := custodyID(), custodyID(), custodyID()
		p, err := postgres.NewPermissions(ctx, pool, root)
		if err != nil {
			t.Fatal(err)
		}
		trust := artifact.Digest{1}
		if _, err = p.BeginPermissions(ctx, root, epoch, trust); err != nil {
			t.Fatal(err)
		}
		basis := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "v1", SpecDigest: artifact.Digest{2}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: "app", UID: custodyID()}}, Effect: "Allow", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "team-a"}}, Roles: []string{"workload-maintainer"}}
		basis.ScopeDigest = configapp.PermissionScopeDigest(basis)
		b := fresh(cfg.PermissionBatch{RootID: root, Epoch: epoch, TrustDigest: trust, InputDigest: artifact.Digest{3}, Bases: []cfg.PermissionBasis{basis}})
		control := cfg.NamespaceRef{Name: "asservat", UID: "control"}
		review := initialReview(cluster, control, artifact.Digest{8}, b.ObservedAt)
		b.Initial = &cfg.PermissionInitialization{ClusterID: cluster, Control: control, BindingCount: 1, BindingsDigest: review.BindingsDigest, Review: &review}
		return setup{p, b, authorization.Target{ClusterID: cluster, NamespaceUID: basis.Scope.Namespace.UID, WorkloadUID: custodyID(), PodUID: custodyID()}}
	}
	accept := func(t *testing.T, s *setup) {
		t.Helper()
		r, err := s.p.AcceptPermissions(ctx, s.b)
		if err != nil {
			t.Fatal(err)
		}
		s.b.ExpectedSequence = r.Sequence
	}
	flush := func(t *testing.T, p *postgres.Permissions) {
		t.Helper()
		for i := 0; i < 100; i++ {
			rows, err := p.PendingAuthorityAudits(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 {
				return
			}
			if err = (auditapp.AuthorityPublisher{Ledger: p, Objects: objects}).PublishAuthority(ctx); err != nil {
				t.Fatal(err)
			}
		}
		t.Fatal("audit drain exceeded bound")
	}
	projection := func(t *testing.T, s setup) authorization.Projection {
		t.Helper()
		v, err := s.p.Permissions(ctx, s.target)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	next := func(s *setup) {
		s.b = fresh(s.b)
		s.b.Bases[0].Resource.Generation++
		s.b.Bases[0].Resource.ResourceVersion = s.b.RequestID
		s.b.Bases[0].Resource.SpecDigest[0]++
		s.b.InputDigest[0]++
	}
	for _, kind := range []string{"reset", "initial", "assignment"} {
		for _, version := range []string{"", "null"} {
			label := version
			if label == "" {
				label = "empty"
			}
			t.Run("retained-audit-"+kind+"-"+label, func(t *testing.T) {
				s := create(t)
				accept(t, &s)
				flush(t, s.p)
				next(&s)
				s.b.Bases[0].Subjects = []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "new-owner"}}
				deny := s.b.Bases[0]
				deny.Resource.UID = custodyID()
				deny.Effect = "Deny"
				deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
				s.b.Bases = append(s.b.Bases, deny)
				accept(t, &s)
				flush(t, s.p)
				original := projection(t, s)
				if len(original.Allows) != 1 || len(original.Denies) != 1 || !original.DeniesComplete {
					t.Fatal("original audited allow/deny baseline unavailable")
				}
				event := s.b.Epoch
				if kind == "initial" {
					if err := admin.QueryRow(ctx, "SELECT initial_audit_id FROM permission_stream WHERE id=$1", s.b.RootID).Scan(&event); err != nil {
						t.Fatal(err)
					}
				} else if kind == "assignment" {
					if err := admin.QueryRow(ctx, "SELECT a.activation_audit_id FROM permission_assignment a JOIN permission_basis b ON b.stream_id=a.stream_id AND b.basis_key=a.basis_key WHERE a.stream_id=$1 AND a.retired_at IS NULL AND b.effect='Allow'", s.b.RootID).Scan(&event); err != nil {
						t.Fatal(err)
					}
				}
				withHistoricalAuthorityVersion(t, ctx, admin, s.b.RootID, event, version, func() {
					got := projection(t, s)
					if len(got.Allows) != 0 || len(got.Denies) != 1 || !got.DeniesComplete || got.Denies[0].Audience != original.Denies[0].Audience {
						t.Fatal("old receipt enabled access or hid a current deny")
					}
					// A genuine newer source observation cannot repair immutable audit history.
					s.b = fresh(s.b)
					if err := s.p.RefreshPermissions(ctx, s.b); err != nil {
						t.Fatal(err)
					}
					got = projection(t, s)
					if len(got.Allows) != 0 || len(got.Denies) != 1 || !got.DeniesComplete {
						t.Fatal("source refresh repaired old audit authority")
					}
					if !time.Now().Before(s.b.FreshUntil) {
						t.Fatal("audit denial crossed original source interval")
					}
				})
				if got := projection(t, s); len(got.Allows) != 1 || len(got.Denies) != 1 || got.Allows[0].Audience != original.Allows[0].Audience {
					t.Fatal("exact restored authority baseline changed")
				}
				if _, err := pool.Exec(ctx, "SET session_replication_role=replica"); err == nil {
					t.Fatal("runtime can rewrite acknowledged audit history")
				}
			})
		}
	}
	t.Run("foreign-audit-root-disables-allow-without-hiding-deny", func(t *testing.T) {
		s := create(t)
		foreign := create(t)
		accept(t, &s)
		flush(t, s.p)
		next(&s)
		s.b.Bases[0].Subjects = []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "new-owner"}}
		deny := s.b.Bases[0]
		deny.Resource.UID = custodyID()
		deny.Effect = "Deny"
		deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
		s.b.Bases = append(s.b.Bases, deny)
		accept(t, &s)
		flush(t, s.p)
		original := projection(t, s)
		if len(original.Allows) != 1 || len(original.Denies) != 1 || !original.DeniesComplete {
			t.Fatal("original mixed authority unavailable")
		}
		var event string
		if err := admin.QueryRow(ctx, "SELECT a.activation_audit_id FROM permission_assignment a JOIN permission_basis b ON b.stream_id=a.stream_id AND b.basis_key=a.basis_key WHERE a.stream_id=$1 AND a.retired_at IS NULL AND b.effect='Allow'", s.b.RootID).Scan(&event); err != nil {
			t.Fatal(err)
		}
		withHistoricalAuthorityRoot(t, ctx, admin, event, s.b.RootID, foreign.b.RootID, func() {
			got := projection(t, s)
			if len(got.Allows) != 0 || len(got.Denies) != 1 || !got.DeniesComplete || got.Denies[0].Audience != original.Denies[0].Audience {
				t.Fatal("foreign audit enabled access or hid an exact current deny")
			}
			if !time.Now().Before(original.FreshUntil) {
				t.Fatal("foreign audit denial crossed original source interval")
			}
		})
		if restored := projection(t, s); len(restored.Allows) != 1 || len(restored.Denies) != 1 || restored.Allows[0].Audience != original.Allows[0].Audience {
			t.Fatal("exact restored authority scope changed baseline")
		}
	})
	t.Run("bootstrap-requires-exact-review-and-is-durable", func(t *testing.T) {
		s := create(t)
		missing := s.b
		missing.Initial = nil
		if _, err := s.p.AcceptPermissions(ctx, missing); !errors.Is(err, cfg.ErrDenied) {
			t.Fatalf("unreviewed baseline: %v", err)
		}
		wrong := *s.b.Initial
		wrong.BindingsDigest[0]++
		missing.Initial = &wrong
		if _, err := s.p.AcceptPermissions(ctx, missing); !errors.Is(err, cfg.ErrDenied) {
			t.Fatalf("different review: %v", err)
		}
		accept(t, &s)
		pending, err := s.p.PendingAuthorityAudits(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range pending {
			if r.Bootstrap != nil {
				found = true
				if r.Bootstrap.ReviewUID != s.b.Initial.Review.Resource.UID || r.Bootstrap.BindingsDigest != s.b.Initial.BindingsDigest {
					t.Fatal("bootstrap audit lost provenance")
				}
			}
		}
		if !found {
			t.Fatal("missing bootstrap audit")
		}
		flush(t, s.p)
		f, err := s.p.BeginPermissions(ctx, s.b.RootID, s.b.Epoch, s.b.TrustDigest)
		if err != nil || !f.Initialized {
			t.Fatalf("initialization not durable: %v", err)
		}
		if err = s.p.SuspendPermissions(ctx, f); err != nil {
			t.Fatal(err)
		}
		f, err = s.p.BeginPermissions(ctx, s.b.RootID, custodyID(), s.b.TrustDigest)
		if err != nil || !f.Initialized {
			t.Fatalf("ordinary restart lost review: %v", err)
		}
		if err = s.p.SuspendPermissions(ctx, f); err != nil {
			t.Fatal(err)
		}
		trust := s.b.TrustDigest
		trust[0]++
		f, err = s.p.BeginPermissions(ctx, s.b.RootID, custodyID(), trust)
		if err != nil || f.Initialized {
			t.Fatalf("new trust reused old review: %v", err)
		}
	})
	t.Run("bootstrap-audit-cannot-be-skipped-by-out-of-order-publication", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		rows, err := s.p.PendingAuthorityAudits(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ack := func(r audit.AuthorityRecord) {
			t.Helper()
			receipt, e := objects.WriteAuthorityAudit(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			if e = s.p.AcknowledgeAuthorityAudit(ctx, r, receipt); e != nil {
				t.Fatal(e)
			}
		}
		for _, r := range rows {
			if r.Kind == "permission-reset" {
				ack(r)
			}
		}
		next(&s)
		s.b.Bases[0].Subjects[0].ID = "replacement-owner"
		accept(t, &s)
		rows, err = s.p.PendingAuthorityAudits(ctx)
		if err != nil || len(rows) != 2 {
			t.Fatalf("expected initial and later audit: %v", err)
		}
		for _, r := range rows {
			if r.Bootstrap == nil {
				ack(r)
			}
		}
		if len(projection(t, s).Allows) != 0 {
			t.Fatal("new access bypassed unacknowledged bootstrap provenance")
		}
		flush(t, s.p)
		if len(projection(t, s).Allows) != 1 {
			t.Fatal("complete audit did not activate access")
		}
	})
	t.Run("audit-gated-grants-and-encrypted-retry", func(t *testing.T) {
		s := create(t)
		original := s.b
		accept(t, &s)
		if len(projection(t, s).Allows) != 0 {
			t.Fatal("unaudited grant exposed")
		}
		pending, err := s.p.PendingAuthorityAudits(ctx)
		if err != nil || len(pending) != 2 {
			t.Fatalf("pending audit %v", err)
		}
		for _, r := range pending {
			receipt, err := objects.WriteAuthorityAudit(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			again, err := objects.WriteAuthorityAudit(ctx, r)
			if err != nil || again != receipt {
				t.Fatalf("conditional audit retry %v", err)
			}
			o, err := s3admin.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &receipt.Key})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(o.Body)
			o.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte("team-a")) || bytes.Contains(body, []byte("workload-maintainer")) {
				t.Fatal("plaintext assignment stored")
			}
			changed := r
			changed.CreatedAt = changed.CreatedAt.Add(time.Second)
			if _, err = objects.WriteAuthorityAudit(ctx, changed); err == nil {
				t.Fatal("different record accepted at same key")
			}
			if err = s.p.AcknowledgeAuthorityAudit(ctx, r, receipt); err != nil {
				t.Fatal(err)
			}
			if err = s.p.AcknowledgeAuthorityAudit(ctx, r, receipt); err != nil {
				t.Fatal(err)
			}
			receipt.SHA256[0] ^= 1
			if err = s.p.AcknowledgeAuthorityAudit(ctx, r, receipt); !errors.Is(err, cfg.ErrChanged) {
				t.Fatalf("changed receipt %v", err)
			}
		}
		before := projection(t, s)
		if len(before.Allows) != 1 {
			t.Fatal("audited grant missing")
		}
		replay, err := s.p.AcceptPermissions(ctx, original)
		if err != nil || replay.Sequence != 1 {
			t.Fatalf("idempotent acceptance %v", err)
		}
		s.b = fresh(s.b)
		if err = s.p.RefreshPermissions(ctx, s.b); err != nil {
			t.Fatal(err)
		}
		after := projection(t, s)
		if before.Allows[0].Audience != after.Allows[0].Audience || after.Revision.Generation != 1 {
			t.Fatal("heartbeat changed assignment")
		}
		var count int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM authority_audit WHERE stream_id=$1", s.b.RootID).Scan(&count); err != nil || count != 2 {
			t.Fatal("heartbeat appended audit")
		}
	})
	t.Run("ownership-A-B-A-does-not-resurrect", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		flush(t, s.p)
		old := projection(t, s).Allows[0].Audience
		next(&s)
		s.b.Bases[0].Subjects[0].ID = "team-b"
		accept(t, &s)
		if len(projection(t, s).Allows) != 0 {
			t.Fatal("old owner survived or unaudited owner active")
		}
		flush(t, s.p)
		next(&s)
		s.b.Bases[0].Subjects[0].ID = "team-a"
		accept(t, &s)
		flush(t, s.p)
		now := projection(t, s).Allows[0].Audience
		if old.AssignmentID == now.AssignmentID {
			t.Fatal("old audience resurrected")
		}
	})
	t.Run("journal-to-SQL-preserves-metadata-and-retires-owner-cycles", func(t *testing.T) {
		s := create(t)
		basis := s.b.Bases[0]
		basis.Resource.ClusterID = s.target.ClusterID
		basis.Resource.Namespace = "asservat"
		basis.Resource.NamespaceUID = "control"
		basis.Resource.Name = "owners"
		binding := cfg.Binding{Resource: basis.Resource, Scope: basis.Scope, Effect: basis.Effect, Subjects: basis.Subjects, Roles: basis.Roles}
		now := time.Now().UTC().Truncate(time.Microsecond)
		snapshot := cfg.Snapshot{ClusterID: s.target.ClusterID, ControlNamespace: cfg.NamespaceRef{Name: "asservat", UID: "control"}, BindingResourceVersion: "baseline", Bindings: []cfg.Binding{binding}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		journal, err := configapp.NewBindingJournal(snapshot, now)
		if err != nil {
			t.Fatal(err)
		}
		if err = journal.SetInitialReview(initialReview(snapshot.ClusterID, snapshot.ControlNamespace, configapp.InitialBindingDigest(snapshot), now), now); err != nil {
			t.Fatal(err)
		}
		fence := cfg.PermissionFence{RootID: s.b.RootID, Epoch: s.b.Epoch, TrustDigest: s.b.TrustDigest}
		commit := func() {
			t.Helper()
			batch, err := journal.Prepare(fence, custodyID(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := s.p.AcceptPermissions(ctx, batch)
			if err != nil {
				t.Fatal(err)
			}
			if err = journal.Accepted(accepted); err != nil {
				t.Fatal(err)
			}
			fence = accepted.PermissionFence
			flush(t, s.p)
		}
		commit()
		original := projection(t, s).Allows[0].Audience
		binding.Resource.ResourceVersion = "metadata-change"
		if err = journal.Apply(cfg.BindingEvent{Type: "MODIFIED", ResourceVersion: binding.Resource.ResourceVersion, Binding: &binding}); err != nil {
			t.Fatal(err)
		}
		commit()
		if projection(t, s).Allows[0].Audience != original {
			t.Fatal("metadata-only transition replaced audience")
		}
		for _, team := range []string{"team-b", "team-a"} {
			binding.Resource.ResourceVersion = team
			binding.Resource.Generation++
			binding.Resource.SpecDigest[0]++
			binding.Subjects = []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: team}}
			if err = journal.Apply(cfg.BindingEvent{Type: "MODIFIED", ResourceVersion: team, Binding: &binding}); err != nil {
				t.Fatal(err)
			}
			commit()
		}
		if projection(t, s).Allows[0].Audience.AssignmentID == original.AssignmentID {
			t.Fatal("journal restored original owner assignment")
		}
	})

	t.Run("generation-gap-invalidates-even-identical-spec", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		flush(t, s.p)
		old := projection(t, s).Allows[0].Audience
		s.b = fresh(s.b)
		s.b.Bases[0].Resource.Generation += 2
		accept(t, &s)
		flush(t, s.p)
		if projection(t, s).Allows[0].Audience.AssignmentID == old.AssignmentID {
			t.Fatal("missed history preserved")
		}
	})
	t.Run("namespace-observation-is-separate-from-source-version", func(t *testing.T) {
		s := create(t)
		s.b.Bases[0].Resource.Kind = "PermissionSource"
		s.b.Bases[0].ObservationVersion = "namespace-v1"
		s.b.Bases[0].ScopeDigest = configapp.PermissionScopeDigest(s.b.Bases[0])
		accept(t, &s)
		flush(t, s.p)
		old := projection(t, s).Allows[0].Audience
		s.b = fresh(s.b)
		s.b.Bases[0].ObservationVersion = "namespace-v9"
		accept(t, &s)
		flush(t, s.p)
		if projection(t, s).Allows[0].Audience.AssignmentID == old.AssignmentID {
			t.Fatal("namespace relist treated as continuous history")
		}
	})
	t.Run("scope-change-and-delete-retire-without-audit", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		flush(t, s.p)
		next(&s)
		s.b.Bases[0].Scope.Workloads = []cfg.WorkloadRef{{Kind: "Deployment", Name: "different", UID: custodyID()}}
		s.b.Bases[0].ScopeDigest = configapp.PermissionScopeDigest(s.b.Bases[0])
		accept(t, &s)
		if len(projection(t, s).Allows) != 0 {
			t.Fatal("scope change retained old access")
		}
		s.b = fresh(s.b)
		s.b.Bases = nil
		accept(t, &s)
		if len(projection(t, s).Allows) != 0 {
			t.Fatal("delete retained access")
		}
	})
	t.Run("explicit-deny-precedes-audit", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		flush(t, s.p)
		deny := s.b.Bases[0]
		deny.Resource.UID = custodyID()
		deny.Effect = "Deny"
		deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
		s.b = fresh(s.b)
		s.b.Bases = append(s.b.Bases, deny)
		accept(t, &s)
		p := projection(t, s)
		if len(p.Denies) != 1 || len(p.Allows) != 1 {
			t.Fatal("deny hidden behind audit")
		}
	})
	t.Run("competing-reconcilers-and-restart", func(t *testing.T) {
		s := create(t)
		if _, err := s.p.BeginPermissions(ctx, s.b.RootID, custodyID(), s.b.TrustDigest); !errors.Is(err, cfg.ErrChanged) {
			t.Fatal("live leader stolen")
		}
		first := s.b
		second := s.b
		second.RequestID = custodyID()
		var wg sync.WaitGroup
		wg.Add(2)
		results := make(chan error, 2)
		for _, b := range []cfg.PermissionBatch{first, second} {
			go func() { defer wg.Done(); _, err := s.p.AcceptPermissions(ctx, b); results <- err }()
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if !errors.Is(err, cfg.ErrChanged) {
				t.Fatal(err)
			}
		}
		if success != 1 {
			t.Fatal("sequence did not fence competing accepts")
		}
		flush(t, s.p)
		old := projection(t, s).Allows[0].Audience
		if _, err = admin.Exec(ctx, "UPDATE permission_stream SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", s.b.RootID); err != nil {
			t.Fatal(err)
		}
		oldEpoch := s.b.Epoch
		s.b.Epoch = custodyID()
		if _, err = s.p.BeginPermissions(ctx, s.b.RootID, s.b.Epoch, s.b.TrustDigest); err != nil {
			t.Fatal(err)
		}
		if _, err = s.p.RenewPermissions(ctx, cfg.PermissionFence{RootID: s.b.RootID, Epoch: oldEpoch, TrustDigest: s.b.TrustDigest}); !errors.Is(err, cfg.ErrChanged) {
			t.Fatal("old leader renewed")
		}
		s.b.ExpectedSequence = 0
		s.b = fresh(s.b)
		accept(t, &s)
		flush(t, s.p)
		if projection(t, s).Allows[0].Audience.AssignmentID != old.AssignmentID {
			t.Fatal("routine restart discarded exact unchanged observation")
		}
		s.b = fresh(s.b)
		s.b.Bases[0].Resource.ResourceVersion = "changed-during-gap"
		accept(t, &s)
		flush(t, s.p)
		if projection(t, s).Allows[0].Audience.AssignmentID == old.AssignmentID {
			t.Fatal("changed version restored uncertain history")
		}
	})
	t.Run("expiry-after-blocking-lock", func(t *testing.T) {
		s := create(t)
		s.b.FreshUntil = s.b.ObservedAt.Add(150 * time.Millisecond)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.b.RootID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := s.p.AcceptPermissions(ctx, s.b); done <- err }()
		time.Sleep(250 * time.Millisecond)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("expired observation accepted after lock")
		}
		var count int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM permission_assignment WHERE stream_id=$1", s.b.RootID).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired transaction left authority")
		}
	})
}
