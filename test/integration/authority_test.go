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
	"slices"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
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
	// ADR-237: the impact preview reads every workload cell of the affected
	// namespace from the same accepted projection, and the real evaluator
	// turns a removed allow into Deny and a proposed deny into ExplicitDeny.
	t.Run("permission-impact-preview", func(t *testing.T) {
		s := create(t)
		named := custodyID()
		s.b.Bases[0].Scope.Workloads = []cfg.WorkloadRef{{Kind: "Deployment", Name: "api", UID: named}}
		s.b.Bases[0].ScopeDigest = configapp.PermissionScopeDigest(s.b.Bases[0])
		accept(t, &s)
		flush(t, s.p)
		next(&s)
		wide := s.b.Bases[0]
		wide.Resource.UID, wide.Scope.Workloads = custodyID(), nil
		wide.ScopeDigest = configapp.PermissionScopeDigest(wide)
		s.b.Bases = append(s.b.Bases, wide)
		accept(t, &s)
		flush(t, s.p)
		ns := cfg.PreviewNamespace{ClusterID: s.target.ClusterID, NamespaceUID: wide.Scope.Namespace.UID}
		proposed := custodyID()
		snap, err := s.p.PreviewProjections(ctx, cfg.PreviewRead{Workloads: map[cfg.PreviewNamespace][]string{ns: {proposed}}, Bases: []cfg.PreviewBasis{{Kind: "AccessBinding", UID: wide.Resource.UID}, {Kind: "AccessBinding", UID: "absent"}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Cells) != 3 || len(snap.Unmatched) != 1 || snap.Unmatched[0].UID != "absent" {
			t.Fatalf("cells %d unmatched %+v", len(snap.Cells), snap.Unmatched)
		}
		// A delegated previewer's read (Allowed = their envelope namespaces)
		// does not match an object in another namespace: it is reported
		// Unmatched like a nonexistent UID and its namespace is not read.
		elsewhere := cfg.PreviewNamespace{ClusterID: s.target.ClusterID, NamespaceUID: "envelope-namespace"}
		limited, err := s.p.PreviewProjections(ctx, cfg.PreviewRead{Namespaces: []cfg.PreviewNamespace{elsewhere}, Allowed: []cfg.PreviewNamespace{elsewhere}, Bases: []cfg.PreviewBasis{{Kind: "AccessBinding", UID: wide.Resource.UID}, {Kind: "AccessBinding", UID: "absent"}}})
		if err != nil || len(limited.Unmatched) != 2 || len(limited.Cells) != 1 || limited.Cells[0].Target.NamespaceUID != elsewhere.NamespaceUID {
			t.Fatalf("envelope read: %v %+v", err, limited)
		}
		allows := map[string]int{}
		for _, c := range snap.Cells {
			if c.Unavailable != "" || c.Projection.Target != c.Target {
				t.Fatalf("cell %+v", c)
			}
			allows[c.Target.WorkloadUID] = len(c.Projection.Allows)
		}
		if allows[named] != 2 || allows[proposed] != 1 || allows[cfg.OtherWorkloads] != 1 {
			t.Fatalf("allows per cell %v", allows)
		}
		changes, _, err := cfg.PreviewChanges([]cfg.AccessChange{{Action: "delete", Kind: "AccessBinding", UID: wide.Resource.UID}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		policy := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
		got, err := cfg.PreviewAccess(changes, snap, []string{s.target.ClusterID}, nil, policy, time.Now())
		// Two cells (the proposal-named workload and all other workloads)
		// lose all three operations; the workload the narrowed binding names
		// keeps them.
		if err != nil || !got.Complete() || got.DeltasTotal != 6 {
			t.Fatalf("%v %+v", err, got)
		}
		for _, d := range got.Deltas {
			if d.Target.WorkloadUID == named || d.Before != authorization.Allow || d.After != authorization.Deny || d.AfterUnmet != authorization.UnmetNoMatchingAllow {
				t.Fatalf("only workloads without the narrowed binding lose access: %+v", d)
			}
		}
	})
	// ADR-237: a worst-case preview reads 1,000 cells (992 workloads named by
	// 16 current bindings, 7 named only by the proposal, all other workloads)
	// in one transaction and evaluates them within the five-second request.
	t.Run("permission-impact-preview-1000-targets", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		flush(t, s.p)
		next(&s)
		ns := s.b.Bases[0].Scope.Namespace
		for range 16 {
			b := s.b.Bases[0]
			b.Resource.UID = custodyID()
			b.Scope.Workloads = nil
			for range 62 {
				b.Scope.Workloads = append(b.Scope.Workloads, cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: custodyID()})
			}
			b.ScopeDigest = configapp.PermissionScopeDigest(b)
			s.b.Bases = append(s.b.Bases, b)
		}
		accept(t, &s)
		flush(t, s.p)
		key := cfg.PreviewNamespace{ClusterID: s.target.ClusterID, NamespaceUID: ns.UID}
		var proposed []cfg.WorkloadRef
		for range 7 {
			proposed = append(proposed, cfg.WorkloadRef{Kind: "Deployment", Name: "new", UID: custodyID()})
		}
		binding := cfg.Binding{Resource: cfg.Resource{SpecDigest: artifact.Digest{4}}, Effect: "Deny", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "team-a"}}, Roles: []string{"workload-maintainer"},
			Scope: cfg.Scope{ClusterID: s.target.ClusterID, Namespace: ns, Workloads: proposed}}
		changes, read, err := cfg.PreviewChanges([]cfg.AccessChange{{Action: "create", Kind: "AccessBinding", Binding: binding}, {Action: "delete", Kind: "AccessBinding", UID: s.b.Bases[0].Resource.UID}}, nil)
		if err != nil || read.Namespaces[0] != key {
			t.Fatal(err)
		}
		started := time.Now()
		snap, err := s.p.PreviewProjections(ctx, read)
		readTime := time.Since(started)
		if err != nil || len(snap.Cells) != cfg.MaxPreviewTargets {
			t.Fatalf("%v cells=%d", err, len(snap.Cells))
		}
		policy := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
		got, err := cfg.PreviewAccess(changes, snap, []string{s.target.ClusterID}, nil, policy, time.Now())
		total := time.Since(started)
		if err != nil || !got.Complete() || got.Targets != cfg.MaxPreviewTargets || got.DeltasTotal == 0 {
			t.Fatalf("%v %+v", err, got.Targets)
		}
		t.Logf("ADR-237 worst case: %d cells read in %v, read+evaluate %v, %d decision changes", len(snap.Cells), readTime, total, got.DeltasTotal)
		if total > 4*time.Second {
			t.Fatalf("worst-case preview took %v; it must fit the five-second request", total)
		}
	})
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
			batch, err := journal.Prepare(fence, custodyID(), time.Now().UTC(), configapp.Inheritance{})
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
	// ADR-242: inherited assignments keep their identity only while the
	// namespace version is unchanged or the watch was continuous; an
	// unavailable source keeps them without granting; removal retires and a
	// re-grant mints a new identity; an explicit deny still wins; the
	// accepted namespace observation is recorded and previewed.
	t.Run("inherited-assignments-continuity-unavailability-and-preview", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		flush(t, s.p)
		binding := s.b.Bases[0]
		namespace := binding.Scope.Namespace
		issuer := "https://id.example.test"
		source := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "PermissionSource", UID: custodyID(), Generation: 1, ResourceVersion: "source-1", SpecDigest: artifact.Digest{4}}, Scope: cfg.Scope{ClusterID: s.target.ClusterID, Namespace: namespace},
			Effect: "Allow", Subjects: []cfg.Subject{{Kind: "Group", Issuer: issuer, ID: "team-s"}}, Roles: []string{"evidence-reader"}, ObservationVersion: "ns-1"}
		source.ScopeDigest = configapp.PermissionScopeDigest(source)
		observation := &cfg.NamespaceObservation{ClusterID: s.target.ClusterID, Keys: cfg.NamespaceKeys{Labels: []string{"managed"}, Annotations: []string{"owner"}},
			Namespaces: []cfg.ObservedNamespace{{Name: namespace.Name, UID: namespace.UID, Labels: map[string]string{"managed": configapp.ValueDigest("true")}, Annotations: map[string]string{"owner": configapp.ValueDigest("payments")}}}}
		step := func(t *testing.T, bases []cfg.PermissionBasis, unavailable []string, all bool) {
			t.Helper()
			s.b = fresh(s.b)
			s.b.Bases, s.b.UnavailableSources, s.b.SourcesUnavailable, s.b.Namespaces = bases, unavailable, all, observation
			s.b.InputDigest[1]++
			accept(t, &s)
			flush(t, s.p)
		}
		inherited := func(t *testing.T) string {
			t.Helper()
			for _, a := range projection(t, s).Allows {
				if a.Audience.BasisKind == "PermissionSource" && a.Audience.SubjectID == "team-s" {
					return a.Audience.AssignmentID
				}
			}
			return ""
		}
		current := func(t *testing.T, id string) bool {
			t.Helper()
			var n int
			if err := admin.QueryRow(ctx, "SELECT count(*) FROM permission_assignment WHERE id=$1 AND retired_at IS NULL", id).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n == 1
		}
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		first := inherited(t)
		if first == "" {
			t.Fatal("inherited allow not granted")
		}
		var record []byte
		if err := admin.QueryRow(ctx, "SELECT record FROM authority_audit WHERE id=$1", s.b.RequestID).Scan(&record); err != nil {
			t.Fatal(err)
		}
		var event audit.AuthorityRecord
		if json.Unmarshal(record, &event) != nil || event.Namespaces == nil || len(event.Namespaces.Namespaces) != 1 || bytes.Contains(record, []byte(`"payments"`)) {
			t.Fatalf("namespace observation not recorded minimized: %s", record)
		}
		// A complete relist with unchanged versions, and a source write that
		// only changes its resourceVersion, keep the identity.
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		source.Resource.ResourceVersion = "source-2"
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		if inherited(t) != first {
			t.Fatal("unchanged inheritance re-minted its assignment")
		}
		// Unavailable: kept but never granted, alone or with every source.
		step(t, []cfg.PermissionBasis{binding}, []string{source.Resource.UID}, false)
		if inherited(t) != "" || !current(t, first) || len(projection(t, s).Allows) != 1 {
			t.Fatal("unavailable source granted or lost its assignment")
		}
		step(t, []cfg.PermissionBasis{binding}, nil, true)
		if inherited(t) != "" || !current(t, first) {
			t.Fatal("unreadable source list granted or lost the assignment")
		}
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		if inherited(t) != first {
			t.Fatal("unchanged namespace after an outage re-minted the assignment")
		}
		// A namespace version change without continuity retires; with a
		// continuous watch it is kept.
		source.ObservationVersion = "ns-2"
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		second := inherited(t)
		if second == "" || second == first || current(t, first) {
			t.Fatal("relist after a gap claimed continuity")
		}
		source.ObservationVersion, source.Continuous = "ns-3", true
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		if inherited(t) != second {
			t.Fatal("continuous namespace watch re-minted the assignment")
		}
		// An explicit deny of the same group overrides the inherited allow.
		deny := binding
		deny.Resource.UID, deny.Effect = custodyID(), "Deny"
		deny.Subjects = []cfg.Subject{{Kind: "Group", Issuer: issuer, ID: "team-s"}}
		deny.Roles = []string{"evidence-reader"}
		deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
		step(t, []cfg.PermissionBasis{binding, source, deny}, nil, false)
		now := time.Now()
		member := identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: "member", ClientID: "console", Kind: identity.Human}, Groups: []string{"team-s"}, Scopes: []string{"evidence:read"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
		if r := authorization.ScopeEligibility(member, projection(t, s), authorization.ReadApproved, s.target, now); r.Eligible || r.Reason != "ExplicitDeny" {
			t.Fatalf("inherited allow overrode an explicit deny: %+v", r)
		}
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		if r := authorization.ScopeEligibility(member, projection(t, s), authorization.ReadApproved, s.target, time.Now()); !r.Eligible {
			t.Fatalf("inherited allow not effective: %+v", r)
		}
		// Removal retires; a re-grant mints a new identity.
		step(t, []cfg.PermissionBasis{binding}, nil, false)
		if inherited(t) != "" || current(t, second) {
			t.Fatal("removed inheritance kept granting")
		}
		source.Continuous = false
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		third := inherited(t)
		if third == "" || third == second || third == first {
			t.Fatal("re-grant restored a retired assignment")
		}
		// Two spec generations at once may hide A -> B -> A.
		source.Resource.Generation += 2
		step(t, []cfg.PermissionBasis{binding, source}, nil, false)
		if id := inherited(t); id == "" || id == third {
			t.Fatal("generation gap preserved the assignment")
		}
		// The preview evaluates a proposed source against this observation.
		spec := cfg.Source{Resource: cfg.Resource{SpecDigest: artifact.Digest{6}}, Enabled: true, Type: "namespaceMetadata", ClusterID: s.target.ClusterID, Role: "evidence-reader", NamespaceSelector: map[string]string{"managed": "true"},
			MaxDecisionAge: 30 * time.Second, MaxNamespaces: 10, Protection: cfg.Protection{Mode: "administratorManaged", ReviewRef: "review"},
			Mapping: cfg.Mapping{Field: "annotation", Key: "owner", Mode: "valueMap", Issuer: issuer, Values: map[string][]string{"payments": {"team-p"}}}}
		unobserved := spec
		unobserved.Mapping.Key = "team"
		changes, read, err := cfg.PreviewChanges([]cfg.AccessChange{{Action: "create", Kind: "PermissionSource", Source: spec}, {Action: "create", Kind: "PermissionSource", Source: unobserved}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := s.p.PreviewProjections(ctx, read)
		if err != nil || len(snap.Sources) != 2 || len(snap.Sources[0].Grants) != 1 || snap.Sources[1].Unevaluated != cfg.MetadataNotObserved {
			t.Fatalf("source preview read: %v %+v", err, snap.Sources)
		}
		got, err := cfg.PreviewAccess(changes, snap, []string{s.target.ClusterID}, nil, identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, time.Now())
		if err != nil || got.Complete() || len(got.NotEvaluated) != 1 || got.DeltasTotal != 2 {
			t.Fatalf("source preview: %v %+v", err, got)
		}
		for _, d := range got.Deltas {
			if d.Subject.ID != "team-p" || d.Before != authorization.Deny || d.After != authorization.Allow || d.Target.NamespaceUID != namespace.UID || d.Target.WorkloadUID != cfg.OtherWorkloads {
				t.Fatalf("source preview delta %+v", d)
			}
		}
	})
	// ADR-245: decision-time reviews. The connector is synthetic here (the
	// permission-integration subtest submits real SubjectAccessReviews); the
	// SQL store, projection, evaluator and acceptance are the product's.
	t.Run("decision-time-reviews-mint-expire-deny-and-retire", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		flush(t, s.p)
		binding := s.b.Bases[0]
		issuer := "https://id.example.test"
		spec := cfg.Source{Resource: cfg.Resource{Kind: "PermissionSource", UID: custodyID(), ResourceVersion: "exec-1", Generation: 1, SpecDigest: artifact.Digest{40}}, Enabled: true, Type: cfg.SourceKubernetesExec,
			ClusterID: s.target.ClusterID, Role: "workload-maintainer", NamespaceSelector: map[string]string{"managed": "true"}, MaxDecisionAge: 30 * time.Second, MaxNamespaces: 10,
			IdentityMappingRef: "company", AdmissionParity: cfg.AdmissionParity{Mode: "noAdditionalRestrictions", ReviewRef: "synthetic-attestation"}}
		source, reason := cfg.ReviewSourceFor(spec)
		if reason != "" {
			t.Fatal(reason)
		}
		step := func(t *testing.T, bases []cfg.PermissionBasis, reviews []cfg.ReviewSource, unavailable bool) {
			t.Helper()
			s.b = fresh(s.b)
			s.b.Bases, s.b.ReviewSources, s.b.SourcesUnavailable, s.b.UnavailableSources, s.b.Namespaces = bases, reviews, unavailable, nil, nil
			s.b.InputDigest[2]++
			accept(t, &s)
			flush(t, s.p)
		}
		step(t, []cfg.PermissionBasis{binding}, []cfg.ReviewSource{source}, false)
		store, err := postgres.NewAccessReviews(ctx, pool, s.b.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := store.ReviewSources(ctx, s.target.ClusterID); err != nil || len(got) != 1 || !got[0].SameAuthority(source) || got[0].Resource != source.Resource {
			t.Fatalf("current review sources %v %+v", err, got)
		}
		request := targets.Request{ClusterID: s.target.ClusterID, Namespace: binding.Scope.Namespace, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: s.target.WorkloadUID}, PodName: "api-1", PodUID: s.target.PodUID}
		alice := identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: "alice", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read", "evidence:capture"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}}
		bob := alice
		bob.Principal.Subject = "bob"
		record := func(t *testing.T, who identity.Identity, src cfg.ReviewSource, allowed bool) error {
			t.Helper()
			return store.RecordReview(ctx, authapp.ReviewDecision{Source: src, Principal: who.Principal, Target: request, Allowed: allowed, DecidedAt: time.Now()})
		}
		reviewed := func(t *testing.T, who identity.Identity) string {
			t.Helper()
			for _, a := range projection(t, s).Allows {
				if a.Reviewed && a.Audience.SubjectID == who.Principal.Subject {
					return a.Audience.AssignmentID
				}
			}
			return ""
		}
		eligible := func(t *testing.T, who identity.Identity) authorization.CaptureEligibility {
			t.Helper()
			now := time.Now()
			who.VerifiedAt, who.ValidUntil = now, now.Add(30*time.Second)
			return authorization.ContextEligibility(who, projection(t, s), s.target, now)
		}
		if reviewed(t, alice) != "" || eligible(t, alice).Eligible {
			t.Fatal("decision-time source granted before any review")
		}
		// A refusal of a principal with no assignment mints nothing.
		if err = record(t, alice, source, false); err != nil {
			t.Fatal(err)
		}
		if n := 0; admin.QueryRow(ctx, "SELECT count(*) FROM permission_review_assignment WHERE stream_id=$1", s.b.RootID).Scan(&n) != nil || n != 0 {
			t.Fatal("refusal minted an assignment", n)
		}
		if err = record(t, alice, source, true); err != nil {
			t.Fatal(err)
		}
		first := reviewed(t, alice)
		c := eligible(t, alice)
		if first == "" || !c.Eligible || !slices.ContainsFunc(c.DefaultAudience, func(a artifact.AudienceAssignment) bool {
			return a.AssignmentID == first && a.Kind == "User" && a.BasisUID == source.Resource.UID
		}) {
			t.Fatalf("allowed review did not grant its principal: %q %+v", first, c)
		}
		if err = record(t, bob, source, true); err != nil {
			t.Fatal(err)
		}
		if a := eligible(t, alice); slices.ContainsFunc(a.DefaultAudience, func(x artifact.AudienceAssignment) bool { return x.SubjectID == "bob" }) {
			t.Fatal("another principal's review joined the capturing principal's audience")
		}
		// A fresh allowed review keeps the identity; recorded names are kept.
		if err = record(t, alice, source, true); err != nil || reviewed(t, alice) != first {
			t.Fatal("repeated review re-minted the assignment", err)
		}
		if got, err := store.RecordedReviews(ctx, alice.Principal, s.target); err != nil || len(got) != 1 || got[0].Target != request || got[0].SourceUID != source.Resource.UID {
			t.Fatalf("recorded review %v %+v", err, got)
		}
		// A refusal (RBAC removed, SAR unavailable) ends the decision at once.
		if err = record(t, alice, source, false); err != nil || reviewed(t, alice) != "" || eligible(t, alice).Eligible {
			t.Fatal("refusal left the decision current", err)
		}
		if err = record(t, alice, source, true); err != nil || reviewed(t, alice) != first {
			t.Fatal("re-allowed review lost the assignment of an unchanged source", err)
		}
		// An explicit deny of the user wins over the fresh review.
		deny := binding
		deny.Resource.UID, deny.Effect = custodyID(), "Deny"
		deny.Subjects = []cfg.Subject{{Kind: "User", Issuer: issuer, ID: "alice"}}
		deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
		step(t, []cfg.PermissionBasis{binding, deny}, []cfg.ReviewSource{source}, false)
		if r := eligible(t, alice); r.Eligible || r.Reason != "ExplicitDeny" {
			t.Fatalf("deny did not win: %+v", r)
		}
		step(t, []cfg.PermissionBasis{binding}, []cfg.ReviewSource{source}, false)
		if err = record(t, alice, source, true); err != nil || reviewed(t, alice) != first {
			t.Fatal("decision after deny removal", err)
		}
		// An unreadable source list keeps the assignment but grants nothing.
		step(t, []cfg.PermissionBasis{binding}, nil, true)
		if reviewed(t, alice) != "" {
			t.Fatal("unavailable source list still granted a review")
		}
		if err = record(t, alice, source, true); !errors.Is(err, cfg.ErrChanged) {
			t.Fatal("review recorded against a source that is not current", err)
		}
		// One spec transition with the same authority (a selector edit) keeps
		// the assignment and its original basis digest.
		spec.Resource.Generation, spec.Resource.SpecDigest, spec.NamespaceSelector = 2, artifact.Digest{41}, map[string]string{"managed": "yes"}
		edited, _ := cfg.ReviewSourceFor(spec)
		step(t, []cfg.PermissionBasis{binding}, []cfg.ReviewSource{edited}, false)
		if err = record(t, alice, edited, true); err != nil || reviewed(t, alice) != first {
			t.Fatal("equivalent source edit re-minted the assignment", err)
		}
		// Removal retires every assignment of the source; a re-added source
		// mints new identities.
		step(t, []cfg.PermissionBasis{binding}, nil, false)
		var retired int
		if admin.QueryRow(ctx, "SELECT count(*) FROM permission_review_assignment WHERE stream_id=$1 AND retired_at IS NOT NULL", s.b.RootID).Scan(&retired) != nil || retired != 2 {
			t.Fatal("removed source kept assignments", retired)
		}
		var event audit.AuthorityRecord
		var raw []byte
		if admin.QueryRow(ctx, "SELECT record FROM authority_audit WHERE id=$1", s.b.RequestID).Scan(&raw) != nil || json.Unmarshal(raw, &event) != nil || len(event.ReviewRetirements) != 1 || event.ReviewRetirements[0].Retired != 2 || bytes.Contains(raw, []byte(`"alice"`)) {
			t.Fatalf("retirement audit %s", raw)
		}
		step(t, []cfg.PermissionBasis{binding}, []cfg.ReviewSource{edited}, false)
		if err = record(t, alice, edited, true); err != nil {
			t.Fatal(err)
		}
		if again := reviewed(t, alice); again == "" || again == first {
			t.Fatal("re-added source restored a retired assignment")
		}
		// A generation jump also retires.
		spec.Resource.Generation, spec.Resource.SpecDigest = 4, artifact.Digest{42}
		jumped, _ := cfg.ReviewSourceFor(spec)
		before := reviewed(t, alice)
		step(t, []cfg.PermissionBasis{binding}, []cfg.ReviewSource{jumped}, false)
		if err = record(t, alice, jumped, true); err != nil || reviewed(t, alice) == before {
			t.Fatal("generation jump kept the assignment", err)
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
