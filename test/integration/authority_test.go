package integration

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgconn"
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

// Delay each client write so a serial document query per cluster exceeds the
// production reconciler's three-second refresh window.
type delayedPermissionConn struct{ net.Conn }

func (c delayedPermissionConn) Write(b []byte) (int, error) {
	time.Sleep(20 * time.Millisecond)
	return c.Conn.Write(b)
}

type remoteBindingHubFixture struct {
	cluster  string
	bindings []cfg.Binding
}

func (f remoteBindingHubFixture) PermissionSnapshot(context.Context) (cfg.Snapshot, error) {
	now := time.Now()
	return cfg.Snapshot{ClusterID: f.cluster, ControlNamespace: cfg.NamespaceRef{Name: "asservat", UID: f.cluster}, BindingResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second), SourcesComplete: true, Bindings: f.bindings}, nil
}

func (f remoteBindingHubFixture) ClusterAccessBindings(ctx context.Context) (cfg.Snapshot, error) {
	return f.PermissionSnapshot(ctx)
}
func (remoteBindingHubFixture) PermissionTrust(context.Context) (configapp.PermissionTrust, error) {
	now := time.Now()
	return configapp.PermissionTrust{Digest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

var errBaselineAccepted = errors.New("test stops at watch after initial acceptance")

func (f remoteBindingHubFixture) WatchBindings(context.Context, string) (configapp.BindingWatch, error) {
	return stopAfterBaseline{}, nil
}

type stopAfterBaseline struct{}

func (stopAfterBaseline) Close() {}
func (stopAfterBaseline) Next(context.Context) (cfg.BindingEvent, error) {
	return cfg.BindingEvent{}, errBaselineAccepted
}

type observedPermissionWriter struct {
	*postgres.Permissions
	accepted  chan cfg.PermissionAcceptance
	renewed   chan cfg.PermissionFence
	refreshed chan struct{}
}

func (w *observedPermissionWriter) AcceptPermissions(ctx context.Context, b cfg.PermissionBatch) (cfg.PermissionAcceptance, error) {
	a, err := w.Permissions.AcceptPermissions(ctx, b)
	if err == nil {
		w.accepted <- a
	}
	return a, err
}
func (w *observedPermissionWriter) RenewPermissions(ctx context.Context, f cfg.PermissionFence) (cfg.PermissionFence, error) {
	next, err := w.Permissions.RenewPermissions(ctx, f)
	if err == nil {
		w.renewed <- next
	}
	return next, err
}
func (w *observedPermissionWriter) RefreshPermissions(ctx context.Context, b cfg.PermissionBatch) error {
	select {
	case w.refreshed <- struct{}{}:
	default:
	}
	return w.Permissions.RefreshPermissions(ctx, b)
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
		return setup{p, b, authorization.Target{ClusterID: cluster, NamespaceUID: basis.Scope.Namespace.UID, WorkloadUID: custodyID(), PodUID: custodyID()}}
	}
	accept := func(t *testing.T, s *setup) {
		t.Helper()
		r, err := s.p.AcceptPermissions(ctx, s.b)
		if err != nil {
			var step interface{ FixedStep() string }
			if errors.As(err, &step) {
				t.Fatalf("accept: %s (%v)", step.FixedStep(), err)
			}
			t.Fatal(err)
		}
		s.b.ExpectedSequence = r.Sequence
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
	t.Run("cluster-wide-allow-deny-and-retirement", func(t *testing.T) {
		s := create(t)
		allow := s.b.Bases[0]
		allow.Resource.Kind = cfg.ClusterAccessBindingKind
		allow.Scope.Namespace = cfg.AllNamespaces
		allow.ScopeDigest = configapp.PermissionScopeDigest(allow)
		deny := allow
		deny.Resource.UID = custodyID()
		deny.Effect = "Deny"
		deny.ScopeDigest = configapp.PermissionScopeDigest(deny)

		check := func(want bool, reason string, bases ...cfg.PermissionBasis) {
			t.Helper()
			s.b = fresh(s.b)
			s.b.InputDigest[0]++
			s.b.Bases = bases
			accept(t, &s)

			now := time.Now()
			who := identity.Identity{Principal: identity.Principal{Issuer: allow.Subjects[0].Issuer, Subject: "alice", ClientID: "console", Kind: identity.Human},
				Groups: []string{allow.Subjects[0].ID}, Scopes: []string{"evidence:read", "evidence:capture"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
			// Each decision targets a different namespace in the covered cluster.
			s.target.NamespaceUID = custodyID()
			got := authorization.ContextEligibility(who, projection(t, s), s.target, now)
			if got.Eligible != want || (!want && got.Reason != reason) || (want && (len(got.DefaultAudience) != 1 || got.DefaultAudience[0].BasisKind != cfg.ClusterAccessBindingKind || got.DefaultAudience[0].BasisUID != allow.Resource.UID)) {
				t.Fatalf("cluster-wide decision eligible=%v reason=%s audience=%v", got.Eligible, got.Reason, got.DefaultAudience)
			}
		}
		check(true, "", allow)
		check(false, "ExplicitDeny", allow, deny)
		check(true, "", allow)
		check(false, "NoEntitlement")
		var retired int
		err := admin.QueryRow(ctx, `SELECT count(*) FROM permission_assignment a JOIN authority_audit e ON e.id=a.retirement_audit_id WHERE a.stream_id=$1 AND a.retired_at IS NOT NULL`, s.b.RootID).Scan(&retired)
		if err != nil || retired != 2 {
			t.Fatal("audited cluster-wide retirements", retired, err)
		}
	})

	t.Run("decision-time-source-audit-readback", func(t *testing.T) {
		s := create(t)
		for range 65 {
			s.b.ReviewSources = append(s.b.ReviewSources, cfg.ReviewSource{
				Resource:  cfg.Resource{Kind: "PermissionSource", UID: custodyID(), ResourceVersion: "1", Generation: 1, SpecDigest: artifact.Digest{1}},
				ClusterID: s.target.ClusterID, Type: cfg.SourceKubernetesExec, Check: cfg.ReviewPodExec, Role: "workload-maintainer", IdentityMappingRef: "company",
			})
		}
		accept(t, &s)

		reviews, err := postgres.NewAccessReviews(ctx, pool, s.b.RootID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reviews.ReviewSources(ctx, s.target.ClusterID)
		if err != nil || len(got) != len(s.b.ReviewSources) {
			t.Fatal("committed decision sources", len(got), err)
		}
		for _, want := range s.b.ReviewSources {
			if !slices.ContainsFunc(got, func(r cfg.ReviewSource) bool { return r.Resource == want.Resource && r.SameAuthority(want) }) {
				t.Fatal("lost source", want.Resource.UID)
			}
		}
	})

	t.Run("fleet-automation-audit-readback", func(t *testing.T) {
		s := create(t)
		template := s.b.Bases[0]
		template.Automation = &authorization.AutomationEnvelope{AllowedActions: []string{"logs"}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 1024}
		s.b.Bases = nil
		for i := 0; i < 1025; i++ {
			b := template
			b.Resource.UID = custodyID()
			s.b.Bases = append(s.b.Bases, b)
		}
		s.b = fresh(s.b)
		accept(t, &s)
		var count int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM permission_basis_change WHERE event_id=$1 AND NOT retired AND automation_json IS NOT NULL", s.b.RequestID).Scan(&count); err != nil || count != 1025 {
			t.Fatal("incomplete automation provenance", count, err)
		}
		// Long issuers remain on their own immutable assignment rows.
		issuer := template.Subjects[0].Issuer + strings.Repeat("a", 1536)
		for i := range s.b.Bases {
			b := &s.b.Bases[i]
			b.Subjects = slices.Clone(template.Subjects)
			for j := 0; j < 4; j++ {
				b.Subjects = append(b.Subjects, cfg.Subject{Kind: "Group", Issuer: issuer, ID: fmt.Sprintf("team-%d", j)})
			}
			b.Resource.Generation++
			b.Resource.ResourceVersion = "v2"
			b.Resource.SpecDigest[0]++
			b.Continuous = true
		}
		s.b = fresh(s.b)
		accept(t, &s)
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM permission_assignment WHERE activation_audit_id=$1 AND issuer=$2", s.b.RequestID, issuer).Scan(&count); err != nil || count != 4100 {
			t.Fatal("incorrect added members", count, err)
		}
	})
	t.Run("remote-bindings-after-fleet-grows", func(t *testing.T) {
		root := custodyID()
		slow := pool.Config()
		dial := slow.ConnConfig.DialFunc
		slow.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return delayedPermissionConn{conn}, nil
		}
		slowPool, err := pgxpool.NewWithConfig(ctx, slow)
		if err != nil {
			t.Fatal(err)
		}
		defer slowPool.Close()
		reader, err := postgres.NewRemoteAccessBindings(ctx, slowPool, root)
		if err != nil {
			t.Fatal(err)
		}
		store, err := postgres.NewPermissions(ctx, slowPool, root)
		if err != nil {
			t.Fatal(err)
		}
		const cluster = "ffffffff-ffff-4fff-8fff-ffffffffffff"
		ns := cfg.NamespaceRef{Name: "payments", UID: custodyID()}
		binding := cfg.Binding{
			Resource: cfg.Resource{Kind: "AccessBinding", Name: "readers", UID: custodyID(), ClusterID: cluster, Namespace: ns.Name, NamespaceUID: ns.UID, ResourceVersion: "1", Generation: 1, SpecDigest: artifact.Digest{1}},
			Scope:    cfg.Scope{ClusterID: cluster, Namespace: ns}, Effect: "Allow",
			Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "payments"}}, Roles: []string{"evidence-reader"},
		}
		hub := remoteBindingHubFixture{cluster: custodyID()}
		local := binding
		local.Resource.ClusterID, local.Scope.ClusterID, local.Resource.UID = hub.cluster, hub.cluster, custodyID()
		hub.bindings = []cfg.Binding{local}
		reconciler := configapp.BindingReconciler{RootID: root, NamespaceClusterID: hub.cluster, Reader: hub, Watcher: hub, Trust: hub, RemoteBindings: reader, Store: store, NewID: custodyID, Now: time.Now}
		reconcile := func() {
			t.Helper()
			result := reconciler.RunEpoch(ctx)
			if !errors.Is(result.Err, errBaselineAccepted) || !result.Suspended {
				t.Fatalf("reconcile remote deliveries: %v (suspended %t)", result.Err, result.Suspended)
			}
		}
		body, err := json.Marshal([]cfg.Binding{binding})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, `INSERT INTO remote_access_binding_delivery(root_id,cluster_id,observed_at,digest,bindings,unavailable)
			VALUES ($1,$2,clock_timestamp(),sha256($3::bytea),$3,false)`, root, cluster, body); err != nil {
			t.Fatal(err)
		}
		// A v5 federation replica omits availability. Its upsert must fail
		// even if a current replica already wrote an observation for this peer.
		_, err = admin.Exec(ctx, `INSERT INTO remote_access_binding_delivery(root_id,cluster_id,observed_at,digest,bindings)
			VALUES ($1,$2,clock_timestamp(),sha256($3::bytea),$3)
			ON CONFLICT(root_id,cluster_id) DO UPDATE SET digest=excluded.digest,bindings=excluded.bindings`, root, cluster, []byte("[]"))
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23502" || pgErr.ColumnName != "unavailable" {
			t.Fatalf("accepted legacy delivery or wrong refusal: %v", err)
		}
		reconcile()
		checkAssignments := func(cluster string, want int) {
			t.Helper()
			var count int
			err := admin.QueryRow(ctx, `SELECT count(*) FROM permission_assignment a JOIN permission_basis b
				ON b.stream_id=a.stream_id AND b.basis_key=a.basis_key WHERE a.stream_id=$1 AND b.cluster_id=$2 AND a.retired_at IS NULL`, root, cluster).Scan(&count)
			if err != nil || count != want {
				t.Fatalf("active assignments for %s: got %d, want %d: %v", cluster, count, want, err)
			}
		}
		checkAssignments(cluster, 1)
		// Each new cluster contributes a distinct binding and assignment.
		for i := 1; i <= 200; i++ {
			regional := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
			binding.Scope.ClusterID, binding.Resource.ClusterID = regional, regional
			binding.Resource.UID, binding.Subjects[0].ID = custodyID(), regional
			body, err = json.Marshal([]cfg.Binding{binding})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = admin.Exec(ctx, `INSERT INTO remote_access_binding_delivery(root_id,cluster_id,observed_at,digest,bindings,unavailable)
				VALUES ($1,$2,clock_timestamp(),sha256($3::bytea),$3,false)`, root, regional, body); err != nil {
				t.Fatal(err)
			}
		}
		reconcile()
		checkFleet := func(want int) {
			t.Helper()
			var count int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM permission_assignment WHERE stream_id=$1 AND retired_at IS NULL`, root).Scan(&count); err != nil || count != want {
				t.Fatalf("active fleet assignments: got %d, want %d: %v", count, want, err)
			}
		}
		checkFleet(202)
		checkAssignments(hub.cluster, 1)
		if _, err = admin.Exec(ctx, `UPDATE remote_access_binding_delivery SET observed_at=clock_timestamp(), digest=sha256('[]'::bytea), bindings='[]'::bytea
			WHERE root_id=$1 AND cluster_id=$2`, root, cluster); err != nil {
			t.Fatal(err)
		}
		const newlyJoined = "00000000-0000-4000-8000-000000000200"
		// The second read is unchanged and must reuse the decoded documents.
		for range 2 {
			reconcile()
			checkAssignments(cluster, 0)
			checkAssignments(newlyJoined, 1)
			checkFleet(201)
			checkAssignments(hub.cluster, 1)
		}
		// Accept and reread more than 8 MiB of real binding scopes locally.
		// Only the two hundred changed assignments belong to this audit event.
		workloads := make([]cfg.WorkloadRef, 190)
		for i := range workloads {
			workloads[i] = cfg.WorkloadRef{Kind: "Deployment", Name: fmt.Sprintf("app-%03d.%s", i, strings.Repeat(strings.Repeat("a", 46)+".", 4)+"api")}
		}
		encodedWorkloads, err := json.Marshal(workloads)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, `WITH revised AS (
			SELECT cluster_id,convert_to(jsonb_set(jsonb_set(jsonb_set(jsonb_set(
				convert_from(bindings,'UTF8')::jsonb,'{0,Scope,Workloads}',$3::jsonb),
				'{0,Resource,Generation}','2'),'{0,Resource,ResourceVersion}','"2"'),'{0,Resource,SpecDigest,0}','2')::text,'UTF8') AS body
			FROM remote_access_binding_delivery WHERE root_id=$1 AND cluster_id<>$2)
			UPDATE remote_access_binding_delivery AS d SET observed_at=clock_timestamp(),digest=sha256(r.body),bindings=r.body
			FROM revised r WHERE d.root_id=$1 AND d.cluster_id=r.cluster_id`, root, cluster, encodedWorkloads); err != nil {
			t.Fatal(err)
		}
		var fleetBytes int
		if err := admin.QueryRow(ctx, `SELECT sum(octet_length(bindings)) FROM remote_access_binding_delivery WHERE root_id=$1`, root).Scan(&fleetBytes); err != nil || fleetBytes <= 8<<20 {
			t.Fatalf("fleet contains %d bytes: %v", fleetBytes, err)
		}
		reconciler.RemoteBindings, err = postgres.NewRemoteAccessBindings(ctx, pool, root)
		if err != nil {
			t.Fatal(err)
		}
		reconciler.Store, err = postgres.NewPermissions(ctx, pool, root)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			reconcile()
			checkFleet(201)
		}
		// Keep the real production watch active through a database renewal.
		// The quiet fleet must not build, hash or write a new projection.
		live, stop := context.WithTimeout(ctx, 45*time.Second)
		defer stop()
		writer := &observedPermissionWriter{reconciler.Store.(*postgres.Permissions), make(chan cfg.PermissionAcceptance, 4), make(chan cfg.PermissionFence, 2), make(chan struct{}, 1)}
		reconciler.Watcher = idleKubernetesBindingWatch(t, hub.cluster)
		reconciler.Store = writer
		reconciler.RemoteBindingChanges = postgres.Listen(live, pool, postgres.RemoteBindingsChannel)
		done := make(chan configapp.PermissionEpochResult, 1)
		go func() { done <- reconciler.RunEpoch(live) }()
		defer func() {
			stop()
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Error("epoch did not stop")
			}
		}()
		nextAcceptance := func() cfg.PermissionAcceptance {
			t.Helper()
			select {
			case accepted := <-writer.accepted:
				return accepted
			case result := <-done:
				done <- result
				t.Fatalf("epoch stopped: %v", result.Err)
			case <-live.Done():
				t.Fatal(live.Err())
			}
			return cfg.PermissionAcceptance{}
		}
		baseline := nextAcceptance()
		select {
		case f := <-writer.renewed:
			if f.Sequence != baseline.Sequence || len(writer.refreshed) != 0 || len(writer.accepted) != 0 {
				t.Fatal("idle fleet recomputed its projection")
			}
		case result := <-done:
			done <- result
			t.Fatalf("epoch stopped before renewal: %v", result.Err)
		case <-live.Done():
			t.Fatal(live.Err())
		}
		// Leave observed_at untouched: the changed digest at PostgreSQL's
		// original timestamp is the committed replacement.
		if _, err := admin.Exec(ctx, `UPDATE remote_access_binding_delivery SET bindings='[]'::bytea,digest=sha256('[]'::bytea) WHERE root_id=$1 AND cluster_id=$2`, root, newlyJoined); err != nil {
			t.Fatal(err)
		}
		changed := nextAcceptance()
		if changed.Sequence != baseline.Sequence+1 || changed.Retired != 1 {
			t.Fatal("equal-timestamp replacement did not retire the original assignment", changed)
		}
		checkAssignments(newlyJoined, 0)
		checkFleet(200)
	})
	// ADR-237: the impact preview reads every workload cell of the affected
	// namespace from the same accepted projection, and the real evaluator
	// turns a removed allow into Deny and a proposed deny into ExplicitDeny.
	t.Run("permission-impact-preview", func(t *testing.T) {
		s := create(t)
		named := custodyID()
		s.b.Bases[0].Scope.Workloads = []cfg.WorkloadRef{{Kind: "Deployment", Name: "api", UID: named}}
		s.b.Bases[0].ScopeDigest = configapp.PermissionScopeDigest(s.b.Bases[0])
		accept(t, &s)

		next(&s)
		wide := s.b.Bases[0]
		wide.Resource.UID, wide.Scope.Workloads = custodyID(), nil
		wide.ScopeDigest = configapp.PermissionScopeDigest(wide)
		s.b.Bases = append(s.b.Bases, wide)
		accept(t, &s)

		ns := cfg.PreviewNamespace{ClusterID: s.target.ClusterID, NamespaceUID: wide.Scope.Namespace.UID}
		proposed := custodyID()
		snap, err := s.p.PreviewProjections(ctx, cfg.PreviewRead{Workloads: map[cfg.PreviewNamespace][]string{ns: {proposed}}, Bases: []cfg.PreviewBasis{{Kind: "AccessBinding", UID: wide.Resource.UID}, {Kind: "AccessBinding", UID: "absent"}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Cells) != 3 || len(snap.Unmatched) != 1 || snap.Unmatched[0].UID != "absent" {
			t.Fatalf("cells %d unmatched %+v", len(snap.Cells), snap.Unmatched)
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
		changes, _, err := cfg.PreviewChanges([]cfg.AccessChange{{Action: "delete", Kind: "AccessBinding", UID: wide.Resource.UID}})
		if err != nil {
			t.Fatal(err)
		}
		policy := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
		got, err := cfg.PreviewAccess(changes, snap, []string{s.target.ClusterID}, policy, time.Now())
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

		next(&s)
		ns := s.b.Bases[0].Scope.Namespace
		for range 16 {
			b := s.b.Bases[0]
			b.Resource.UID = custodyID()
			b.Scope.Workloads = nil
			for range 62 {
				uid := custodyID()
				b.Scope.Workloads = append(b.Scope.Workloads, cfg.WorkloadRef{Kind: "Deployment", Name: "api-" + uid[24:], UID: uid})
			}
			b.ScopeDigest = configapp.PermissionScopeDigest(b)
			s.b.Bases = append(s.b.Bases, b)
		}
		accept(t, &s)

		key := cfg.PreviewNamespace{ClusterID: s.target.ClusterID, NamespaceUID: ns.UID}
		var proposed []cfg.WorkloadRef
		for range 7 {
			proposed = append(proposed, cfg.WorkloadRef{Kind: "Deployment", Name: "new", UID: custodyID()})
		}
		binding := cfg.Binding{Resource: cfg.Resource{SpecDigest: artifact.Digest{4}}, Effect: "Deny", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "team-a"}}, Roles: []string{"workload-maintainer"},
			Scope: cfg.Scope{ClusterID: s.target.ClusterID, Namespace: ns, Workloads: proposed}}
		changes, read, err := cfg.PreviewChanges([]cfg.AccessChange{{Action: "create", Kind: "AccessBinding", Binding: binding}, {Action: "delete", Kind: "AccessBinding", UID: s.b.Bases[0].Resource.UID}})
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
		got, err := cfg.PreviewAccess(changes, snap, []string{s.target.ClusterID}, policy, time.Now())
		total := time.Since(started)
		if err != nil || !got.Complete() || got.Targets != cfg.MaxPreviewTargets || got.DeltasTotal == 0 {
			t.Fatalf("%v %+v", err, got.Targets)
		}
		t.Logf("ADR-237 worst case: %d cells read in %v, read+evaluate %v, %d decision changes", len(snap.Cells), readTime, total, got.DeltasTotal)
		if total > 4*time.Second {
			t.Fatalf("worst-case preview took %v; it must fit the five-second request", total)
		}
	})
	t.Run("first-acceptance-is-durable", func(t *testing.T) {
		s := create(t)
		accept(t, &s)

		f, err := s.p.BeginPermissions(ctx, s.b.RootID, s.b.Epoch, s.b.TrustDigest)
		if err != nil || !f.Initialized {
			t.Fatalf("initialization not durable: %v", err)
		}
		if err = s.p.SuspendPermissions(ctx, f); err != nil {
			t.Fatal(err)
		}
		f, err = s.p.BeginPermissions(ctx, s.b.RootID, custodyID(), s.b.TrustDigest)
		if err != nil || f.Initialized {
			t.Fatalf("new epoch already had an accepted snapshot: %v", err)
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
	t.Run("atomic-grants-and-idempotent-audit", func(t *testing.T) {
		s := create(t)
		s.b.FreshUntil = s.b.ObservedAt.Add(time.Second)
		original := s.b
		accept(t, &s)
		before := projection(t, s)
		if len(before.Allows) != 1 {
			t.Fatal("audited grant missing")
		}
		// Replaying a committed request after its original end cannot create a new grant.
		<-time.After(time.Until(original.FreshUntil))
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
	t.Run("distinct-bases-commit-and-withdraw", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		healthy := projection(t, s).Allows[0].Audience
		original := s.b.Bases[0]
		remote := custodyID()
		for range 24000 {
			b := original
			b.Resource.Kind = cfg.ClusterAccessBindingKind
			b.Resource.UID = custodyID()
			b.Scope = cfg.Scope{ClusterID: remote, Namespace: cfg.AllNamespaces}
			b.ScopeDigest = configapp.PermissionScopeDigest(b)
			s.b.Bases = append(s.b.Bases, b)
		}
		// While the writer holds its fleet mutation lock, an unrelated reader
		// can still authorize against the last committed assignment.
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.b.RootID); err != nil {
			t.Fatal(err)
		}
		if got := projection(t, s); len(got.Allows) != 1 || got.Allows[0].Audience != healthy {
			t.Fatal("healthy peer blocked behind write")
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		// Apply the same grants as setup. The acceptor can append the event
		// and its original scope, but cannot rewrite either after commit.
		const role = "fixture_permission_history_writer"
		roleTx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer roleTx.Rollback(ctx)
		if _, err = roleTx.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
			t.Fatal(err)
		}
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("permission-accept", role)
		if !ok {
			t.Fatal("unknown permission grant plan")
		}
		for _, grant := range grants {
			if _, err = roleTx.Exec(ctx, grant); err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range []string{"authority_audit", "permission_basis_change"} {
			var immutable bool
			if err = roleTx.QueryRow(ctx, "SELECT has_table_privilege($1,$2,'INSERT') AND NOT has_any_column_privilege($1,$2,'UPDATE') AND NOT has_table_privilege($1,$2,'DELETE,TRUNCATE')", role, table).Scan(&immutable); err != nil || !immutable {
				t.Fatal("mutable permission history", table, err)
			}
		}
		if err = roleTx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		for _, retired := range []bool{false, true} {
			if retired {
				s.b.Bases = s.b.Bases[:1]
			}
			s.b = fresh(s.b)
			f, err := s.p.BeginPermissions(ctx, s.b.RootID, s.b.Epoch, s.b.TrustDigest)
			if err != nil {
				t.Fatal(err)
			}
			s.b.FreshUntil = f.LeaseUntil
			started := time.Now()
			accept(t, &s)
			elapsed := time.Since(started)
			var bases, members, events int
			col := "activation_audit_id"
			if retired {
				col = "retirement_audit_id"
			}
			if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM permission_basis_change WHERE event_id=$1 AND retired=$2),(SELECT count(*) FROM permission_assignment WHERE "+col+"=$1),(SELECT count(*) FROM authority_audit WHERE id=$1 AND octet_length(record::text)<2048)", s.b.RequestID, retired).Scan(&bases, &members, &events); err != nil || bases != 24000 || members != 24000 || events != 1 {
				t.Fatal("incomplete atomic event", bases, members, events, err)
			}
			if got := projection(t, s); len(got.Allows) != 1 || got.Allows[0].Audience != healthy {
				t.Fatal("healthy peer changed")
			}
			t.Logf("24000 distinct bindings retired=%t committed in %s", retired, elapsed)
		}
	})
	t.Run("expanded-remote-change-retains-healthy-peer", func(t *testing.T) {
		s := create(t)
		accept(t, &s)

		old := projection(t, s).Allows[0].Audience
		remote := custodyID()
		bases := s.b.Bases[:1:1]
		for i := 0; i < 32; i++ {
			b := s.b.Bases[0]
			b.Resource.Kind = cfg.ClusterAccessBindingKind
			b.Resource.UID = custodyID()
			b.Scope = cfg.Scope{ClusterID: remote, Namespace: cfg.AllNamespaces}
			b.ScopeDigest = configapp.PermissionScopeDigest(b)
			b.Roles = cfg.Roles
			b.Subjects = nil
			for j := 0; j < 256; j++ {
				b.Subjects = append(b.Subjects, cfg.Subject{Kind: "Group", Issuer: old.Issuer, ID: fmt.Sprintf("team-%d-%d", i, j)})
			}
			bases = append(bases, b)
		}
		s.b = fresh(s.b)
		s.b.Bases = bases
		s.b.Bases[0].Continuous = true
		accept(t, &s)
		healthy := func() {
			t.Helper()
			p := projection(t, s)
			now := time.Now()
			who := identity.Identity{Principal: identity.Principal{Issuer: old.Issuer, Subject: "alice", ClientID: "console", Kind: identity.Human}, Groups: []string{old.SubjectID}, Scopes: []string{"evidence:capture"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
			if got := authorization.ContextEligibility(who, p, s.target, now); !got.Eligible || len(got.DefaultAudience) != 1 || got.DefaultAudience[0] != old {
				t.Fatal("healthy peer lost its existing assignment", got)
			}
		}
		healthy()
		activation := s.b.RequestID
		var cnt int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM permission_assignment WHERE stream_id=$1 AND activation_audit_id=$2", s.b.RootID, activation).Scan(&cnt); err != nil || cnt != 32768 {
			t.Fatal("incomplete atomic write", cnt, err)
		}
		remoteTarget := s.target
		remoteTarget.ClusterID = remote
		audited, err := s.p.Permissions(ctx, remoteTarget)
		if err != nil || len(audited.Allows) != 32768 {
			t.Fatal("audited assignments missing", len(audited.Allows), err)
		}
		var assignment string
		first := bases[1]
		if err := admin.QueryRow(ctx, `SELECT id FROM permission_assignment WHERE stream_id=$1 AND activation_audit_id=$2 AND basis_key=$3 AND subject_kind='Group' AND issuer=$4 AND subject_id='team-0-0' AND role='evidence-reader' AND basis_digest=$5`, s.b.RootID, activation, first.Key(), old.Issuer, first.Resource.SpecDigest[:]).Scan(&assignment); err != nil {
			t.Fatal("cannot resolve original member from activation", err)
		}
		// Remove the whole remote set. No current basis is needed to recover
		// the retired assignment's identity, source and original scope.
		s.b = fresh(s.b)
		s.b.Bases = s.b.Bases[:1]
		accept(t, &s)
		healthy()
		var scope []byte
		if err := admin.QueryRow(ctx, "SELECT scope_digest FROM permission_basis_change WHERE event_id=$1 AND basis_key=$2 AND retired", s.b.RequestID, first.Key()).Scan(&scope); err != nil || !bytes.Equal(scope, first.ScopeDigest[:]) {
			t.Fatal("missing original retirement scope", err)
		}
		var provenance bool
		if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM permission_assignment WHERE id=$1 AND stream_id=$2 AND activation_audit_id=$3 AND retirement_audit_id=$4 AND basis_key=$5 AND basis_digest=$6 AND role='evidence-reader' AND subject_id='team-0-0' AND retired_at IS NOT NULL)`, assignment, s.b.RootID, activation, s.b.RequestID, first.Key(), first.Resource.SpecDigest[:]).Scan(&provenance); err != nil || !provenance {
			t.Fatal("lost event-linked original member after removal", err)
		}

		replacement := first
		replacement.Resource.Generation++
		replacement.Resource.ResourceVersion = "new"
		replacement.Resource.SpecDigest[0]++
		replacement.NotAfter = time.Now().UTC().Add(time.Hour)
		replacement.ScopeDigest = configapp.PermissionScopeDigest(replacement)
		replacement.Subjects = first.Subjects[:1]
		s.b = fresh(s.b)
		s.b.Bases = append(s.b.Bases, replacement)
		accept(t, &s)
		var current []byte
		if err = admin.QueryRow(ctx, "SELECT scope_digest FROM permission_basis WHERE stream_id=$1 AND basis_key=$2", s.b.RootID, first.Key()).Scan(&current); err != nil || !bytes.Equal(current, replacement.ScopeDigest[:]) || bytes.Equal(current, first.ScopeDigest[:]) {
			t.Fatal("scope replacement failed", err)
		}
		if err = admin.QueryRow(ctx, "SELECT scope_digest FROM permission_basis_change WHERE event_id=$1 AND basis_key=$2 AND NOT retired", activation, first.Key()).Scan(&scope); err != nil || !bytes.Equal(scope, first.ScopeDigest[:]) {
			t.Fatal("lost original activation scope", err)
		}

	})
	t.Run("post-renewal-api-clock-behind", func(t *testing.T) {
		s := create(t)
		accept(t, &s)

		// This pool alone sees PostgreSQL half a second ahead of the API.
		// Neither the host clock nor concurrent database sessions are changed.
		_, err := admin.Exec(ctx, `CREATE SCHEMA permission_test_clock;
CREATE FUNCTION permission_test_clock.clock_timestamp() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$SELECT pg_catalog.clock_timestamp()+interval '500 milliseconds'$$;
CREATE FUNCTION permission_test_clock.statement_timestamp() RETURNS timestamptz LANGUAGE sql STABLE AS $$SELECT pg_catalog.statement_timestamp()+interval '500 milliseconds'$$;
GRANT USAGE ON SCHEMA permission_test_clock TO authority_runtime`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, "DROP SCHEMA permission_test_clock CASCADE"); err != nil {
				t.Error(err)
			}
		}()
		config := pool.Config()
		config.ConnConfig.RuntimeParams["search_path"] = "permission_test_clock, pg_catalog, public"
		shifted, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer shifted.Close()
		s.p, err = postgres.NewPermissions(ctx, shifted, s.b.RootID)
		if err != nil {
			t.Fatal(err)
		}
		f := cfg.PermissionFence{RootID: s.b.RootID, Epoch: s.b.Epoch, TrustDigest: s.b.TrustDigest, Sequence: s.b.ExpectedSequence, Initialized: true}
		if _, err = s.p.RenewPermissions(ctx, f); err != nil {
			t.Fatal(err)
		}
		var stamp, until time.Time
		if err = admin.QueryRow(ctx, "SELECT observed_at,fresh_until FROM permission_stream WHERE id=$1", s.b.RootID).Scan(&stamp, &until); err != nil {
			t.Fatal(err)
		}
		p := projection(t, s)
		now := time.Now()
		if !stamp.After(now) {
			t.Fatal("fixture did not exercise clock skew", stamp, now)
		}
		who := identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "alice", ClientID: "console", Kind: identity.Human}, Groups: []string{"team-a"}, Scopes: []string{"evidence:capture"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}
		workload := authorization.WorkloadTarget{ClusterID: s.target.ClusterID, NamespaceUID: s.target.NamespaceUID, WorkloadUID: s.target.WorkloadUID}
		wp, err := s.p.WorkloadPermissions(ctx, workload)
		if err != nil || !authorization.WorkloadScopeEligibility(who, wp, authorization.CollectContext, workload, time.Now()).Eligible {
			t.Fatal("renewal disabled workload permissions", wp.ObservedAt, err)
		}
		got := authorization.ContextEligibility(who, p, s.target, now)
		if !got.Eligible || p.FreshUntil.After(until.Add(-500*time.Millisecond)) || authorization.ContextEligibility(who, p, s.target, p.FreshUntil).Eligible {
			t.Fatal("SQL-clock renewal changed the API decision or extended its deadline", got.Reason, p.ObservedAt, p.FreshUntil, until)
		}
	})
	t.Run("post-renewal-worker-clock-behind", func(t *testing.T) {
		s := create(t)
		accept(t, &s)
		initial := cfg.PermissionFence{RootID: s.b.RootID, Epoch: s.b.Epoch, Sequence: s.b.ExpectedSequence, TrustDigest: s.b.TrustDigest, Initialized: true}
		if _, err := s.p.RenewPermissions(ctx, initial); err != nil {
			t.Fatal(err)
		}
		var renewed time.Time
		if err := admin.QueryRow(ctx, "SELECT observed_at FROM permission_stream WHERE id=$1", s.b.RootID).Scan(&renewed); err != nil {
			t.Fatal(err)
		}
		next(&s)
		s.b.Bases[0].Subjects[0].ID = "new-owner"
		s.b.ObservedAt = renewed.Add(-500 * time.Millisecond)
		s.b.FreshUntil = s.b.ObservedAt.Add(5 * time.Second)
		accept(t, &s)
		if s.b.ExpectedSequence != initial.Sequence+1 {
			t.Fatal("change lost its sequence", s.b.ExpectedSequence)
		}

		got := projection(t, s)
		if got.Revision.UID != initial.Epoch || got.Revision.Generation != s.b.ExpectedSequence || len(got.Allows) != 1 || got.Allows[0].Audience.SubjectID != "new-owner" {
			t.Fatal("renewal disrupted the ordered edit", got)
		}
		stale := fresh(s.b)
		stale.ExpectedSequence = initial.Sequence
		if _, err := s.p.AcceptPermissions(ctx, stale); !errors.Is(err, cfg.ErrChanged) {
			t.Fatal("stale sequence", err)
		}
		expired := fresh(s.b)
		expired.ObservedAt = renewed.Add(-6 * time.Second)
		expired.FreshUntil = expired.ObservedAt.Add(5 * time.Second)
		if _, err := s.p.AcceptPermissions(ctx, expired); !errors.Is(err, cfg.ErrInvalid) {
			t.Fatal("expired original deadline", err)
		}

	})
	t.Run("ownership-A-B-A-does-not-resurrect", func(t *testing.T) {
		s := create(t)
		accept(t, &s)

		old := projection(t, s).Allows[0].Audience
		next(&s)
		s.b.Bases[0].Subjects[0].ID = "team-b"
		accept(t, &s)
		if a := projection(t, s).Allows; len(a) != 1 || a[0].Audience.SubjectID != "team-b" || a[0].Audience.AssignmentID == old.AssignmentID {
			t.Fatal("ownership replacement failed to retire the original assignment")
		}

		next(&s)
		s.b.Bases[0].Subjects[0].ID = "team-a"
		accept(t, &s)

		now := projection(t, s).Allows[0].Audience
		if old.AssignmentID == now.AssignmentID {
			t.Fatal("old audience resurrected")
		}
	})
	t.Run("journal-to-SQL-preserves-metadata-and-retires-owner-cycles", func(t *testing.T) {
		s := create(t)
		basis := s.b.Bases[0]
		basis.Resource.ClusterID = s.target.ClusterID
		// ADR-329: a binding lives in the application namespace it scopes.
		basis.Resource.Namespace = basis.Scope.Namespace.Name
		basis.Resource.NamespaceUID = basis.Scope.Namespace.UID
		basis.Resource.Name = "owners"
		binding := cfg.Binding{Resource: basis.Resource, Scope: basis.Scope, Effect: basis.Effect, Subjects: basis.Subjects, Roles: basis.Roles}
		now := time.Now().UTC().Truncate(time.Microsecond)
		snapshot := cfg.Snapshot{ClusterID: s.target.ClusterID, ControlNamespace: cfg.NamespaceRef{Name: "asservat", UID: "control"}, BindingResourceVersion: "baseline", Bindings: []cfg.Binding{binding}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		journal, err := configapp.NewBindingJournal(snapshot, now)
		if err != nil {
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

		old := projection(t, s).Allows[0].Audience
		s.b = fresh(s.b)
		s.b.Bases[0].Resource.Generation += 2
		accept(t, &s)

		if projection(t, s).Allows[0].Audience.AssignmentID == old.AssignmentID {
			t.Fatal("missed history preserved")
		}
	})
	t.Run("namespace-relist-withdraws-only-derived-access", func(t *testing.T) {
		qualifyBlockedNamespaceRelist(t, pool)
	})
	t.Run("namespace-observation-is-separate-from-source-version", func(t *testing.T) {
		s := create(t)
		s.b.Bases[0].Resource.Kind = "PermissionSource"
		s.b.Bases[0].ObservationVersion = "namespace-v1"
		s.b.Bases[0].ScopeDigest = configapp.PermissionScopeDigest(s.b.Bases[0])
		accept(t, &s)

		old := projection(t, s).Allows[0].Audience
		s.b = fresh(s.b)
		s.b.Bases[0].ObservationVersion = "namespace-v9"
		accept(t, &s)

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
		spec := cfg.Source{Resource: cfg.Resource{SpecDigest: artifact.Digest{6}}, Enabled: true, Type: "namespaceMetadata", ClusterID: s.target.ClusterID, Role: "evidence-reader", NamespaceSelector: map[string]string{"managed": "true"}, Protection: cfg.Protection{Mode: "administratorManaged", ReviewRef: "review"},
			Mapping: cfg.Mapping{Field: "annotation", Key: "owner", Mode: "valueMap", Issuer: issuer, Values: map[string][]string{"payments": {"team-p"}}}}
		unobserved := spec
		unobserved.Mapping.Key = "team"
		changes, read, err := cfg.PreviewChanges([]cfg.AccessChange{{Action: "create", Kind: "PermissionSource", Source: spec}, {Action: "create", Kind: "PermissionSource", Source: unobserved}})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := s.p.PreviewProjections(ctx, read)
		if err != nil || len(snap.Sources) != 2 || len(snap.Sources[0].Grants) != 1 || snap.Sources[1].Unevaluated != cfg.MetadataNotObserved {
			t.Fatalf("source preview read: %v %+v", err, snap.Sources)
		}
		got, err := cfg.PreviewAccess(changes, snap, []string{s.target.ClusterID}, identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, time.Now())
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

		binding := s.b.Bases[0]
		issuer := "https://id.example.test"
		spec := cfg.Source{Resource: cfg.Resource{Kind: "PermissionSource", UID: custodyID(), ResourceVersion: "exec-1", Generation: 1, SpecDigest: artifact.Digest{40}}, Enabled: true, Type: cfg.SourceKubernetesExec,
			ClusterID: s.target.ClusterID, Role: "workload-maintainer", NamespaceSelector: map[string]string{"managed": "true"},
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
			outcome := map[bool]string{true: "Allowed", false: "Denied"}[allowed]
			return store.RecordReview(ctx, authapp.ReviewDecision{Source: src, Principal: who.Principal, Target: request, Allowed: allowed, Outcome: outcome, DecidedAt: time.Now()})
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
		// REQ-PER-006: one authority event per decision change, none for a
		// confirming review. Read its transactionally committed event.
		changes := func(t *testing.T) []string {
			t.Helper()
			rows, err := admin.Query(ctx, "SELECT record FROM authority_audit WHERE stream_id=$1 AND event_kind='permission-review' ORDER BY created_at,id", s.b.RootID)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var out []string
			for rows.Next() {
				var raw []byte
				var event audit.AuthorityRecord
				if rows.Scan(&raw) != nil || json.Unmarshal(raw, &event) != nil || event.Review == nil || !event.Valid() || bytes.Contains(raw, []byte(`"api-1"`)) || bytes.Contains(raw, []byte(`"app"`)) {
					t.Fatalf("review change record %s", raw)
				}
				out = append(out, event.Review.Subject+":"+event.Review.Change+":"+event.Review.Outcome)
			}
			return out
		}
		if got := changes(t); !slices.Equal(got, []string{"alice:granted:Allowed", "bob:granted:Allowed", "alice:revoked:Denied", "alice:restored:Allowed"}) {
			t.Fatalf("decision changes %v", got)
		}
		// An allow decided before the current refusal does not overwrite it:
		// no row changes, so no restored event (Gitar finding on PR #88).
		if err = record(t, alice, source, false); err != nil {
			t.Fatal(err)
		}
		if err = store.RecordReview(ctx, authapp.ReviewDecision{Source: source, Principal: alice.Principal, Target: request, Allowed: true, Outcome: "Allowed", DecidedAt: time.Now().Add(-2 * time.Second)}); err != nil || reviewed(t, alice) != "" {
			t.Fatal("stale allow overwrote the refusal", err)
		}
		if err = record(t, alice, source, true); err != nil || reviewed(t, alice) != first {
			t.Fatal("current allow did not restore", err)
		}
		if got := changes(t); !slices.Equal(got, []string{"alice:granted:Allowed", "bob:granted:Allowed", "alice:revoked:Denied", "alice:restored:Allowed", "alice:revoked:Denied", "alice:restored:Allowed"}) {
			t.Fatalf("stale allow wrote a decision event: %v", got)
		}

		// Preview of deleting the source: the persistent assignments it minted
		// are removed (alice and bob hold current decisions: Allow -> Deny).
		deleting := []cfg.AccessChange{{Action: "delete", Kind: "PermissionSource", UID: source.Resource.UID}}
		deleting, read, err := cfg.PreviewChanges(deleting)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := s.p.PreviewProjections(ctx, read)
		if err != nil || len(snap.Unmatched) != 0 {
			t.Fatalf("decision-time source unmatched in preview: %v %+v", err, snap.Unmatched)
		}
		preview2, err := cfg.PreviewAccess(deleting, snap, []string{s.target.ClusterID}, identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		removed := map[string]int{}
		for _, d := range preview2.Deltas {
			if d.Target.WorkloadUID == s.target.WorkloadUID && d.Before == authorization.Allow && d.After == authorization.Deny {
				removed[d.Subject.ID]++
			}
		}
		if removed["alice"] != 3 || removed["bob"] != 3 {
			t.Fatalf("deleting the source did not show the removed access: %+v", preview2.Deltas)
		}
		// Other principals' direct assignments do not displace this Pod's review.
		approvers := binding
		approvers.Resource.UID, approvers.Roles = custodyID(), []string{"action-approver"}
		approvers.Subjects = make([]cfg.Subject, 257)
		for i := range approvers.Subjects {
			approvers.Subjects[i] = cfg.Subject{Kind: "User", Issuer: issuer, ID: fmt.Sprintf("approver-%d", i)}
		}
		approvers.ScopeDigest = configapp.PermissionScopeDigest(approvers)
		step(t, []cfg.PermissionBasis{binding, approvers}, []cfg.ReviewSource{source}, false)
		if got := eligible(t, alice); !got.Eligible || reviewed(t, alice) != first {
			t.Fatal("unrelated direct assignments obscured decision-time grant", got.Reason)
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
	t.Run("scope-change-and-delete-retire", func(t *testing.T) {
		s := create(t)
		accept(t, &s)

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
	// ADR-335 D4: a workload named without uid matches the resolved workload
	// of that kind and name; a uid pins one instance.
	t.Run("workload-by-name", func(t *testing.T) {
		s := create(t)
		next(&s)
		s.b.Bases[0].Scope.Workloads = []cfg.WorkloadRef{{Kind: "Deployment", Name: "api"}}
		s.b.Bases[0].ScopeDigest = configapp.PermissionScopeDigest(s.b.Bases[0])
		deny := s.b.Bases[0]
		deny.Resource.UID = custodyID()
		deny.Effect = "Deny"
		deny.Scope.Workloads = []cfg.WorkloadRef{{Kind: "StatefulSet", Name: "db"}}
		deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
		s.b.Bases = append(s.b.Bases, deny)
		accept(t, &s)

		if p := projection(t, s); len(p.Allows) != 0 || len(p.Denies) != 0 {
			t.Fatal("unresolved workload matched a name")
		}
		remember := func(uid, ref string) {
			if _, err := admin.Exec(ctx, "INSERT INTO workload_name(cluster_id,workload_uid,ref) VALUES($1,$2,$3)", s.target.ClusterID, uid, ref); err != nil {
				t.Fatal(err)
			}
		}
		remember(s.target.WorkloadUID, "Deployment/api")
		if p := projection(t, s); len(p.Allows) != 1 || len(p.Denies) != 0 {
			t.Fatal("named workload not granted", p.Allows, p.Denies)
		}
		other := s
		other.target.WorkloadUID = custodyID()
		remember(other.target.WorkloadUID, "StatefulSet/db")
		if p := projection(t, other); len(p.Allows) != 0 || len(p.Denies) != 1 {
			t.Fatal("named deny not applied", p.Allows, p.Denies)
		}
		next(&s)
		s.b.Bases = s.b.Bases[:1]
		s.b.Bases[0].Scope.Workloads = []cfg.WorkloadRef{{Kind: "Deployment", Name: "api", UID: custodyID()}}
		s.b.Bases[0].ScopeDigest = configapp.PermissionScopeDigest(s.b.Bases[0])
		accept(t, &s)

		if p := projection(t, s); len(p.Allows) != 0 {
			t.Fatal("pinned uid matched another instance by name")
		}
	})
	t.Run("explicit-deny-effective-at-commit", func(t *testing.T) {
		s := create(t)
		accept(t, &s)

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
	t.Run("hub-local-unrepresentable-deny", func(t *testing.T) {
		qualifyHubLegacyDeny(t, admin, pool)
	})
	t.Run("withdrawn-registration", func(t *testing.T) {
		s := create(t)
		accept(t, &s)

		if len(projection(t, s).Allows) != 1 {
			t.Fatal("original audited Allow unavailable")
		}
		qualifyRegistrationWithdrawal(t, admin, pool, s.p, s.target, s.b)
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

		if projection(t, s).Allows[0].Audience.AssignmentID != old.AssignmentID {
			t.Fatal("routine restart discarded exact unchanged observation")
		}
		s.b = fresh(s.b)
		// The same final spec can hide an intervening change and reversal.
		s.b.Bases[0].Resource.Generation += 2
		s.b.Bases[0].Resource.ResourceVersion = "changed-during-gap"
		accept(t, &s)

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
