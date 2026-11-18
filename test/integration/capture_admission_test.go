package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	privacy "asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
)

type captureAdmissionScenario struct {
	p             *postgres.Permissions
	s             *postgres.ContextAdmissions
	batch         cfg.PermissionBatch
	a             capture.Admission
	poolID        string
	retention     *retentionEffectFixture
	recovery      *recoveryEffectFixture
	nativeSources *nativeFixtureSourceOwner
}

// Shared by the actual fixture factory and its constructor-boundary regression.
// Keep the original role, TLS, connection limit and default idle policy. Product
// SQL adapters reject pgx tracers; diagnostics belong in the owned server log.
func captureAdmissionPoolConfig(dsn string, transport *tls.Config) (*pgxpool.Config, error) {
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pc.ConnConfig.TLSConfig = transport
	pc.ConnConfig.Fallbacks = nil
	pc.MaxConns = 8
	return pc, nil
}

// The installed one-connection profile (bootstrap providerInputs.sqlConfig):
// MaxConns=1, no warm minimum, 30-second idle and five-minute jittered lifetime.
// Native15 exhausted the unchanged 48-slot server only because the journey used
// the previous 16-connection fixture profile above. This does not raise any limit, and
// idle expiry is not admission control; a nested same-pool acquisition now
// waits on its original deadline exactly as it would in the installed hub.
func installedSQLPoolProfile(pc *pgxpool.Config) *pgxpool.Config {
	pc.MaxConns, pc.MinConns = 1, 0
	pc.MaxConnLifetime, pc.MaxConnLifetimeJitter, pc.MaxConnIdleTime = 5*time.Minute, 30*time.Second, 30*time.Second
	return pc
}

// This composes real SQL admission, capacity and transaction-local permission audit. IdP,
// retained policy qualification and target observations are synthetic fixtures;
// it does not enable the public collection path or qualify fleet execution.
func TestContextAdmissionWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	var native *fixture
	if path == "" {
		path = os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
		if path == "" {
			t.Skip("run make custody-integration or context-integration")
		}
		native = &fixture{}
	}
	var f struct{ Postgres, S3 string }
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	if native != nil && (json.Unmarshal(b, native) != nil || len(native.Clusters) != 2) {
		t.Fatal("native context fixture unavailable")
	}
	clear(b)
	ctx := context.Background()
	if native != nil {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, 3*time.Minute)
		defer stop()
	}
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	u, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tls := pgTLSBridge(t, u.Host)
	poolFor := func(user, password string) *pgxpool.Pool {
		t.Helper()
		pc, err := captureAdmissionPoolConfig("postgres://"+user+":"+password+"@"+address+"/custody_test?sslmode=disable", tls)
		if err != nil {
			t.Fatal(err)
		}
		p, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	t.Run("retained-local-key-versions", func(t *testing.T) {
		qualifyRetainedLocalKeyVersions(t, ctx, admin, poolFor)
	})
	installedPoolFor := func(user, password string) *pgxpool.Pool {
		t.Helper()
		pc, err := captureAdmissionPoolConfig("postgres://"+user+":"+password+"@"+address+"/custody_test?sslmode=disable", tls)
		if err != nil {
			t.Fatal(err)
		}
		p, err := pgxpool.NewWithConfig(ctx, installedSQLPoolProfile(pc))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	authorityOpen := poolFor
	if native != nil && os.Getenv("ASSERVAT_CONTEXT_REGIONAL_START_NATIVE") == "journey" {
		// The journey branch alone uses this hub purpose afterwards; native18
		// showed its fixture profile opening a third connection under the
		// unchanged 48-slot server. Use the installed one-connection profile.
		authorityOpen = installedPoolFor
	}
	authorityPool := authorityOpen("authority_runtime", "synthetic-authority")
	capturePool := poolFor("capture_runtime", "synthetic-capture")
	custodyPool := poolFor("custody_runtime", "synthetic-runtime")
	for _, sql := range []string{"UPDATE permission_stream SET suspended=false", "UPDATE context_storage_binding SET fresh_until=clock_timestamp()+interval '1 day'", "UPDATE context_capture SET deadline=clock_timestamp()+interval '1 day'", "DELETE FROM context_capture"} {
		if _, err := capturePool.Exec(ctx, sql); err == nil {
			t.Fatal("capture role has unnecessary authority", sql)
		}
	}
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "capture-authority"
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	if _, err = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	// Current worker, enrollment and download audit receipts require immutable
	// versions. The mixed evidence store below retains its generic constructor.
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
	ledger, err := postgres.New(ctx, custodyPool)
	if err != nil {
		t.Fatal(err)
	}
	seedRetention, resetRetention := newRetentionEffectFixtures(t, ctx, poolFor, store, keys)
	seedRecovery := newRecoveryEffectFixtures(t, ctx, admin)
	if native == nil {
		// Every pool opened below the shared fixtures above must be closed by
		// its own subtest or helper; leaked idle connections exhausted the
		// unchanged 48-connection server for later cases.
		defer requireOnlySQLRoles(t, ctx, admin, "postgres", "authority_runtime", "capture_runtime", "custody_runtime", "context_control_config_runtime", "capture_audit_runtime", "peer_read_runtime")
	}
	type scenario = captureAdmissionScenario
	// ADR-248: a recording scenario registers the 8 MiB per-capture limit.
	scenarioNativeLimit := int64(4096)
	createForTargetWithControl := func(t *testing.T, slots, _, _ int64, source func(context.Context) (targets.PodResolution, error), image artifact.Digest) scenario {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		root, epoch, cluster, namespace, workload, pod := custodyID(), custodyID(), custodyID(), custodyID(), custodyID(), custodyID()
		namespaceName := "app"
		if source != nil {
			target, err := source(ctx)
			if err != nil {
				t.Fatal(err)
			}
			cluster, namespace, workload, pod, namespaceName = target.Request.ClusterID, target.Request.Namespace.UID, target.Request.Workload.UID, target.Request.PodUID, target.Request.Namespace.Name
		}
		p, err := postgres.NewPermissions(ctx, authorityPool, root)
		if err != nil {
			t.Fatal(err)
		}
		trust := artifact.Digest{1}
		if _, err = p.BeginPermissions(ctx, root, epoch, trust); err != nil {
			t.Fatal(err)
		}
		bases := []cfg.PermissionBasis{
			{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "1", SpecDigest: artifact.Digest{2}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: namespaceName, UID: namespace}}, Effect: "Allow", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}, Roles: []string{"workload-maintainer"}},
			{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "2", SpecDigest: artifact.Digest{3}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: namespaceName, UID: namespace}}, Effect: "Allow", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "other-owners"}}, Roles: []string{"evidence-owner"}},
		}
		for i := range bases {
			bases[i].ScopeDigest = configapp.PermissionScopeDigest(bases[i])
		}
		batch := cfg.PermissionBatch{RootID: root, Epoch: epoch, RequestID: custodyID(), TrustDigest: trust, InputDigest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Bases: bases}
		accepted, err := p.AcceptPermissions(ctx, batch)
		if err != nil {
			t.Fatal(err)
		}
		batch.ExpectedSequence = accepted.Sequence
		now = time.Now().UTC().Truncate(time.Microsecond)
		target := targets.PodResolution{Request: targets.Request{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: namespaceName, UID: namespace}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: workload}, PodName: "api-123", PodUID: pod}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: namespace, Name: "api-123", UID: pod, NodeName: "worker", ControllerUID: "replicaset"}, NodeUID: "node", NodeBootID: custodyID(), PodResourceVersion: "10", WorkloadResourceVersion: "11", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		if source != nil {
			target, err = source(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if target.Request.ClusterID != cluster || target.Request.PodUID != pod {
				t.Fatal("native selected target changed during fixture setup")
			}
		}
		retentionFixture := seedRetention(t, root, target.Target())
		recoveryFixture := seedRecovery(t, root)
		policies, err := retentionFixture.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}

		now = time.Now().UTC().Truncate(time.Microsecond)
		retention, err := privacy.Resolve(policies, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: now}, now)
		if err != nil {
			t.Fatal(err)
		}
		actor := identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "browser", Kind: identity.Human}
		identityValue := identity.Identity{Principal: actor, Scopes: []string{"evidence:capture"}, Groups: []string{"maintainers"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{6}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
		if source != nil {
			batch.ObservedAt = now
			batch.FreshUntil = now.Add(5 * time.Second)
			if err = p.RefreshPermissions(ctx, batch); err != nil {
				t.Fatal(err)
			}
			target, err = source(ctx)
			if err != nil {
				t.Fatal(err)
			}
		}
		projection, err := p.Permissions(ctx, target.Target())
		if err != nil {
			t.Fatal(err)
		}
		eligibility := authorization.ContextEligibility(identityValue, projection, target.Target(), now)
		if !eligibility.Eligible {
			t.Fatal(eligibility.Reason)
		}
		caseID, planCaseID := custodyID(), ""
		if source != nil {
			planCaseID = caseID
		} else {
			image = artifact.Digest{8}
		}
		plan, err := planning.CompileContext(planvalue.ContextInput{CaptureID: custodyID(), CaseID: planCaseID, Executor: actor, Deadline: now.Add(time.Minute), Target: target, Retention: retention, Capability: planvalue.ContextCapability{ExecutionClass: target.ExecutionClass, Revision: identity.Revision{UID: "capability", Generation: 1, Digest: [32]byte{7}}, Enabled: true, CollectorVersion: "synthetic", CollectorImageDigest: image, ProjectionDigest: planning.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}}, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
		poolID, storeID, allocationID := custodyID(), custodyID(), custodyID()
		r := artifact.Registration{Location: artifact.Location{ClusterID: cluster, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: storeID, AllocationID: allocationID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: scenarioNativeLimit, AnchorAt: now, WriteUntil: plan.Input.Deadline, ExpiresAt: retention.ExpiresAt, DeleteBy: retention.DeleteBy}
		if _, err = admin.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,clock_timestamp()+interval '1 hour',$3,$4)", poolID, storeID, r.ReservedBytes()*max(slots, 1)*2, max(slots, 1)*8); err != nil {
			t.Fatal(err)
		}
		if err = provisionAllocation(ctx, admin, testAllocation{ID: allocationID, PoolID: poolID, ScopeID: custodyID(), ServiceClass: "context", PoolRevision: 1, Revision: 1, Bytes: r.ReservedBytes() * slots, Objects: slots * 4, ValidUntil: now.Add(30 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		storage := capture.StorageBinding{RootID: root, ClusterID: cluster, NamespaceUID: namespace, WorkloadUID: workload, AllocationID: allocationID, Revision: identity.Revision{UID: "budget-binding", Generation: 1, Digest: [32]byte{9}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}
		// Protected configuration is synthesized by the fixture, never a capture
		// caller. This role cannot update authority or binding freshness.
		if _, err = admin.Exec(ctx, "INSERT INTO context_storage_binding(root_id,cluster_id,namespace_uid,workload_uid,allocation_id,source_uid,source_generation,source_digest,observed_at,fresh_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", root, cluster, namespace, workload, allocationID, storage.Revision.UID, storage.Revision.Generation, storage.Revision.Digest[:], now, storage.FreshUntil); err != nil {
			t.Fatal(err)
		}
		s, err := postgres.NewContextAdmissions(ctx, capturePool, root, recoveryFixture.installation)
		if err != nil {
			t.Fatal(err)
		}
		return scenario{p, s, batch, capture.Admission{RootID: root, IdempotencyKey: "synthetic-request", SubmissionDigest: artifact.Digest{10}, Plan: plan, Eligibility: eligibility, Storage: storage, Registration: r, CaseID: caseID, OccurrenceID: custodyID()}, poolID, retentionFixture, recoveryFixture, nil}
	}
	createForTarget := func(t *testing.T, slots int64, source func(context.Context) (targets.PodResolution, error), image artifact.Digest) scenario {
		return createForTargetWithControl(t, slots, max(slots, 1)*2, max(slots, 1)*2, source, image)
	}
	if native != nil {
		regional := os.Getenv("ASSERVAT_CONTEXT_REGIONAL_START_NATIVE")
		name := "native-api-runner"
		if regional != "" {
			if regional != "first" && regional != "continuation" && regional != "journey" {
				t.Fatal("invalid owned regional qualification selection")
			}
			name = "native-regional-api-" + regional
		}
		selectedCreate := createForTarget
		if regional == "journey" {
			selectedCreate = func(t *testing.T, slots int64, source func(context.Context) (targets.PodResolution, error), image artifact.Digest) scenario {
				s := createForTarget(t, slots, source, image)
				// The shared journey uses its audited admission and execution roles.
				// These legacy/setup adapters have no later work in that branch.
				capturePool.Close()
				custodyPool.Close()
				return s
			}
		}
		t.Run(name, func(t *testing.T) {
			qualifyNativeAPIExecution(t, ctx, *native, admin, poolFor, installedPoolFor, store, keys, selectedCreate, regional)
		})
		return
	}
	create := func(t *testing.T, slots int64) scenario { return createForTarget(t, slots, nil, artifact.Digest{}) }
	t.Run("capture-during-peer-permission-publication", func(t *testing.T) {
		s := create(t, 1)
		withStagedPeerPermission(t, ctx, admin, s, nil, func() error {
			_, err := s.s.AdmitContext(ctx, s.a)
			return err
		})
	})
	t.Run("suspension-during-peer-permission-publication", func(t *testing.T) {
		s := create(t, 1)
		f := cfg.PermissionFence{RootID: s.batch.RootID, Epoch: s.batch.Epoch, TrustDigest: s.batch.TrustDigest}
		withStagedPeerPermission(t, ctx, admin, s, cfg.ErrChanged, func() error {
			return s.p.SuspendPermissions(ctx, f)
		})
		var sequence, events int64
		var suspended bool
		if err := admin.QueryRow(ctx, `SELECT sequence,suspended,(SELECT count(*) FROM authority_audit WHERE stream_id=$1)
			FROM permission_stream WHERE id=$1`, s.batch.RootID).Scan(&sequence, &suspended, &events); err != nil || sequence != s.batch.ExpectedSequence || !suspended || events != 2 {
			t.Fatalf("staged mutation after suspension: sequence %d, suspended %v, events %d: %v", sequence, suspended, events, err)
		}
	})
	qualifyHistoryParameters(t, ctx, admin, poolFor, store, keys, create)
	qualifyContextReplay(t, ctx, admin, poolFor, create)
	qualifyContextProgress(t, ctx, admin, poolFor, create)
	qualifyAPIExecutionTransactions(t, ctx, admin, poolFor, store, keys, s3admin, bucket, create)
	qualifyRecordingTransactions(t, ctx, admin, poolFor, store, keys, func(t *testing.T) scenario {
		scenarioNativeLimit = artifact.RecordingNativeLimit
		defer func() { scenarioNativeLimit = 4096 }()
		return create(t, recordingScenarioSlots)
	})
	t.Run("policy-recorder-team-action-grant-and-occurrence", func(t *testing.T) {
		qualifyPolicyRecorderAdmission(t, ctx, admin, poolFor, store, keys, func(t *testing.T) scenario {
			scenarioNativeLimit = artifact.RecordingNativeLimit
			defer func() { scenarioNativeLimit = 4096 }()
			return create(t, 1)
		})
	})
	qualifyContextPublications(t, ctx, admin, poolFor, store, keys, create, func() {
		// Joined bursts also release the shared parent fixture's idle pools;
		// the native exchange below needs about 40 of the 48 server slots.
		authorityPool.Reset()
		admin.Reset()
		capturePool.Reset()
		custodyPool.Reset()
		resetRetention()
	})
	qualifyRetentionPolicies(t, ctx, admin, poolFor, create)
	charges := func(t *testing.T, s scenario, want int64) {
		t.Helper()
		var count, bytes int64
		if err := admin.QueryRow(ctx, "SELECT charged_objects,charged_bytes FROM custody_allocation WHERE id=$1", s.a.Registration.AllocationID).Scan(&count, &bytes); err != nil {
			t.Fatal(err)
		}
		if count != want*4 || bytes != want*s.a.Registration.ReservedBytes() {
			t.Fatalf("charge mismatch objects=%d bytes=%d want attempts=%d", count, bytes, want)
		}
	}
	t.Run("concurrent-replay-is-one-frozen-admission", func(t *testing.T) {
		s := create(t, 1)
		results := make(chan capture.Accepted, 8)
		errs := make(chan error, 8)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); r, e := s.s.AdmitContext(ctx, s.a); results <- r; errs <- e }()
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		fresh := 0
		for r := range results {
			if !r.Replay {
				fresh++
			}
			if r.MetadataValidUntil.IsZero() || r.MetadataValidUntil.After(s.a.Eligibility.ValidUntil) {
				t.Fatal("accepted reply lost original metadata authority deadline")
			}
			if r.CaptureID != s.a.Plan.Input.CaptureID || !r.Deadline.Equal(s.a.Plan.Input.Deadline) || len(r.Expectation.Audience) != 2 || r.Expectation.Validate() != nil {
				t.Fatalf("incorrect acceptance: %+v", r)
			}
		}
		if fresh != 1 {
			t.Fatalf("new admissions %d", fresh)
		}
		charges(t, s, 1)
		var count int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM custody_copy WHERE attempt_id=$1", s.a.Registration.Location.AttemptID).Scan(&count); err != nil || count != 4 {
			t.Fatal("missing pre-write obligations", err, count)
		}
		s.a.SubmissionDigest[0]++
		if _, err := s.s.AdmitContext(ctx, s.a); !errors.Is(err, capture.ErrConflict) {
			t.Fatal("different intent replayed", err)
		}
		charges(t, s, 1)
	})
	for _, test := range []struct {
		name   string
		change func(*capture.Admission)
		want   error
	}{
		{"wrong-target", func(a *capture.Admission) { a.Eligibility.Target.WorkloadUID = "other" }, capture.ErrInvalid},
		{"forged-audience", func(a *capture.Admission) { a.Eligibility.DefaultAudience = a.Eligibility.DefaultAudience[:1] }, capture.ErrChanged},
		{"wrong-store", func(a *capture.Admission) { a.Registration.StoreID = custodyID() }, capture.ErrChanged},
		{"wrong-allocation", func(a *capture.Admission) {
			a.Storage.AllocationID = custodyID()
			a.Registration.AllocationID = a.Storage.AllocationID
		}, capture.ErrUnavailable},
		{"missing-membership", func(a *capture.Admission) { a.Eligibility.VerifiedIdentity.Groups = nil }, capture.ErrDenied},
		{"expired-identity", func(a *capture.Admission) {
			a.Eligibility.VerifiedIdentity.ValidUntil = a.Eligibility.VerifiedIdentity.VerifiedAt
		}, capture.ErrDenied},
		{"different-permission-revision", func(a *capture.Admission) { a.Eligibility.PermissionRevision.Generation++ }, capture.ErrChanged},
		{"plaintext-native-ceiling", func(a *capture.Admission) { a.Registration.NativeLimit = 8192 }, capture.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := create(t, 1)
			test.change(&s.a)
			if _, err := s.s.AdmitContext(ctx, s.a); !errors.Is(err, test.want) {
				t.Fatalf("got %v want %v", err, test.want)
			}
			if test.name != "wrong-allocation" {
				charges(t, s, 0)
			}
		})
	}

	t.Run("exhausted-workload-does-not-use-another-allocation", func(t *testing.T) {
		s := create(t, 0)
		if _, err := s.s.AdmitContext(ctx, s.a); !errors.Is(err, capture.ErrCapacity) {
			t.Fatal(err)
		}
		charges(t, s, 0)
		other := create(t, 1)
		if _, err := other.s.AdmitContext(ctx, other.a); err != nil {
			t.Fatal("independent allocation blocked", err)
		}
		charges(t, other, 1)
	})
	t.Run("authority-expires-during-pool-lock-wait", func(t *testing.T) {
		s := create(t, 1)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM custody_pool WHERE id=$1 FOR UPDATE", s.poolID); err != nil {
			t.Fatal(err)
		}
		s.a.Eligibility.ValidUntil = time.Now().Add(150 * time.Millisecond)
		done := make(chan error, 1)
		go func() { _, e := s.s.AdmitContext(ctx, s.a); done <- e }()
		time.Sleep(300 * time.Millisecond)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; !errors.Is(err, capture.ErrDenied) {
			t.Fatal("expired input crossed blocking lock", err)
		}
		charges(t, s, 0)
	})
	t.Run("revocation-between-evaluation-and-admission", func(t *testing.T) {
		s := create(t, 1)
		fence, err := s.p.BeginPermissions(ctx, s.batch.RootID, s.batch.Epoch, s.batch.TrustDigest)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.p.SuspendPermissions(ctx, fence); err != nil {
			t.Fatal(err)
		}
		if _, err = s.s.AdmitContext(ctx, s.a); err == nil {
			t.Fatal("suspended authority accepted")
		}
		charges(t, s, 0)
	})
	t.Run("admission-writes-one-audit-row", func(t *testing.T) {
		s := create(t, 1)
		id := s.a.Plan.Input.CaptureID
		rows := func() (n int) {
			if err := admin.QueryRow(ctx, "SELECT count(*) FROM audit_event WHERE operation_id=$1 AND kind='capture.start' AND status='success' AND effect='accepted' AND capture_ids=ARRAY[$2::text] AND case_ids=ARRAY[$3::text] AND subject=$4", id, id, s.a.CaseID, s.a.Plan.Input.Executor.Subject).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		if rows() != 1 {
			t.Fatal("admission did not write its audit row")
		}
		if record, err := s.s.AdmitContext(ctx, s.a); err != nil || !record.Replay || rows() != 1 {
			t.Fatal("replay wrote another audit row", err)
		}
		charges(t, s, 1)
	})
	t.Run("original-replay-after-plan-observation-expiry", func(t *testing.T) {
		s := create(t, 1)
		original, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(s.a.Plan.ValidUntil) + 10*time.Millisecond)
		now := time.Now().UTC().Truncate(time.Microsecond)
		s.batch.ObservedAt = now
		s.batch.FreshUntil = now.Add(5 * time.Second)
		if err = s.p.RefreshPermissions(ctx, s.batch); err != nil {
			t.Fatal(err)
		}
		projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		s.a.Eligibility = authorization.ContextEligibility(s.a.Eligibility.VerifiedIdentity, projection, s.a.Eligibility.Target, now)
		replay, err := s.s.AdmitContext(ctx, s.a)
		if err != nil || !replay.Replay || replay.CaptureID != original.CaptureID || !replay.CreatedAt.Equal(original.CreatedAt) || !replay.Deadline.Equal(original.Deadline) {
			t.Fatal("expired observation caused reacquisition or lost original request", err)
		}
		charges(t, s, 1)
	})

	t.Run("generic-custody-does-not-become-capture-authority", func(t *testing.T) {
		s := create(t, 1)
		if _, err = ledger.Register(ctx, s.a.Registration); err != nil {
			t.Fatal(err)
		}
		if _, err = s.s.AdmitContext(ctx, s.a); !errors.Is(err, capture.ErrConflict) {
			t.Fatal("adopted prior attempt", err)
		}
		charges(t, s, 1)
	})
}

// requireOnlySQLRoles fails when a client connection of any other role is still
// open: a helper or subtest kept its pool past its own scope. Closing a pool
// ends its sessions, so a short wait covers only server-side session exit.
func requireOnlySQLRoles(t *testing.T, ctx context.Context, admin *pgxpool.Pool, allowed ...string) {
	t.Helper()
	if t.Failed() {
		return
	}
	var open []string
	for deadline := time.Now().Add(5 * time.Second); ; {
		open = nil
		rows, err := admin.Query(ctx, "SELECT usename||':'||count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND datname=current_database() AND NOT usename=ANY($1) GROUP BY usename ORDER BY usename", allowed)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err = rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			open = append(open, s)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		if len(open) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(open) > 0 {
		t.Errorf("SQL pools left open by their subtest or helper: %v", open)
	}
}
