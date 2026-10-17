package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/configuration"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the installer's topology and initial protected API observations are
// synthesized. SQL readiness, encrypted audit and catch-up use runtime roles.
type retentionEffectTopology struct {
	root   string
	source privacy.PolicySourceRef
}

func (r retentionEffectTopology) RetentionTopology(_ context.Context, cluster string) (privacy.PolicyTopology, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return privacy.PolicyTopology{RootID: r.root, TargetClusterID: cluster, Revision: identity.Revision{UID: "topology", Generation: 1, Digest: artifact.Digest{42}}, Sources: []privacy.PolicySourceRef{r.source}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

type retentionEffectFixture struct {
	mu              sync.Mutex
	guard           *postgres.RetentionTransactionGuard
	sources, reader *postgres.RetentionSources
	checkpoint      app.RetentionCheckpoint
	fence           app.RetentionFence
	topology        retentionEffectTopology
	target          authorization.Target
}

func (f *retentionEffectFixture) observe(ctx context.Context) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	list := f.checkpoint.Transition.List
	list.Snapshot.ObservedAt, list.Snapshot.FreshUntil = now, now.Add(5*time.Second)
	return f.sources.ObserveRetention(ctx, app.RetentionObservation{Fence: f.fence, List: list, Protection: privacy.SourceProtection{SourceClusterID: f.fence.Source.ClusterID, ControlNamespaceUID: f.fence.Source.ControlNamespaceUID, Digest: f.fence.Source.ProtectionDigest, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}})
}
func (f *retentionEffectFixture) policies(ctx context.Context) (privacy.PolicySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.observe(ctx); err != nil {
		return privacy.PolicySet{}, err
	}
	return (privacyapp.AcceptedRetentionReader{Topology: f.topology, Sources: f.reader, Now: time.Now}).RetentionPolicies(ctx, f.target)
}
func (f *retentionEffectFixture) RetainedRetentionPolicies(ctx context.Context, target authorization.Target, origins []artifact.RetentionRule) (privacy.PolicySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if target != f.target {
		return privacy.PolicySet{}, privacy.ErrUnavailable
	}
	if err := f.observe(ctx); err != nil {
		return privacy.PolicySet{}, err
	}
	return (privacyapp.AcceptedRetentionReader{Topology: f.topology, Sources: f.reader, Now: time.Now}).RetainedRetentionPolicies(ctx, target, origins)
}

func retentionEffectDefaultPolicy() privacy.ScopedPolicy {
	return privacy.ScopedPolicy{Name: "baseline", Policy: privacy.Policy{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{5}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 86400, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 86400, LegalExceptions: "disabled"}
}

func newRetentionEffectFixtures(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys) func(*testing.T, string, authorization.Target) *retentionEffectFixture {
	return newRetentionEffectFixturesWithPolicy(t, ctx, poolFor, store, keys, retentionEffectDefaultPolicy())
}

// Only a fixture's original accepted policy is configurable. This path uses
// the same SQL acceptance, encrypted audit, catch-up and current reads.
func newRetentionEffectFixturesWithPolicy(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, policy privacy.ScopedPolicy) func(*testing.T, string, authorization.Target) *retentionEffectFixture {
	sourcePool := poolFor("retention_source_runtime", "synthetic-retention-source")
	readPool := poolFor("retention_source_read_runtime", "synthetic-retention-source-read")
	return func(t *testing.T, root string, target authorization.Target) *retentionEffectFixture {
		t.Helper()
		// These roles only establish the initial accepted checkpoint. The
		// returned fixture retains source/read pools for later observations.
		auditPool := poolFor("retention_source_audit_runtime", "synthetic-retention-source-audit")
		defer auditPool.Close()
		catchupPool := poolFor("retention_catchup_runtime", "synthetic-retention-catchup")
		defer catchupPool.Close()
		source, err := postgres.NewRetentionSources(ctx, sourcePool, root)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := postgres.NewRetentionSources(ctx, readPool, root)
		if err != nil {
			t.Fatal(err)
		}
		auditor, err := postgres.NewRetentionSources(ctx, auditPool, root)
		if err != nil {
			t.Fatal(err)
		}
		catchup, err := postgres.NewRetention(ctx, catchupPool, root)
		if err != nil {
			t.Fatal(err)
		}
		ref := privacy.PolicySourceRef{ClusterID: target.ClusterID, ControlNamespaceUID: "control", Hub: true, ProtectionDigest: artifact.Digest{1}}
		start, err := source.BeginRetention(ctx, root, ref, custodyID())
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		snapshot := privacy.PolicySnapshot{SourceClusterID: ref.ClusterID, ControlNamespaceUID: ref.ControlNamespaceUID, Hub: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Policies: []privacy.ScopedPolicy{policy}}
		snapshot.Revision = identity.Revision{UID: ref.ControlNamespaceUID, Generation: 1, Digest: app.RetentionSnapshotDigest(snapshot)}
		list := app.PolicyList{Snapshot: snapshot, ResourceVersion: "100", Versions: map[string]string{"baseline": "90"}}
		review := cfg.RetentionBootstrapReview{Resource: cfg.Resource{Kind: "ConfigMap", Name: "review", UID: "review", ClusterID: ref.ClusterID, Namespace: "control", NamespaceUID: ref.ControlNamespaceUID, ResourceVersion: "review:1", SpecDigest: artifact.Digest{2}}, Reviewer: "synthetic-installer", PoliciesDigest: snapshot.Revision.Digest, ProtectionDigest: ref.ProtectionDigest, ReviewedAt: now, ExpiresAt: now.Add(time.Hour), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		cp, err := source.AcceptRetention(ctx, app.RetentionTransition{ID: custodyID(), Fence: start.Fence, List: list, Review: &review})
		if err != nil {
			t.Fatal(err)
		}
		if err = (app.RetentionAcceptancePublisher{Journal: auditor, Writer: &objectstore.RetentionAcceptanceObjects{Store: store, Seal: keys, Open: keys}}).Publish(ctx, 64); err != nil {
			t.Fatal(err)
		}
		page, err := catchup.ReconcileRetentionPage(ctx, ref, 1)
		if err != nil || !page.Complete || page.Visited != 0 {
			t.Fatal("initial empty catch-up", page, err)
		}
		topology := retentionEffectTopology{root, ref}
		guard, err := postgres.NewRetentionTransactionGuard(root, topology)
		if err != nil {
			t.Fatal(err)
		}
		fence := start.Fence
		fence.Sequence = cp.Record.Sequence
		return &retentionEffectFixture{guard: guard, sources: source, reader: reader, checkpoint: cp, fence: fence, topology: topology, target: target}
	}
}
