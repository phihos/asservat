package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retentionEffectFixture supplies one target's current policy set. Retention
// is stored deadlines (ADR-330 D12): effects need no proof, so the fixture
// only resolves; it never writes the shared retention_policy table.
type retentionEffectFixture struct {
	set    []privacy.ScopedPolicy
	target authorization.Target
}

func (f *retentionEffectFixture) CurrentRetentionPolicies(context.Context) ([]privacy.ScopedPolicy, error) {
	return append([]privacy.ScopedPolicy(nil), f.set...), nil
}

func (f *retentionEffectFixture) policies(ctx context.Context) (privacy.PolicySet, error) {
	return f.RetentionPolicies(ctx, f.target)
}

// caseMetadataPolicies is the set with case-metadata lifetimes.
func (f *retentionEffectFixture) caseMetadataPolicies(ctx context.Context) (privacy.PolicySet, error) {
	c := &retentionEffectFixture{target: f.target}
	for _, p := range f.set {
		p.Policy = privacy.CaseMetadataPolicy(p)
		c.set = append(c.set, p)
	}
	return c.policies(ctx)
}

// RetentionPolicies matches the set for t, as RetentionResolver does.
func (f *retentionEffectFixture) RetentionPolicies(_ context.Context, t authorization.Target) (privacy.PolicySet, error) {
	return privacy.MatchPolicies(f.set, t, func(p []privacy.Policy) identity.Revision {
		b, _ := json.Marshal(p)
		return identity.Revision{UID: t.ClusterID, Generation: 1, Digest: sha256.Sum256(b)}
	})
}

func retentionEffectDefaultPolicy() privacy.ScopedPolicy {
	return privacy.ScopedPolicy{Name: "baseline", Policy: privacy.Policy{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{5}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 86400, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 86400, LegalExceptions: "disabled"}
}

func newRetentionEffectFixtures(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys) (func(*testing.T, string, authorization.Target) *retentionEffectFixture, func()) {
	return newRetentionEffectFixturesWithPolicy(t, ctx, poolFor, store, keys, retentionEffectDefaultPolicy())
}

func newRetentionEffectFixturesWithPolicy(_ *testing.T, _ context.Context, _ func(string, string) *pgxpool.Pool, _ *objectstore.Store, _ authorityTestKeys, policy privacy.ScopedPolicy, additional ...privacy.ScopedPolicy) (func(*testing.T, string, authorization.Target) *retentionEffectFixture, func()) {
	return func(_ *testing.T, _ string, target authorization.Target) *retentionEffectFixture {
		return &retentionEffectFixture{set: append([]privacy.ScopedPolicy{policy}, additional...), target: target}
	}, func() {}
}

// retentionShortening shortens one artifact's stored deadlines the way a
// policy event's set-based update does (retention_runtime fixture role).
type retentionShortening struct{ pool *pgxpool.Pool }

func newRetentionShortening(_ context.Context, pool *pgxpool.Pool, _ string) (*retentionShortening, error) {
	return &retentionShortening{pool}, nil
}

func (r *retentionShortening) TightenRetention(ctx context.Context, d privacy.LifecycleDecision) error {
	tag, err := r.pool.Exec(ctx, `UPDATE custody_attempt SET effective_expires_at=$2,effective_delete_by=$3 WHERE id=$1 AND effective_expires_at>=$2 AND effective_delete_by>=$3`, d.Location.AttemptID, d.Effective.ExpiresAt, d.Effective.DeleteBy)
	if err == nil && tag.RowsAffected() != 1 {
		return privacy.ErrInvalid
	}
	return err
}

func retentionTestDecision(t *testing.T, _ context.Context, _ *retentionShortening, loc artifact.Location, expires, deleteBy time.Time) privacy.LifecycleDecision {
	t.Helper()
	return privacy.LifecycleDecision{Location: loc, Effective: privacy.Deadlines{ExpiresAt: expires, DeleteBy: deleteBy}}
}
