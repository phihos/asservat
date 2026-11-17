package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retentionPolicyFixture is one EvidenceRetentionPolicy. A scoped policy
// names only the scenario's own cluster, so a shared database's other
// artifacts never match it; the baseline's ten-year maximum shortens none.
func retentionPolicyFixture(uid string, generation int64, cluster string, maximum, budget int64) privacy.ScopedPolicy {
	p := privacy.ScopedPolicy{Name: uid, Policy: privacy.Policy{Revision: identity.Revision{UID: uid, Generation: generation, Digest: artifact.Digest{byte(generation), byte(maximum)}}, PurposeRef: "diagnostics", DefaultSeconds: maximum, MaximumSeconds: maximum, DeletionBudgetSeconds: budget}, CaseDefaultSeconds: maximum, CaseMaximumSeconds: maximum, AuditDefaultSeconds: maximum, AuditMaximumSeconds: maximum, LegalExceptions: "disabled"}
	if cluster == "" {
		p.Policy.Baseline = true
	} else {
		p.Scope.ClusterIDs = []string{cluster}
	}
	return p
}

// qualifyRetentionPolicies (ADR-330 D12) checks stored-deadline retention on
// real PostgreSQL with the follower's runtime role: a policy event shortens
// matching deadlines with one audit row; raising or removing never extends;
// the preview aggregates without writing; and an admission under a stricter
// stored policy is shortened by the admission trigger.
func qualifyRetentionPolicies(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Run("retention-policy-events-shorten-stored-deadlines", func(t *testing.T) {
		pool := poolFor("retention_source_runtime", "synthetic-retention-source")
		defer pool.Close()
		previewPool := poolFor("retention_preview_read_runtime", "synthetic-retention-preview-read")
		defer previewPool.Close()
		store, err := postgres.NewRetentionPolicies(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		preview, err := postgres.NewRetentionPolicies(ctx, previewPool)
		if err != nil {
			t.Fatal(err)
		}
		s := create(t, 2)
		first, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		cluster := s.a.Registration.Location.ClusterID
		deadlines := func(attempt string) (anchor, expires, deleteBy time.Time) {
			t.Helper()
			if err := admin.QueryRow(ctx, "SELECT anchor_at,effective_expires_at,effective_delete_by FROM custody_attempt WHERE id=$1", attempt).Scan(&anchor, &expires, &deleteBy); err != nil {
				t.Fatal(err)
			}
			return anchor, expires, deleteBy
		}
		events := func(uid, change string) (n, shortened int64) {
			t.Helper()
			if err := admin.QueryRow(ctx, "SELECT count(*),coalesce(sum(shortened),0) FROM retention_policy_event WHERE uid=$1 AND change=$2", uid, change).Scan(&n, &shortened); err != nil {
				t.Fatal(err)
			}
			return n, shortened
		}
		attempt := first.Expectation.Registration.Location.AttemptID
		anchor, e0, d0 := deadlines(attempt)
		baseline := retentionPolicyFixture(custodyID(), 1, "", privacy.MaxAgeSeconds, 300)
		strict := retentionPolicyFixture(custodyID(), 1, cluster, 600, 60)
		defer func() {
			if err := store.SyncRetentionPolicies(context.WithoutCancel(ctx), nil); err != nil {
				t.Error("remove fixture policies", err)
			}
		}()

		if err = store.SyncRetentionPolicies(ctx, []privacy.ScopedPolicy{baseline}); err != nil {
			t.Fatal(err)
		}
		stored, err := preview.CurrentRetentionPolicies(ctx)
		if err != nil || len(stored) != 1 || stored[0].Policy.Revision != baseline.Policy.Revision {
			t.Fatal("stored baseline", stored, err)
		}
		if _, e, d := deadlines(attempt); !e.Equal(e0) || !d.Equal(d0) {
			t.Fatal("baseline shortened a deadline inside its maximum")
		}
		if n, _ := events(baseline.Policy.Revision.UID, "applied"); n != 1 {
			t.Fatal("baseline audit row", n)
		}
		// Unchanged policies write no further event.
		if err = store.SyncRetentionPolicies(ctx, []privacy.ScopedPolicy{baseline}); err != nil {
			t.Fatal(err)
		}
		if n, _ := events(baseline.Policy.Revision.UID, "applied"); n != 1 {
			t.Fatal("repeated sync wrote another audit row", n)
		}

		if err = store.SyncRetentionPolicies(ctx, []privacy.ScopedPolicy{baseline, strict}); err != nil {
			t.Fatal(err)
		}
		_, e1, d1 := deadlines(attempt)
		if !d1.Equal(anchor.Add(600*time.Second)) || !e1.Equal(anchor.Add(540*time.Second)) {
			t.Fatal("stricter policy did not shorten stored deadlines", anchor, e1, d1)
		}
		if n, shortened := events(strict.Policy.Revision.UID, "applied"); n != 1 || shortened != 1 {
			t.Fatal("stricter policy audit row", n, shortened)
		}

		// A rejected policy next to valid ones is stored with its audit row
		// and changes no deadline; the valid ones stay in force, and the
		// admission trigger below skips it.
		rejected := privacy.ScopedPolicy{Name: "rejected", Policy: privacy.Policy{Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{3}}}, Scope: privacy.PolicyScope{ClusterIDs: []string{cluster}}, Rejected: privacy.RejectedPolicy}
		if err = store.SyncRetentionPolicies(ctx, []privacy.ScopedPolicy{baseline, strict, rejected}); err != nil {
			t.Fatal(err)
		}
		if n, shortened := events(rejected.Policy.Revision.UID, "rejected"); n != 1 || shortened != 0 {
			t.Fatal("rejected policy audit row", n, shortened)
		}
		if _, e, d := deadlines(attempt); !e.Equal(e1) || !d.Equal(d1) {
			t.Fatal("rejected policy changed a deadline")
		}
		if stored, err = preview.CurrentRetentionPolicies(ctx); err != nil || len(stored) != 3 {
			t.Fatal("stored set with a rejected policy", stored, err)
		}

		// An admission resolved under the older, longer policy set: the
		// trigger applies the stored stricter policy in its transaction.
		next := s.a
		next.IdempotencyKey = custodyID()
		next.SubmissionDigest[1] = 7
		input := next.Plan.Input
		input.CaptureID = custodyID()
		if next.Plan, err = planning.CompileContext(input, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		next.Registration.Location.ArtifactID = custodyID()
		next.Registration.Location.AttemptID = custodyID()
		second, err := s.s.AdmitContext(ctx, next)
		if err != nil {
			t.Fatal(err)
		}
		secondAttempt := second.Expectation.Registration.Location.AttemptID
		anchor2, e2, d2 := deadlines(secondAttempt)
		if d2.After(anchor2.Add(600*time.Second)) || e2.After(anchor2.Add(540*time.Second)) {
			t.Fatal("admission kept a deadline beyond the stored policy", anchor2, e2, d2)
		}

		// Raising the maximum or removing the policy never extends.
		raised := retentionPolicyFixture(strict.Policy.Revision.UID, 2, cluster, 86400, 60)
		if err = store.SyncRetentionPolicies(ctx, []privacy.ScopedPolicy{baseline, raised}); err != nil {
			t.Fatal(err)
		}
		if _, e, d := deadlines(attempt); !e.Equal(e1) || !d.Equal(d1) {
			t.Fatal("raised maximum extended a deadline")
		}
		if n, shortened := events(strict.Policy.Revision.UID, "applied"); n != 2 || shortened != 1 {
			t.Fatal("raised policy audit row", n, shortened)
		}
		if err = store.SyncRetentionPolicies(ctx, []privacy.ScopedPolicy{baseline}); err != nil {
			t.Fatal(err)
		}
		if _, e, d := deadlines(attempt); !e.Equal(e1) || !d.Equal(d1) {
			t.Fatal("removed policy extended a deadline")
		}
		if n, _ := events(strict.Policy.Revision.UID, "removed"); n != 1 {
			t.Fatal("removal audit row", n)
		}

		// The preview of a two-second maximum: both artifacts become
		// unreadable and due once two seconds have passed; nothing is written.
		if wait := time.Until(anchor2.Add(2100 * time.Millisecond)); wait > 0 {
			time.Sleep(wait)
		}
		tiny := retentionPolicyFixture(custodyID(), 1, cluster, 2, 1)
		rows, err := preview.PreviewRetentionEffects(ctx, []privacy.PolicyEffect{privacy.Effect(tiny)})
		if err != nil {
			t.Fatal(err)
		}
		var mine *privacy.PreviewRow
		for i := range rows {
			if rows[i].ClusterID == cluster && !rows[i].CaseMetadata {
				mine = &rows[i]
			}
		}
		if mine == nil || mine.Scanned != 2 || mine.Affected != 2 || mine.ReadClosed != 2 || mine.DeletionDue != 2 || mine.EarliestDeleteBy.IsZero() {
			t.Fatal("preview aggregate", rows)
		}
		if _, e, d := deadlines(attempt); !e.Equal(e1) || !d.Equal(d1) {
			t.Fatal("preview wrote deadlines")
		}
		if _, err = previewPool.Exec(ctx, "UPDATE custody_attempt SET effective_expires_at=effective_expires_at WHERE id=$1", attempt); err == nil {
			t.Fatal("preview role can change deadlines")
		}
	})
}
