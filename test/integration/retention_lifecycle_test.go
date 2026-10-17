package integration

import (
	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"reflect"
	"sync"
	"testing"
	"time"
)

func retentionTestDecision(t *testing.T, ctx context.Context, s *postgres.Retention, loc artifact.Location, expires, deleteBy time.Time) value.LifecycleDecision {
	t.Helper()
	r, err := s.RetainedArtifact(ctx, loc)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := value.LifecycleDecision{ID: custodyID(), RootID: r.RootID, Location: loc, Target: r.Input.Target, Sequence: r.Sequence + 1, RegistrationDigest: app.RegistrationDigest(r.Registration), PolicyRevision: identity.Revision{UID: "accepted-policy", Generation: 2, Digest: [32]byte{2}}, Policies: []artifact.RetentionRule{{UID: "baseline", Generation: 2, Digest: artifact.Digest{3}}}, Previous: r.Effective, Effective: value.Deadlines{AnchorAt: r.Registration.AnchorAt, ExpiresAt: expires, DeleteBy: deleteBy}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	d.Origins, err = value.MergePolicyOrigins(r.OriginPolicies, d.Policies)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Valid() {
		t.Fatal("invalid test decision", d)
	}
	return d
}

// Real SQL/S3 and signed encrypted journal. Protected source-policy acceptance
// is a fixture input; these tests do not qualify the production policy reader.
func qualifyRetentionLifecycle(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, artifact.PublishedContext)) {
	runtimePool := poolFor("retention_runtime", "synthetic-retention")
	defer runtimePool.Close()
	auditPool := poolFor("retention_audit_runtime", "synthetic-retention-audit")
	defer auditPool.Close()
	readerPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
	defer readerPool.Close()
	custodyPool := poolFor("custody_runtime", "synthetic-runtime")
	defer custodyPool.Close()
	for _, c := range []struct {
		p *pgxpool.Pool
		q string
	}{{runtimePool, "UPDATE retention_decision SET audit_acknowledged_at=clock_timestamp()"}, {runtimePool, "UPDATE custody_attempt SET expires_at=expires_at"}, {auditPool, "UPDATE custody_attempt SET effective_expires_at=effective_expires_at"}, {auditPool, "UPDATE retention_decision SET decision_json=decision_json"}, {custodyPool, "UPDATE custody_attempt SET effective_expires_at=effective_expires_at"}} {
		if _, err := c.p.Exec(ctx, c.q); err == nil {
			t.Fatal("excess retention SQL privilege")
		}
	}
	setup := func(t *testing.T) (captureAdmissionScenario, artifact.PublishedContext, *postgres.Retention, *postgres.Retention, *postgres.ContextPublications) {
		t.Helper()
		s, p := create(t)
		r, err := postgres.NewRetention(ctx, runtimePool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		a, err := postgres.NewRetention(ctx, auditPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := postgres.NewContextPublications(ctx, readerPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		return s, p, r, a, reader
	}
	t.Run("retention-shortening-is-concurrent-monotonic-and-signed", func(t *testing.T) {
		s, p, r, a, reader := setup(t)
		loc := p.Expectation.Registration.Location
		before, err := r.RetainedArtifact(ctx, loc)
		if err != nil {
			t.Fatal(err)
		}
		expires := before.Registration.ExpiresAt.Add(-time.Minute)
		deletes := before.Registration.DeleteBy.Add(-time.Minute)
		d := retentionTestDecision(t, ctx, r, loc, expires, deletes)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); errs <- r.TightenRetention(ctx, d) }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		retained, err := reader.RetainedAudience(ctx, loc.ArtifactID)
		if err != nil || !retained.ExpiresAt.Equal(expires) {
			t.Fatal("reader retained old cutoff", retained, err)
		}
		after, err := r.RetainedArtifact(ctx, loc)
		if err != nil || !reflect.DeepEqual(before.Registration, after.Registration) || after.Sequence != 1 {
			t.Fatal("immutable registration changed", after, err)
		}
		pending, err := a.PendingLifecycleDecisions(ctx)
		if err != nil || len(pending) != 1 {
			t.Fatal("duplicate or missing lifecycle", pending, err)
		}
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, err := jose.NewLifecycleSignatures(s.a.RootID, "lifecycle-1", priv, map[string]ed25519.PublicKey{"lifecycle-1": pub})
		if err != nil {
			t.Fatal(err)
		}
		objects := &objectstore.LifecycleObjects{Store: store, Seal: keys, Open: keys, Signer: signer, Verifier: signer}
		receipt, err := objects.WriteLifecycleDecision(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.AcknowledgeLifecycleDecision(ctx, d, receipt); err != nil {
			t.Fatal(err)
		}
		// Key rotation verifies the existing immutable object's historical signature.
		pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
		rotated, err := jose.NewLifecycleSignatures(s.a.RootID, "lifecycle-2", priv2, map[string]ed25519.PublicKey{"lifecycle-1": pub, "lifecycle-2": pub2})
		if err != nil {
			t.Fatal(err)
		}
		objects.Signer = rotated
		objects.Verifier = rotated
		repeated, err := objects.WriteLifecycleDecision(ctx, d)
		if err != nil || repeated != receipt {
			t.Fatal("journal replay after rotation", err)
		}
		if err = a.AcknowledgeLifecycleDecision(ctx, d, repeated); err != nil {
			t.Fatal(err)
		}
		pending, err = a.PendingLifecycleDecisions(ctx)
		if err != nil || len(pending) != 0 {
			t.Fatal("journal remained pending", err)
		}
		bad := d
		bad.Effective.DeleteBy = bad.Effective.DeleteBy.Add(-time.Second)
		if err = r.TightenRetention(ctx, bad); !errors.Is(err, app.ErrConflict) {
			t.Fatal("same decision ID changed", err)
		}
		if _, err = objects.WriteLifecycleDecision(ctx, bad); err == nil {
			t.Fatal("immutable journal replaced")
		}
		if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET effective_expires_at=expires_at WHERE id=$1", loc.AttemptID); err == nil {
			t.Fatal("database trigger allowed extension")
		}
		if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET expires_at=expires_at+interval '1 second' WHERE id=$1", loc.AttemptID); err == nil {
			t.Fatal("database trigger allowed provenance rewrite")
		}
		if _, err = admin.Exec(ctx, "UPDATE retention_decision SET decision_json=decode('00','hex') WHERE id=$1", d.ID); err == nil {
			t.Fatal("journal rewrite")
		}
	})
	t.Run("overdue-shortening-blocks-read-and-commit-before-audit", func(t *testing.T) {
		_, p, r, a, reader := setup(t)
		reg := p.Expectation.Registration
		d := retentionTestDecision(t, ctx, r, reg.Location, reg.AnchorAt.Add(time.Microsecond), reg.AnchorAt.Add(2*time.Microsecond))
		if err := r.TightenRetention(ctx, d); err != nil {
			t.Fatal(err)
		}
		pending, err := a.PendingLifecycleDecisions(ctx)
		if err != nil || len(pending) != 1 {
			t.Fatal(err)
		}
		if _, err = reader.RetainedAudience(ctx, reg.Location.ArtifactID); err == nil {
			t.Fatal("pending journal preserved disclosure")
		}
		ledger, err := postgres.New(ctx, custodyPool)
		if err != nil {
			t.Fatal(err)
		}
		if err = ledger.CheckVerification(ctx, reg); !errors.Is(err, app.ErrExpired) {
			t.Fatal("retention did not fence finalization", err)
		}
		cleanup, err := ledger.ClaimDeletion(ctx, reg.Location)
		if err != nil || !cleanup.Effective.DeleteBy.Equal(d.Effective.DeleteBy) || !cleanup.Registration.ExpiresAt.Equal(reg.ExpiresAt) {
			t.Fatal("overdue cleanup lost provenance", cleanup, err)
		}
		// Replay during pending deletion remains history, never new collection.
		if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", reg.Location.AttemptID); err != nil {
			t.Fatal(err)
		}
		if err = r.TightenRetention(ctx, d); err != nil {
			t.Fatal("retry lost original decision", err)
		}
		// No purge/barrier was proven, so bytes remain charged.
		var charged int64
		if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", reg.AllocationID).Scan(&charged); err != nil || charged != reg.ReservedBytes() {
			t.Fatal("shortening released storage without cleanup", err)
		}
	})
	t.Run("closed-readable-interval-preserves-hard-deadline-and-cleanup", func(t *testing.T) {
		_, p, r, _, reader := setup(t)
		reg := p.Expectation.Registration
		d := retentionTestDecision(t, ctx, r, reg.Location, reg.AnchorAt, reg.DeleteBy)
		if err := r.TightenRetention(ctx, d); err != nil {
			t.Fatal(err)
		}
		stored, err := r.RetainedArtifact(ctx, reg.Location)
		if err != nil || !stored.Effective.ExpiresAt.Equal(reg.AnchorAt) || !stored.Effective.DeleteBy.Equal(reg.DeleteBy) || stored.Sequence != 1 {
			t.Fatal("closed interval lost", err)
		}
		if _, err = reader.RetainedAudience(ctx, reg.Location.ArtifactID); err == nil {
			t.Fatal("closed lifetime remained readable")
		}
		ledger, err := postgres.New(ctx, custodyPool)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ledger.ClaimDeletion(ctx, reg.Location); err != nil {
			t.Fatal("closed interval was not eligible for cleanup", err)
		}
		if err = r.TightenRetention(ctx, d); err != nil {
			t.Fatal("closed interval replay failed", err)
		}
	})
	t.Run("retention-waiter-rechecks-freshness-after-lock", func(t *testing.T) {
		_, p, r, _, _ := setup(t)
		reg := p.Expectation.Registration
		d := retentionTestDecision(t, ctx, r, reg.Location, reg.ExpiresAt.Add(-time.Minute), reg.DeleteBy.Add(-time.Minute))
		d.ValidUntil = d.ObservedAt.Add(100 * time.Millisecond)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM custody_allocation WHERE id=$1 FOR UPDATE", reg.AllocationID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- r.TightenRetention(ctx, d) }()
		time.Sleep(200 * time.Millisecond)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; !errors.Is(err, app.ErrFence) {
			t.Fatal("expired decision applied", err)
		}
		after, err := r.RetainedArtifact(ctx, reg.Location)
		if err != nil || after.Sequence != 0 || !after.Effective.ExpiresAt.Equal(reg.ExpiresAt) {
			t.Fatal("aborted shortening left state", err)
		}
	})
}
