package integration

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This extends the existing actual SQL/S3 fixture, whose source identity and
// permission initialization remain explicitly synthetic. A preview is passive;
// these checks do not qualify a public transport or collection executor.
func qualifyContextPreviews(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	pool := poolFor("context_preview_runtime", "synthetic-context-preview")
	// poolFor also registers outer-test cleanup. Release this helper's pools
	// here: the concurrency check can open all 16 connections, and subsequent
	// publication/download helpers need their own independently scoped roles.
	defer pool.Close()
	cleanupPool := poolFor("context_preview_cleanup_runtime", "synthetic-context-preview-cleanup")
	defer cleanupPool.Close()
	newStore := func(t *testing.T, root string) *postgres.ContextPreviews {
		t.Helper()
		s, err := postgres.NewContextPreviews(ctx, pool, root)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	newCleanup := func(t *testing.T, root string) *postgres.ContextPreviewCleanup {
		t.Helper()
		s, err := postgres.NewContextPreviewCleanup(ctx, cleanupPool, root)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	blueprint := func(t *testing.T, s captureAdmissionScenario) capture.ContextPreview {
		t.Helper()
		a, in := s.a, s.a.Plan.Input
		p := capture.ContextPreview{
			ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: artifact.Digest{42}, RootID: a.RootID, InstallationID: a.Recovery.InstallationID, IssuerEpoch: a.Recovery.IssuerEpoch,
			CaptureID: in.CaptureID, CaseID: a.CaseID, OccurrenceID: a.OccurrenceID, ArtifactID: a.Registration.Location.ArtifactID, AttemptID: a.Registration.Location.AttemptID,
			Actor:  in.Executor,
			Intent: capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace.Name, Kind: in.Target.Request.Workload.Kind, Name: in.Target.Request.Workload.Name}, Diagnostic: capture.ContextDiagnosticName, RequestedSeconds: in.Retention.RequestedSeconds},
			Target: in.Target.Request, Pin: in.Target.Pin,
			Storage:   capture.ContextStorageSelection{StoreID: a.Registration.StoreID, AllocationID: a.Registration.AllocationID, PoolRevision: a.Registration.PoolRevision, AllocationRevision: a.Registration.AllocationRevision, BindingRevision: a.Storage.Revision},
			Retention: capture.ContextRetentionReview{PurposeRef: in.Retention.PurposeRef, RequestedSeconds: in.Retention.RequestedSeconds, MaximumSeconds: in.Retention.MaximumSeconds, DeletionBudgetSeconds: in.Retention.DeletionBudgetSeconds, Policies: in.Retention.Policies},
			Audience:  a.Eligibility.DefaultAudience, CanonicalScope: a.Plan.CanonicalScope, ScopeDigest: a.Plan.ScopeDigest, CreatedAt: a.Plan.CompiledAt, Deadline: in.Deadline,
		}
		if !captureapp.ValidContextPreview(p) {
			t.Fatal("invalid synthetic preview")
		}
		return p
	}
	fork := func(t *testing.T, s captureAdmissionScenario, actor identity.Principal, deadline time.Time) capture.ContextPreview {
		t.Helper()
		input := s.a.Plan.Input
		input.CaptureID, input.Executor, input.Deadline = custodyID(), actor, deadline
		var err error
		s.a.Plan, err = planning.CompileContext(input, s.a.Plan.CompiledAt)
		if err != nil {
			t.Fatal(err)
		}
		s.a.Registration.Location.ArtifactID, s.a.Registration.Location.AttemptID = custodyID(), custodyID()
		s.a.CaseID, s.a.OccurrenceID = custodyID(), custodyID()
		return blueprint(t, s)
	}
	query := func(t *testing.T, s captureAdmissionScenario, p capture.ContextPreview) capture.ReplayQuery {
		t.Helper()
		r, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := s.a.Eligibility.VerifiedIdentity
		i.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
		i.ValidUntil = i.VerifiedAt.Add(5 * time.Second)
		return capture.ReplayQuery{RootID: s.a.RootID, PreviewID: p.ID, IdempotencyKey: s.a.IdempotencyKey, SubmissionDigest: captureapp.ContextRequestDigest(p.ID), Identity: i, Recovery: r}
	}

	qualifyContextRequestResolution(t, ctx, admin, poolFor, create, newStore, blueprint, query)

	t.Run("current-context-placement-is-scoped-read-only-and-preserves-original-freshness", func(t *testing.T) {
		s := create(t, 1)
		readPool := poolFor("context_storage_read_runtime", "synthetic-context-storage-read")
		t.Cleanup(readPool.Close)
		reader, err := postgres.NewContextStorageReader(ctx, readPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reader.ContextStorage(ctx, s.a.Eligibility.Target)
		r := s.a.Registration
		if err != nil || got.Selection.StoreID != r.StoreID || got.Selection.AllocationID != r.AllocationID || got.Selection.PoolRevision != r.PoolRevision || got.Selection.AllocationRevision != r.AllocationRevision || got.Selection.BindingRevision != s.a.Storage.Revision || !got.Binding.ObservedAt.Equal(s.a.Storage.ObservedAt) || !got.Binding.FreshUntil.Equal(s.a.Storage.FreshUntil) {
			t.Fatal("storage observation changed accepted placement/freshness", err)
		}
		other := s.a.Eligibility.Target
		other.WorkloadUID = custodyID()
		if _, err := reader.ContextStorage(ctx, other); err == nil {
			t.Fatal("unbound workload adopted another placement")
		}
		for _, check := range []struct {
			statement string
			args      []any
		}{
			{"UPDATE context_storage_binding SET fresh_until=fresh_until WHERE allocation_id=$1", []any{r.AllocationID}},
			{"UPDATE custody_pool SET allocated_objects=allocated_objects WHERE id=$1", []any{s.poolID}},
			{"UPDATE custody_allocation SET charged_objects=charged_objects WHERE id=$1", []any{r.AllocationID}},
			{"INSERT INTO context_capture DEFAULT VALUES", nil},
		} {
			_, err := readPool.Exec(ctx, check.statement, check.args...)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatal("expected storage-role permission denial", check.statement, err)
			}
		}
	})

	t.Run("preview-principal-cap-is-atomic-across-clients", func(t *testing.T) {
		s := create(t, 1)
		store := newStore(t, s.a.RootID)
		previews := make([]capture.ContextPreview, 20)
		for i := range previews {
			actor := s.a.Plan.Input.Executor
			actor.ClientID = fmt.Sprintf("client-%d", i%2)
			previews[i] = fork(t, s, actor, s.a.Plan.Input.Deadline)
		}
		var wg sync.WaitGroup
		errs := make([]error, len(previews))
		for i := range previews {
			wg.Add(1)
			go func(i int) { defer wg.Done(); errs[i] = store.CreateContextPreview(ctx, previews[i]) }(i)
		}
		wg.Wait()
		accepted := 0
		for _, err := range errs {
			if err == nil {
				accepted++
			} else if !errors.Is(err, capture.ErrCapacity) {
				t.Fatal("unexpected preview error", err)
			}
		}
		if accepted != capture.MaxPreviewsPerPrincipal {
			t.Fatalf("accepted %d previews across clients", accepted)
		}
		actor := s.a.Plan.Input.Executor
		actor.Subject = "another-developer"
		other := fork(t, s, actor, s.a.Plan.Input.Deadline)
		if err := store.CreateContextPreview(ctx, other); err != nil {
			t.Fatal("one developer exhausted another's review slots", err)
		}
		for _, table := range []string{"context_capture", "custody_attempt"} {
			var count int
			q := "SELECT count(*) FROM context_capture WHERE root_id=$1"
			key := s.a.RootID
			if table == "custody_attempt" {
				q, key = "SELECT count(*) FROM custody_attempt WHERE allocation_id=$1", s.a.Registration.AllocationID
			}
			if err := admin.QueryRow(ctx, q, key).Scan(&count); err != nil || count != 0 {
				t.Fatal("passive preview reserved collection", table, count, err)
			}
		}
	})

	t.Run("preview-immutable-owner-bound-and-independent-of-observation-age", func(t *testing.T) {
		s := create(t, 1)
		store := newStore(t, s.a.RootID)
		p := blueprint(t, s)
		p.CreatedAt = p.CreatedAt.Add(-10 * time.Second)
		if err := store.CreateContextPreview(ctx, p); err != nil {
			t.Fatal("review age incorrectly requires five-second observations", err)
		}
		if err := store.CreateContextPreview(ctx, p); err != nil {
			t.Fatal("exact uncertain-create retry failed", err)
		}
		got, err := store.ReadContextPreview(ctx, p.RootID, p.ID, p.Actor)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatal("preview identity or original deadline changed", err)
		}
		changed := p.Clone()
		changed.Deadline = changed.Deadline.Add(time.Second)
		if err := store.CreateContextPreview(ctx, changed); !errors.Is(err, capture.ErrConflict) {
			t.Fatal("immutable retry replaced original preview", err)
		}
		actor := p.Actor
		actor.ClientID = "other-client"
		if _, err := store.ReadContextPreview(ctx, p.RootID, p.ID, actor); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("another client read preview", err)
		}
		for _, statement := range []string{"UPDATE context_preview SET deadline=deadline+interval '1 second' WHERE id=$1", "DELETE FROM context_preview WHERE id=$1"} {
			if _, err := pool.Exec(ctx, statement, p.ID); err == nil {
				t.Fatal("preview role rewrote or deleted active review")
			}
		}
		if _, err := cleanupPool.Exec(ctx, "DELETE FROM context_preview WHERE id=$1", p.ID); err == nil {
			t.Fatal("cleanup credential deleted active review")
		}
		if _, err := admin.Exec(ctx, "UPDATE context_preview SET deadline=deadline+interval '1 second' WHERE id=$1", p.ID); err == nil {
			t.Fatal("schema did not reject immutable preview mutation")
		}
	})

	t.Run("expired-previews-reclaim-capacity-without-capture-side-effects", func(t *testing.T) {
		s := create(t, 1)
		store, cleanup := newStore(t, s.a.RootID), newCleanup(t, s.a.RootID)
		deadline := time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
		for i := 0; i < capture.MaxPreviewsPerPrincipal; i++ {
			p := fork(t, s, s.a.Plan.Input.Executor, deadline)
			if err := store.CreateContextPreview(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := cleanup.DeleteExpiredContextPreviews(ctx); err != nil || n != 0 {
			t.Fatal("deleted live previews", n, err)
		}
		p := fork(t, s, s.a.Plan.Input.Executor, s.a.Plan.Input.Deadline)
		if err := store.CreateContextPreview(ctx, p); !errors.Is(err, capture.ErrCapacity) {
			t.Fatal("full review quota did not deny", err)
		}
		time.Sleep(time.Until(deadline) + 10*time.Millisecond)
		if n, err := cleanup.DeleteExpiredContextPreviews(ctx); err != nil || n != capture.MaxPreviewsPerPrincipal {
			t.Fatal("expired quota was not reclaimed", n, err)
		}
		if err := store.CreateContextPreview(ctx, p); err != nil {
			t.Fatal("reclaimed preview slot unavailable", err)
		}
	})

	t.Run("accepted-replay-survives-preview-expiry-and-deletion", func(t *testing.T) {
		s := create(t, 1)
		store, cleanup := newStore(t, s.a.RootID), newCleanup(t, s.a.RootID)
		input := s.a.Plan.Input
		input.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
		var err error
		s.a.Plan, err = planning.CompileContext(input, s.a.Plan.CompiledAt)
		if err != nil {
			t.Fatal(err)
		}
		s.a.Registration.WriteUntil = input.Deadline
		p := blueprint(t, s)
		s.a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
		if err := store.CreateContextPreview(ctx, p); err != nil {
			t.Fatal(err)
		}
		original, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(p.Deadline) + 10*time.Millisecond)
		if n, err := cleanup.DeleteExpiredContextPreviews(ctx); err != nil || n != 1 {
			t.Fatal("expired review remains", n, err)
		}
		if _, err := store.ReadContextPreview(ctx, p.RootID, p.ID, p.Actor); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("missing preview readable", err)
		}
		in := query(t, s, p)
		got, found, err := s.s.LookupContextAdmission(ctx, in)
		original.Replay = true
		if got.MetadataValidUntil.IsZero() || got.MetadataValidUntil.After(in.Identity.ValidUntil) || got.MetadataValidUntil.After(in.Recovery.FreshUntil) {
			t.Fatal("accepted lookup lost current metadata deadline")
		}
		original.MetadataValidUntil = got.MetadataValidUntil // transient reply authority, not immutable admission
		if err != nil || !found || !reflect.DeepEqual(got, original) {
			t.Fatal("replay lost original IDs, retention or registration", found, err)
		}
		var count int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM custody_attempt WHERE allocation_id=$1", s.a.Registration.AllocationID).Scan(&count); err != nil || count != 1 {
			t.Fatal("replay created another acquisition", count, err)
		}
		in.PreviewID = custodyID()
		in.SubmissionDigest = captureapp.ContextRequestDigest(in.PreviewID)
		if _, found, err := s.s.LookupContextAdmission(ctx, in); !errors.Is(err, capture.ErrConflict) || found {
			t.Fatal("same key accepted changed reviewed intent", found, err)
		}
		in = query(t, s, p)
		in.Identity.Principal.ClientID = "another-client"
		if _, found, err := s.s.LookupContextAdmission(ctx, in); err != nil || found {
			t.Fatal("idempotency lookup crossed client boundary", found, err)
		}
	})

	t.Run("accepted-replay-checks-current-denies-before-conflict", func(t *testing.T) {
		s := create(t, 1)
		p := blueprint(t, s)
		s.a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		batch := s.batch
		batch.Initial = nil
		batch.RequestID, batch.InputDigest = custodyID(), artifact.Digest{99}
		batch.ObservedAt, batch.FreshUntil = now, now.Add(5*time.Second)
		deny := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "deny-1", SpecDigest: artifact.Digest{98}}, Scope: batch.Bases[0].Scope, Effect: "Deny", Subjects: []cfg.Subject{{Kind: "User", Issuer: p.Actor.Issuer, ID: p.Actor.Subject}}, Roles: []string{"workload-maintainer"}}
		deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
		batch.Bases = append(append([]cfg.PermissionBasis{}, batch.Bases...), deny)
		if _, err := s.p.AcceptPermissions(ctx, batch); err != nil {
			t.Fatal(err)
		}
		in := query(t, s, p)
		in.PreviewID, in.SubmissionDigest = custodyID(), artifact.Digest{}
		in.SubmissionDigest = captureapp.ContextRequestDigest(in.PreviewID)
		if _, found, err := s.s.LookupContextAdmission(ctx, in); !errors.Is(err, capture.ErrDenied) || found {
			t.Fatal("denied actor saw accepted/conflicting operation", found, err)
		}
	})

	t.Run("accepted-replay-does-not-renew-identity-after-lock-wait", func(t *testing.T) {
		s := create(t, 1)
		p := blueprint(t, s)
		s.a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		in := query(t, s, p)
		in.Identity.ValidUntil = time.Now().Add(150 * time.Millisecond)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, _, err := s.s.LookupContextAdmission(ctx, in); done <- err }()
		time.Sleep(300 * time.Millisecond)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, capture.ErrDenied) {
			t.Fatal("expired request crossed replay lock", err)
		}
	})

	t.Run("accepted-replay-does-not-renew-deny-completeness-after-lock-wait", func(t *testing.T) {
		s := create(t, 1)
		p := blueprint(t, s)
		s.a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		in := query(t, s, p)
		batch := s.batch
		batch.Initial = nil
		batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		batch.FreshUntil = batch.ObservedAt.Add(150 * time.Millisecond)
		if err := s.p.RefreshPermissions(ctx, batch); err != nil {
			t.Fatal(err)
		}
		got, found, err := s.s.LookupContextAdmission(ctx, in)
		if err != nil || !found || !got.MetadataValidUntil.Equal(batch.FreshUntil) {
			t.Fatal("replay did not preserve shorter permission deadline", found, got.MetadataValidUntil, batch.FreshUntil, err)
		}
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, _, err := s.s.LookupContextAdmission(ctx, in); done <- err }()
		time.Sleep(300 * time.Millisecond)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("fresh identity renewed expired complete-deny observation")
		}
	})
}
