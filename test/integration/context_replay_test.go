package integration

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This extends the existing actual SQL/S3 fixture, whose source identity and
// permission initialization remain explicitly synthetic. It checks storage
// placement reads and accepted-request replay; a preview stores nothing.
func qualifyContextReplay(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	blueprint := func(t *testing.T, s captureAdmissionScenario) capture.ContextPreview {
		t.Helper()
		a, in := s.a, s.a.Plan.Input
		p := capture.ContextPreview{
			ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: artifact.Digest{42}, RootID: a.RootID, InstallationID: s.recovery.installation,
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
	query := func(t *testing.T, s captureAdmissionScenario, p capture.ContextPreview) capture.ReplayQuery {
		t.Helper()
		i := s.a.Eligibility.VerifiedIdentity
		i.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
		i.ValidUntil = i.VerifiedAt.Add(5 * time.Second)
		return capture.ReplayQuery{RootID: s.a.RootID, PreviewID: p.ID, IdempotencyKey: s.a.IdempotencyKey, SubmissionDigest: captureapp.ContextRequestDigest(p.ID), Identity: i}
	}

	t.Run("current-context-placement-is-scoped-and-read-only", func(t *testing.T) {
		s := create(t, 1)
		readPool := poolFor("context_storage_read_runtime", "synthetic-context-storage-read")
		t.Cleanup(readPool.Close)
		reader, err := postgres.NewContextStorageReader(ctx, readPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		// Bindings are standing rows: the read itself is the observation, valid
		// for at most the thirty-second storage interval from its own time.
		before := time.Now().Add(-time.Second)
		got, err := reader.ContextStorage(ctx, s.a.Eligibility.Target)
		after := time.Now().Add(time.Second)
		r := s.a.Registration
		if err != nil || got.Selection.StoreID != r.StoreID || got.Selection.AllocationID != r.AllocationID || got.Selection.PoolRevision != r.PoolRevision || got.Selection.AllocationRevision != r.AllocationRevision || got.Selection.BindingRevision != s.a.Storage.Revision ||
			got.Binding.ObservedAt.Before(before) || got.Binding.ObservedAt.After(after) || !got.Binding.FreshUntil.After(got.Binding.ObservedAt) || got.Binding.FreshUntil.After(got.Binding.ObservedAt.Add(30*time.Second)) {
			t.Fatal("storage observation changed accepted placement or its read interval", err)
		}
		other := s.a.Eligibility.Target
		other.WorkloadUID = custodyID()
		_, err = reader.ContextStorage(ctx, other)
		var refusal interface{ ContextStorageRead() string }
		if !errors.Is(err, capture.ErrUnavailable) || !errors.As(err, &refusal) || refusal.ContextStorageRead() != "query/no-row" {
			t.Fatal("unbound workload changed its refusal or lost its private no-row phase", err)
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

	t.Run("accepted-replay-survives-the-preview-deadline", func(t *testing.T) {
		s := create(t, 1)
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
		original, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(p.Deadline) + 10*time.Millisecond)
		in := query(t, s, p)
		got, found, err := s.s.LookupContextAdmission(ctx, in)
		original.Replay = true
		if got.MetadataValidUntil.IsZero() || got.MetadataValidUntil.After(in.Identity.ValidUntil) {
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
		// ADR-200 revision (migration 00074): an accepted stream observation is
		// complete for 30 seconds after its own observation, not for the batch's
		// shorter interval. Age the stored observation so that its complete-deny
		// interval ends 150 ms from now; replay must still keep exactly that end.
		var streamUntil time.Time
		if err := admin.QueryRow(ctx, "UPDATE permission_stream SET observed_at=statement_timestamp()-interval '29850 milliseconds',fresh_until=statement_timestamp()+interval '150 milliseconds' WHERE id=$1 RETURNING fresh_until", s.a.RootID).Scan(&streamUntil); err != nil {
			t.Fatal(err)
		}
		got, found, err := s.s.LookupContextAdmission(ctx, in)
		if err != nil || !found || !got.MetadataValidUntil.Equal(streamUntil) {
			t.Fatal("replay did not preserve shorter permission deadline", found, got.MetadataValidUntil, streamUntil, err)
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

// readImplementedExample reads the example this runtime implements:
// examples/implemented/ (pre-ADR-330 contracts) when present, otherwise the
// canonical example.
func readImplementedExample(dir, name string) ([]byte, error) {
	if b, err := os.ReadFile(dir + "implemented/" + name); err == nil {
		return b, nil
	}
	return os.ReadFile(dir + name)
}
