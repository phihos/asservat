package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Native SQL fixture source only until the owning frozen custody suite is run.
// Permission/recovery/source setup remains the existing explicit fixture setup.
func qualifyContextRequestResolution(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario, storeFor func(*testing.T, string) *postgres.ContextPreviews, blueprint func(*testing.T, captureAdmissionScenario) value.ContextPreview, readQuery func(*testing.T, captureAdmissionScenario, value.ContextPreview) value.ReplayQuery) {
	pool := poolFor("context_request_resolution_runtime", "synthetic-context-request-resolution")
	defer pool.Close()
	resolver := func(t *testing.T, s captureAdmissionScenario) *postgres.ContextRequestResolutions {
		t.Helper()
		r, err := postgres.NewContextRequestResolutions(ctx, pool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// The admission fixture intentionally has only acquisition scope. Request
	// resolution is a metadata operation and uses its independently required
	// read scope; production validation must not be relaxed for the fixture.
	query := func(t *testing.T, s captureAdmissionScenario, p value.ContextPreview) value.ReplayQuery {
		in := readQuery(t, s, p)
		in.Identity.Scopes = append(append([]string(nil), in.Identity.Scopes...), "evidence:read")
		return in
	}
	prepare := func(t *testing.T) (captureAdmissionScenario, value.ContextPreview) {
		t.Helper()
		s := create(t, 1)
		p := blueprint(t, s)
		p.AssessmentRulesDigest = planning.ContextAssessmentRulesDigestForClass(p.ExecutionClass)
		s.a.SubmissionDigest = app.ContextRequestDigest(p.ID)
		return s, p
	}
	noCapture := func(t *testing.T, s captureAdmissionScenario) {
		t.Helper()
		var captures, attempts int
		if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM context_capture WHERE root_id=$1),(SELECT count(*) FROM custody_attempt WHERE allocation_id=$2)", s.a.RootID, s.a.Registration.AllocationID).Scan(&captures, &attempts); err != nil || captures != 0 || attempts != 0 {
			t.Fatal("passive closure admitted effects", captures, attempts, err)
		}
	}

	t.Run("resolution-requires-read-scope-before-negative-fence", func(t *testing.T) {
		s, p := prepare(t)
		in := query(t, s, p)
		in.Identity.Scopes = []string{"evidence:capture"}
		d, err := resolver(t, s).ResolveOrCloseContextRequest(ctx, in)
		if !errors.Is(err, value.ErrDenied) || d.State != "" {
			t.Fatal("capture scope substituted for metadata scope", err)
		}
		var fences int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM context_preview_fence WHERE root_id=$1", s.a.RootID).Scan(&fences); err != nil || fences != 0 {
			t.Fatal("denied caller closed request", fences, err)
		}
		noCapture(t, s)
	})
	t.Run("closed-review-cannot-be-reopened-by-create-or-cached-admission", func(t *testing.T) {
		s, p := prepare(t)
		store := storeFor(t, s.a.RootID)
		if err := store.CreateContextPreview(ctx, p); err != nil {
			t.Fatal(err)
		}
		r := resolver(t, s)
		in := query(t, s, p)
		d, err := r.ResolveOrCloseContextRequest(ctx, in)
		if err != nil || d.State != value.RequestClosed || d.Accepted != nil || !d.Valid(time.Now()) {
			t.Fatal("close not acknowledged", err)
		}
		var first time.Time
		if err := admin.QueryRow(ctx, "SELECT closed_at FROM context_preview WHERE id=$1", p.ID).Scan(&first); err != nil {
			t.Fatal(err)
		}
		in.IdempotencyKey = "another-key"
		if d, err = r.ResolveOrCloseContextRequest(ctx, in); err != nil || d.State != value.RequestClosed {
			t.Fatal("same preview not closed for other key", err)
		}
		var again time.Time
		if err := admin.QueryRow(ctx, "SELECT closed_at FROM context_preview WHERE id=$1", p.ID).Scan(&again); err != nil || !again.Equal(first) {
			t.Fatal("closure timestamp renewed", err)
		}
		if err := store.CreateContextPreview(ctx, p); !errors.Is(err, value.ErrChanged) {
			t.Fatal("uncertain create reopened closure", err)
		}
		if _, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a); !errors.Is(err, value.ErrChanged) {
			t.Fatal("cached plan bypassed closure", err)
		}
		noCapture(t, s)
	})
	t.Run("missing-review-fence-blocks-delayed-create-without-other-actor-effects", func(t *testing.T) {
		s, p := prepare(t)
		r := resolver(t, s)
		in := query(t, s, p)
		d, err := r.ResolveOrCloseContextRequest(ctx, in)
		if err != nil || d.State != value.RequestClosed {
			t.Fatal("missing close", err)
		}
		var start, end time.Time
		if err := admin.QueryRow(ctx, "SELECT created_at,expires_at FROM context_preview_fence WHERE root_id=$1 AND preview_id=$2", p.RootID, p.ID).Scan(&start, &end); err != nil || end.Sub(start) != 5*time.Minute {
			t.Fatal("unbounded missing fence", err)
		}
		if d, err = r.ResolveOrCloseContextRequest(ctx, in); err != nil || d.State != value.RequestClosed {
			t.Fatal("repeat missing close", err)
		}
		var later time.Time
		if err := admin.QueryRow(ctx, "SELECT expires_at FROM context_preview_fence WHERE root_id=$1 AND preview_id=$2", p.RootID, p.ID).Scan(&later); err != nil || !later.Equal(end) {
			t.Fatal("fence renewed", err)
		}
		if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); !errors.Is(err, value.ErrChanged) {
			t.Fatal("delayed create bypassed missing fence", err)
		}
		if _, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a); !errors.Is(err, value.ErrChanged) {
			t.Fatal("missing blueprint accepted", err)
		}
		noCapture(t, s)
	})
	t.Run("another-client-close-cannot-discover-or-close-original-preview", func(t *testing.T) {
		s, p := prepare(t)
		store := storeFor(t, s.a.RootID)
		if err := store.CreateContextPreview(ctx, p); err != nil {
			t.Fatal(err)
		}
		in := query(t, s, p)
		in.Identity.Principal.ClientID = "another-client"
		d, err := resolver(t, s).ResolveOrCloseContextRequest(ctx, in)
		if err != nil || d.State != value.RequestClosed || d.Accepted != nil {
			t.Fatal("foreign UUID leaked existence", err)
		}
		if _, err := store.ReadContextPreview(ctx, p.RootID, p.ID, p.Actor); err != nil {
			t.Fatal("foreign close changed owner preview", err)
		}
		if _, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a); err != nil {
			t.Fatal("actor-scoped fence denied original admission", err)
		}
	})
	t.Run("accepted-preview-wins-alternate-key-close-including-legacy-rows", func(t *testing.T) {
		for _, legacy := range []bool{false, true} {
			t.Run(fmt.Sprint(legacy), func(t *testing.T) {
				s, p := prepare(t)
				if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); err != nil {
					t.Fatal(err)
				}
				var a value.Accepted
				var err error
				if legacy {
					a, err = s.s.AdmitContext(ctx, s.a)
				} else {
					a, err = s.s.AdmitReviewedContext(ctx, p.ID, s.a)
				}
				if err != nil {
					t.Fatal(err)
				}
				in := query(t, s, p)
				in.IdempotencyKey = "alternate-resolution-key"
				in.Identity.Scopes = []string{"evidence:read"}
				d, err := resolver(t, s).ResolveOrCloseContextRequest(ctx, in)
				if err != nil || d.State != value.RequestAccepted || d.Accepted == nil || d.Accepted.CaptureID != a.CaptureID || d.Accepted.Expectation.Registration != a.Expectation.Registration {
					t.Fatal("accepted preview incorrectly closed", err)
				}
				var closed bool
				if err := admin.QueryRow(ctx, "SELECT closed_at IS NOT NULL FROM context_preview WHERE id=$1", p.ID).Scan(&closed); err != nil || closed {
					t.Fatal("accepted review marked closed", err)
				}
			})
		}
	})
	t.Run("concurrent-admission-and-close-have-one-serialized-outcome", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			s, p := prepare(t)
			if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); err != nil {
				t.Fatal(err)
			}
			r := resolver(t, s)
			in := query(t, s, p)
			start := make(chan struct{})
			accepted := make(chan error, 1)
			go func() { <-start; _, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a); accepted <- err }()
			close(start)
			d, err := r.ResolveOrCloseContextRequest(ctx, in)
			admitErr := <-accepted
			if err != nil {
				t.Fatal("resolution race unavailable", err)
			}
			switch d.State {
			case value.RequestClosed:
				if !errors.Is(admitErr, value.ErrChanged) {
					t.Fatal("late admission crossed close", admitErr)
				}
				noCapture(t, s)
			case value.RequestAccepted:
				if admitErr != nil || d.Accepted == nil || d.Accepted.CaptureID != p.CaptureID {
					t.Fatal("acceptance race lost original", admitErr)
				}
			default:
				t.Fatal("missing race disposition")
			}
		}
	})
	t.Run("negative-fences-share-human-preview-cap-across-clients", func(t *testing.T) {
		s, p := prepare(t)
		r := resolver(t, s)
		for i := 0; i < value.MaxPreviewsPerPrincipal; i++ {
			in := query(t, s, p)
			in.PreviewID = custodyID()
			in.SubmissionDigest = app.ContextRequestDigest(in.PreviewID)
			in.Identity.Principal.ClientID = fmt.Sprintf("client-%d", i%2)
			if d, err := r.ResolveOrCloseContextRequest(ctx, in); err != nil || d.State != value.RequestClosed {
				t.Fatal("bounded fence", i, err)
			}
		}
		d, err := r.ResolveOrCloseContextRequest(ctx, query(t, s, p))
		if !errors.Is(err, value.ErrCapacity) || d.State != "" {
			t.Fatal("exhaustion claimed terminal closure", err)
		}
		if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); !errors.Is(err, value.ErrCapacity) {
			t.Fatal("preview bypassed fence budget", err)
		}
		noCapture(t, s)
	})
	t.Run("closure-after-original-expiry-reclaims-without-reopening", func(t *testing.T) {
		s, p := prepare(t)
		p.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(300 * time.Millisecond)
		// Private preview validation binds its own scope checksum; this fixture only
		// exercises passive close/expiry, never submits the changed deadline as a plan.
		if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); err != nil {
			t.Fatal(err)
		}
		r := resolver(t, s)
		if d, err := r.ResolveOrCloseContextRequest(ctx, query(t, s, p)); err != nil || d.State != value.RequestClosed {
			t.Fatal(err)
		}
		time.Sleep(time.Until(p.Deadline) + 10*time.Millisecond)
		if _, err := pool.Exec(ctx, "DELETE FROM context_preview WHERE id=$1", p.ID); err != nil {
			t.Fatal("expired close cleanup failed", err)
		}
		if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); !errors.Is(err, value.ErrChanged) {
			t.Fatal("expired original create reopened", err)
		}
		noCapture(t, s)
	})
	t.Run("revoked-target-rights-allow-own-passive-close-but-hide-accepted-work", func(t *testing.T) {
		for _, accepted := range []bool{false, true} {
			t.Run(fmt.Sprint(accepted), func(t *testing.T) {
				s, p := prepare(t)
				if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); err != nil {
					t.Fatal(err)
				}
				if accepted {
					if _, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a); err != nil {
						t.Fatal(err)
					}
				}
				batch := s.batch
				batch.Initial = nil
				batch.RequestID, batch.InputDigest = custodyID(), artifact.Digest{99}
				batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
				batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
				deny := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "deny-1", SpecDigest: artifact.Digest{98}}, Scope: batch.Bases[0].Scope, Effect: "Deny", Subjects: []cfg.Subject{{Kind: "User", Issuer: p.Actor.Issuer, ID: p.Actor.Subject}}, Roles: []string{"workload-maintainer", "evidence-reader"}}
				deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
				batch.Bases = append(append([]cfg.PermissionBasis{}, batch.Bases...), deny)
				if _, err := s.p.AcceptPermissions(ctx, batch); err != nil {
					t.Fatal(err)
				}
				in := query(t, s, p)
				in.Identity.Scopes = []string{"evidence:read"}
				d, err := resolver(t, s).ResolveOrCloseContextRequest(ctx, in)
				if accepted {
					if !errors.Is(err, value.ErrDenied) || d.State != "" {
						t.Fatal("unreadable acceptance reported closed or leaked", err)
					}
				} else if err != nil || d.State != value.RequestClosed {
					t.Fatal("revocation blocks own negative closure", err)
				}
			})
		}
	})

	t.Run("resolution-role-cannot-rewrite-identity-or-admit-work", func(t *testing.T) {
		s, p := prepare(t)
		if err := storeFor(t, s.a.RootID).CreateContextPreview(ctx, p); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			"INSERT INTO context_capture DEFAULT VALUES",
			"UPDATE context_capture SET preview_id=NULL",
			"UPDATE context_preview SET deadline=deadline+interval '1 second'",
			"UPDATE custody_allocation SET charged_objects=0",
			"UPDATE permission_stream SET suspended=false",
			"SELECT guard_context_preview_fence()",
		} {
			_, err := pool.Exec(ctx, sql)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "42501" {
				t.Fatal("expected actual permission denial", sql, err)
			}
		}
		if _, err := pool.Exec(ctx, "DELETE FROM context_preview WHERE id=$1", p.ID); err == nil {
			t.Fatal("resolver deleted live preview")
		}
		if d, err := resolver(t, s).ResolveOrCloseContextRequest(ctx, query(t, s, p)); err != nil || d.State != value.RequestClosed {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "UPDATE context_preview SET closed_at=NULL,closed_request_key=NULL,closed_submission_digest=NULL WHERE id=$1", p.ID); err == nil {
			t.Fatal("resolution credential reopened preview")
		}
	})
	t.Run("resolution-lock-wait-cannot-extend-caller-deadline", func(t *testing.T) {
		s, p := prepare(t)
		r := resolver(t, s)
		in := query(t, s, p)
		in.Identity.ValidUntil = time.Now().Add(100 * time.Millisecond)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := r.ResolveOrCloseContextRequest(ctx, in); done <- err }()
		time.Sleep(200 * time.Millisecond)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; !errors.Is(err, value.ErrDenied) {
			t.Fatal("expired closure crossed lock", err)
		}
		var n int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_preview_fence WHERE root_id=$1", s.a.RootID).Scan(&n); err != nil || n != 0 {
			t.Fatal("expired authority committed fence", n, err)
		}
	})
}
