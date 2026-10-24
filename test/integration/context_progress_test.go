package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func progressQuery(t *testing.T, ctx context.Context, s captureAdmissionScenario) capture.ProgressQuery {
	t.Helper()
	r, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	i := s.a.Eligibility.VerifiedIdentity
	i.Scopes = []string{"evidence:read"}
	i.VerifiedAt = time.Now().UTC()
	i.ValidUntil = i.VerifiedAt.Add(5 * time.Second)
	return capture.ProgressQuery{RootID: s.a.RootID, CaptureID: s.a.Plan.Input.CaptureID, Identity: i, Recovery: r}
}
func qualifyContextProgress(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Helper()
	readPool := poolFor("context_progress_read_runtime", "synthetic-context-progress-read")
	defer readPool.Close()
	deadlinePool := poolFor("context_deadline_runtime", "synthetic-context-deadline")
	defer deadlinePool.Close()
	// ADR-223: installed, the hub-worker's cleaner login observes deadlines.
	cleanupPool := poolFor("context_cleanup_runtime", "synthetic-context-cleanup")
	defer cleanupPool.Close()
	reader := func(t *testing.T, s captureAdmissionScenario) *postgres.ContextProgressReads {
		t.Helper()
		r, err := postgres.NewContextProgressReads(ctx, readPool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	observer := func(t *testing.T, s captureAdmissionScenario) *postgres.ContextDeadlines {
		t.Helper()
		r, err := postgres.NewContextDeadlineObserver(ctx, deadlinePool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	installedObserver := func(t *testing.T, s captureAdmissionScenario) *postgres.ContextDeadlines {
		t.Helper()
		r, err := postgres.NewContextDeadlineObserver(ctx, cleanupPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	t.Run("progress-roles-cannot-mutate-lifecycle-or-privileged-function", func(t *testing.T) {
		for _, p := range []*pgxpool.Pool{readPool, deadlinePool} {
			for _, sql := range []string{"UPDATE context_capture SET progress_revision=progress_revision", "UPDATE context_capture SET deadline=deadline", "UPDATE context_capture SET state=state", "UPDATE custody_attempt SET state=state", "INSERT INTO context_catalog(artifact_id,capture_id,root_id) SELECT id,id,root_id FROM context_capture LIMIT 0", "SELECT advance_context_progress()"} {
				_, err := p.Exec(ctx, sql)
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Fatalf("expected privilege denial for %s: %v", sql, err)
				}
			}
		}
		var pinned, private bool
		if err := admin.QueryRow(ctx, "SELECT proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[], NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc WHERE oid='advance_context_progress()'::regprocedure").Scan(&pinned, &private); err != nil || !pinned || !private {
			t.Fatal("unsafe trigger function configuration", pinned, private, err)
		}
	})
	t.Run("api-only-admission-preserves-class-and-original-replay", func(t *testing.T) {
		s := create(t, 1)
		in := s.a.Plan.Input
		in.Target.ExecutionClass = artifact.ContextAPIExecution
		in.Capability.ExecutionClass = artifact.ContextAPIExecution
		in.Target.NodeUID = ""
		in.Target.NodeBootID = ""
		in.Target.Pin.NodeName = ""
		var err error
		s.a.Plan, err = planning.CompileContext(in, s.a.Plan.CompiledAt)
		if err != nil {
			t.Fatal(err)
		}
		first, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		if first.MetadataValidUntil.IsZero() || replay.MetadataValidUntil.IsZero() || replay.MetadataValidUntil.After(s.a.Eligibility.ValidUntil) || replay.MetadataValidUntil.After(s.a.Recovery.FreshUntil) {
			t.Fatal("replay metadata authority was renewed")
		}
		if first.Expectation.ExecutionClass != artifact.ContextAPIExecution || first.Expectation.NodeUID != "" || first.Expectation.NodeBootID != "" || first.Pin.NodeName != "" || replay.Expectation.ExecutionClass != artifact.ContextAPIExecution || !replay.Replay || replay.CaptureID != first.CaptureID {
			t.Fatal("API identity/replay not preserved")
		}
	})
	t.Run("progress-current-access-does-not-follow-shares-or-admission", func(t *testing.T) {
		s := create(t, 1)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		r := reader(t, s)
		for _, name := range []string{"requester", "requester-other-client", "requester-reader", "foreign-maintainer", "foreign-reader", "no-assignment", "no-scope", "absent"} {
			q := progressQuery(t, ctx, s)
			want := true
			switch name {
			case "requester-other-client":
				q.Identity.Principal.ClientID = "mcp"
			case "requester-reader":
				q.Identity.Groups = []string{"other-owners"}
			case "foreign-maintainer":
				q.Identity.Principal.Subject = "other-maintainer"
			case "foreign-reader":
				q.Identity.Principal.Subject = "other-owner"
				q.Identity.Groups = []string{"other-owners"}
				want = false
			case "no-assignment":
				q.Identity.Groups = nil
				want = false
			case "no-scope":
				q.Identity.Scopes = []string{"evidence:capture"}
				want = false
			case "absent":
				q.CaptureID = custodyID()
				want = false
			}
			got, err := r.ReadContextProgress(ctx, q)
			if want {
				if err != nil || got.Revision != 1 || got.Phase != "Pending" || got.ReasonCode != "IntentAuditPending" {
					t.Fatalf("%s: %+v %v", name, got, err)
				}
			} else if !errors.Is(err, capture.ErrDenied) || got.CaptureID != "" {
				t.Fatalf("%s: unauthorized metadata: %+v %v", name, got, err)
			}
		}
		if _, err := admin.Exec(ctx, "UPDATE permission_stream SET suspended=true WHERE id=$1", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		if got, err := r.ReadContextProgress(ctx, progressQuery(t, ctx, s)); !errors.Is(err, capture.ErrDenied) || got.CaptureID != "" {
			t.Fatal("current revoked source returned progress", got, err)
		}
	})
	t.Run("progress-does-not-renew-identity-after-blocking-lock", func(t *testing.T) {
		s := create(t, 1)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		r := reader(t, s)
		q := progressQuery(t, ctx, s)
		q.Identity.ValidUntil = q.Identity.VerifiedAt.Add(150 * time.Millisecond)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			got, err := r.ReadContextProgress(ctx, q)
			if got.CaptureID != "" {
				err = errors.New("expired identity exposed capture metadata")
			}
			done <- err
		}()
		time.Sleep(time.Until(q.Identity.ValidUntil.Add(20 * time.Millisecond)))
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; !errors.Is(err, capture.ErrDenied) {
			t.Fatal("blocked read renewed original identity", err)
		}
	})
	t.Run("overdue-observation-is-durable-once-and-never-refunds", func(t *testing.T) {
		s := create(t, 1)
		in := s.a.Plan.Input
		in.Deadline = time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
		var err error
		s.a.Plan, err = planning.CompileContext(in, s.a.Plan.CompiledAt)
		if err != nil {
			t.Fatal(err)
		}
		s.a.Registration.WriteUntil = in.Deadline
		if _, err = s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		r := reader(t, s)
		o := observer(t, s)
		if count, err := o.ObserveOverdueContextCaptures(ctx, 16); err != nil || count != 0 {
			t.Fatal("deadline observed early", count, err)
		}
		time.Sleep(time.Until(in.Deadline.Add(20 * time.Millisecond)))
		before, err := r.ReadContextProgress(ctx, progressQuery(t, ctx, s))
		if err != nil || before.Revision != 1 || before.Phase != "Pending" {
			t.Fatal("clock fabricated a revision/phase", before, err)
		}
		var wg sync.WaitGroup
		counts := make(chan int64, 4)
		errs := make(chan error, 4)
		installed := installedObserver(t, s)
		for i := range 4 {
			wg.Add(1)
			x := o
			if i%2 == 1 {
				x = installed
			}
			go func() { defer wg.Done(); n, e := x.ObserveOverdueContextCaptures(ctx, 16); counts <- n; errs <- e }()
		}
		wg.Wait()
		close(counts)
		close(errs)
		total := int64(0)
		for n := range counts {
			total += n
		}
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		if total != 1 {
			t.Fatal("repeated deadline transition", total)
		}
		got, err := r.ReadContextProgress(ctx, progressQuery(t, ctx, s))
		if err != nil || got.Revision != 2 || got.Phase != "Indeterminate" || got.ReasonCode != "DeadlineOutcomeUnconfirmed" {
			t.Fatal("missing durable uncertainty", got, err)
		}
		var charged int64
		if err = admin.QueryRow(ctx, "SELECT charged_objects FROM custody_allocation WHERE id=$1", s.a.Registration.AllocationID).Scan(&charged); err != nil || charged != 4 {
			t.Fatal("uncertainty refunded capacity", charged, err)
		}
		for _, sql := range []string{"UPDATE context_capture SET deadline_observed_at=NULL WHERE root_id=$1", "UPDATE context_capture SET deadline_observed_at=clock_timestamp() WHERE root_id=$1"} {
			for _, p := range []*pgxpool.Pool{deadlinePool, cleanupPool} {
				if _, err = p.Exec(ctx, sql, s.a.RootID); err == nil {
					t.Fatal("deadline observer rewrote history")
				}
			}
		}
	})
	t.Run("revision-overflow-does-not-block-retention-or-deletion", func(t *testing.T) {
		s := create(t, 1)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		// Fixture administrator seeds only the unreachable-in-test counter boundary.
		// Runtime roles cannot disable triggers or set this value directly.
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SET LOCAL session_replication_role=replica"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "UPDATE context_capture SET progress_revision=1000000000 WHERE id=$1", s.a.Plan.Input.CaptureID); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		retentionPool := poolFor("retention_runtime", "synthetic-retention")
		t.Cleanup(retentionPool.Close)
		retention, err := postgres.NewRetention(ctx, retentionPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		d := retentionTestDecision(t, ctx, retention, s.a.Registration.Location, s.a.Registration.ExpiresAt.Add(-time.Second), s.a.Registration.DeleteBy.Add(-time.Second))
		if err = retention.TightenRetention(ctx, d); err != nil {
			t.Fatal("overflow blocked restrictive retention", err)
		}
		if got, err := reader(t, s).ReadContextProgress(ctx, progressQuery(t, ctx, s)); !errors.Is(err, capture.ErrUnavailable) || got.CaptureID != "" {
			t.Fatal("overflow exposed invalid public revision", got, err)
		}
		if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET state='deleted',deleted_at=clock_timestamp() WHERE id=$1", s.a.Registration.Location.AttemptID); err != nil {
			t.Fatal("overflow blocked deletion transition", err)
		}
		var rev int64
		if err = admin.QueryRow(ctx, "SELECT progress_revision FROM context_capture WHERE id=$1", s.a.Plan.Input.CaptureID).Scan(&rev); err != nil || rev != 1000000001 {
			t.Fatal("overflow sentinel unstable", rev, err)
		}
	})
}
