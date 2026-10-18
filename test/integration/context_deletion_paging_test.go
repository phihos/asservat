package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is real PostgreSQL scheduling qualification with synthetic temporary
// rows, not an authority or writer-completion fixture. The dedicated connection
// shadows only the two read-only scheduling relations. The full deletion case
// separately verifies actual writer proofs, role grants, purge and finalization.
func qualifyContextDeletionPaging(t *testing.T, ctx context.Context, source *pgxpool.Pool, root, installation string) {
	t.Helper()
	config := source.Config()
	config.MaxConns, config.MinConns = 1, 0
	config.MaxConnLifetime, config.MaxConnIdleTime = 0, 0
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	// Close before later native suites; temporary relations and their connection
	// cannot escape this helper, even when an assertion stops it.
	defer pool.Close()
	ledger, err := postgres.NewContextDeletions(ctx, pool, root, installation)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`CREATE TEMP TABLE custody_attempt (cluster_id uuid NOT NULL, artifact_id uuid NOT NULL, id uuid PRIMARY KEY, effective_expires_at timestamptz NOT NULL, state text NOT NULL, lease_until timestamptz)`,
		`CREATE TEMP TABLE context_writer_completion (root_id uuid NOT NULL, attempt_id uuid PRIMARY KEY)`,
	} {
		if _, err = pool.Exec(ctx, query); err != nil {
			t.Fatal("temporary scheduling fixture", err)
		}
	}
	var now time.Time
	if err = pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	cutoff := now.UTC().Truncate(time.Microsecond).Add(-time.Hour)
	add := func(scope, state string, expires time.Time, lease any, completed bool) artifact.Location {
		t.Helper()
		loc := artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}
		if _, err := pool.Exec(ctx, `INSERT INTO custody_attempt(cluster_id,artifact_id,id,effective_expires_at,state,lease_until) VALUES($1,$2,$3,$4,$5,$6)`, loc.ClusterID, loc.ArtifactID, loc.AttemptID, expires, state, lease); err != nil {
			t.Fatal(err)
		}
		if completed {
			if _, err := pool.Exec(ctx, `INSERT INTO context_writer_completion(root_id,attempt_id) VALUES($1,$2)`, scope, loc.AttemptID); err != nil {
				t.Fatal(err)
			}
		}
		return loc
	}
	var failed []artifact.Location
	for range 16 {
		failed = append(failed, add(root, "deleting", cutoff, cutoff, true))
	}
	healthy := add(root, "stored_unpublished", cutoff.Add(time.Second), nil, true)
	pendingAudit := add(root, "deleting", cutoff.Add(2*time.Second), cutoff, true)
	add(root, "deleting", cutoff, now.Add(time.Hour), true)
	add(custodyID(), "stored_unpublished", cutoff, nil, true)
	add(root, "stored_unpublished", cutoff, nil, false)
	add(root, "deleted", cutoff, nil, true)
	add(root, "stored_unpublished", now.Add(time.Hour), nil, true)

	first, err := ledger.DueContextDeletionPage(ctx, postgres.ContextDeletionCursor{})
	if err != nil || !slices.Equal(first.Locations, failed) || first.Next.Through.IsZero() || first.Next.AfterAttemptID != failed[15].AttemptID {
		t.Fatal("oldest bounded failure page differs", first, err)
	}
	// Keep all sixteen failures unchanged. A successful page read must progress
	// past them even though no deletion/acknowledgement succeeded. A newly due
	// row belongs to the next pass, not an ever-growing current pass.
	arrival := add(root, "stored_unpublished", first.Next.Through.Add(time.Microsecond), nil, true)
	second, err := ledger.DueContextDeletionPage(ctx, first.Next)
	if err != nil || !slices.Equal(second.Locations, []artifact.Location{healthy, pendingAudit}) || second.Next != (postgres.ContextDeletionCursor{}) {
		t.Fatal("persistent failed prefix hid later due attempts or renewed pass cutoff", second, err)
	}
	again, err := ledger.DueContextDeletionPage(ctx, second.Next)
	if err != nil || !slices.Equal(again.Locations, failed) || again.Next.Through.Before(first.Next.Through) {
		t.Fatal("wrapped pass lost failed obligations", again, err)
	}
	later, err := ledger.DueContextDeletionPage(ctx, again.Next)
	if err != nil || !slices.Equal(later.Locations, []artifact.Location{healthy, pendingAudit, arrival}) || later.Next != (postgres.ContextDeletionCursor{}) {
		t.Fatal("new pass did not include the later arrival", later, err)
	}
	compatible, err := ledger.DueContextDeletions(ctx)
	if err != nil || !slices.Equal(compatible, failed) {
		t.Fatal("compatibility interface changed its first-page bound", compatible, err)
	}
	// Ending exactly on a full page wraps after an empty read; the cursor is not
	// a replacement lease and cannot make an attempt with a live lease due.
	if _, err = pool.Exec(ctx, `UPDATE custody_attempt SET lease_until=clock_timestamp()+interval '1 hour' WHERE id=ANY($1::uuid[])`, []string{healthy.AttemptID, pendingAudit.AttemptID, arrival.AttemptID}); err != nil {
		t.Fatal(err)
	}
	empty, err := ledger.DueContextDeletionPage(ctx, again.Next)
	if err != nil || len(empty.Locations) != 0 || empty.Next != (postgres.ContextDeletionCursor{}) {
		t.Fatal("empty tail failed to wrap or a cursor bypassed a live lease", empty, err)
	}
}
