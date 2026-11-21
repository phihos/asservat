package integration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	configapp "asservat.local/asservat/internal/application/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Hold one writer after staging the new assignments and audit header. The
// committed healthy peer must still be usable through its real operation fence.
func withStagedPeerPermission(t *testing.T, ctx context.Context, admin *pgxpool.Pool, s captureAdmissionScenario, wantPublication error, action func() error) {
	t.Helper()
	b := s.batch
	b.Bases = slices.Clone(b.Bases)
	for i := range b.Bases {
		b.Bases[i].Continuous = true
	}
	peer := b.Bases[0]
	peer.Resource.UID, peer.Scope.ClusterID = custodyID(), custodyID()
	peer.ScopeDigest = configapp.PermissionScopeDigest(peer)
	b.Bases = append(b.Bases, peer)
	b.InputDigest[0]++
	b.RequestID = custodyID()
	b.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	b.FreshUntil = b.ObservedAt.Add(30 * time.Second)
	if _, err := admin.Exec(ctx, `CREATE FUNCTION pause_permission_publication() RETURNS trigger
	 LANGUAGE plpgsql SET lock_timeout='0' AS $$ BEGIN
	 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.id::text, 42)); RETURN NEW; END $$;
	 CREATE TRIGGER pause_permission_publication AFTER INSERT ON authority_audit
	 FOR EACH ROW WHEN (NEW.event_kind='permission-change') EXECUTE FUNCTION pause_permission_publication()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP TRIGGER pause_permission_publication ON authority_audit; DROP FUNCTION pause_permission_publication()"); err != nil {
			t.Error(err)
		}
	}()
	barrier, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Rollback(ctx)
	var blocker int
	if err = barrier.QueryRow(ctx, "SELECT pg_backend_pid() FROM pg_advisory_xact_lock(hashtextextended($1,42))", b.RequestID).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.p.AcceptPermissions(ctx, b)
		done <- err
	}()
	waitForSQLBlocker(t, ctx, admin, blocker)
	if err = action(); err != nil {
		t.Error("healthy peer operation while permission event is staged", err)
	}
	if err = barrier.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, wantPublication) {
		t.Fatal("publish permission event", err)
	}
}

// Return the backend held behind this fixture barrier.
func waitForSQLBlocker(t *testing.T, ctx context.Context, admin *pgxpool.Pool, blocker int) int {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		var pid int
		if err := admin.QueryRow(wait, "SELECT coalesce(min(pid),0) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))", blocker).Scan(&pid); err != nil {
			t.Fatal("waiting for blocked transaction", err)
		}
		if pid != 0 {
			return pid
		}
		time.Sleep(5 * time.Millisecond)
	}
}
