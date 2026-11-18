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
	 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.request_id::text, 42)); RETURN NEW; END $$;
	 CREATE TRIGGER pause_permission_publication BEFORE INSERT ON permission_acceptance
	 FOR EACH ROW EXECUTE FUNCTION pause_permission_publication()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP TRIGGER pause_permission_publication ON permission_acceptance; DROP FUNCTION pause_permission_publication()"); err != nil {
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
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		var staged bool
		if err = admin.QueryRow(wait, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))", blocker).Scan(&staged); err != nil {
			t.Fatal("waiting for staged permission event", err)
		}
		if staged {
			break
		}
		select {
		case err = <-done:
			t.Fatalf("writer finished before operation: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
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
