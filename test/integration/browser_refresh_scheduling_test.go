package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual fixture SQL/role/lock qualification; synthetic opaque credentials are
// deliberate. This is not a provider refresh or native-content assertion.
func browserRefreshScheduleSQL(t *testing.T, admin *pgxpool.Pool, store *postgres.BrowserSessions, root, issuer, client string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := identity.BrowserSession{ID: sha256.Sum256([]byte("synthetic-short-refresh-schedule")), Principal: identity.Principal{Issuer: issuer, ClientID: client, Subject: "short-refresh-schedule-subject", Kind: identity.Human}, ProviderSession: "short-refresh-schedule-provider", Ciphertext: []byte("synthetic-opaque-schedule"), CreatedAt: now, AuthenticatedAt: now, ExpiresAt: now.Add(time.Hour), RefreshAt: now.Add(time.Minute), Version: 1}
	created, err := store.CreateSession(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if e := store.RevokeSession(cleanup, r.ID); e != nil {
			t.Error("fixture session cleanup", e)
		}
	}()
	claim := [32]byte{94}
	if err = store.ClaimRefresh(ctx, r.ID, 1, claim); err != nil {
		t.Fatal(err)
	}
	var claimUntil time.Time
	if err = admin.QueryRow(ctx, "SELECT claim_until FROM browser_session WHERE root_id=$1 AND id=$2", root, r.ID[:]).Scan(&claimUntil); err != nil {
		t.Fatal(err)
	}
	if !claimUntil.After(now) || claimUntil.After(time.Now().Add(10*time.Second)) || claimUntil.After(created.ExpiresAt) {
		t.Fatal("original claim bound invalid")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var blockerPID int32
	if err = tx.QueryRow(ctx, "SELECT pg_backend_pid() FROM browser_session WHERE root_id=$1 AND id=$2 FOR UPDATE", root, r.ID[:]).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().Add(time.Microsecond)
	replacement := []byte("synthetic-already-due-result")
	done := make(chan error, 1)
	go func() { done <- store.FinishRefresh(ctx, r.ID, 1, claim, replacement, due) }()
	// Do not assume a sleep proves lock contention: observe the actual backend.
	observed := false
	for !observed {
		select {
		case err = <-done:
			t.Fatalf("FinishRefresh returned before held lock: %v", err)
		default:
		}
		if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", blockerPID).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if !observed {
			select {
			case <-ctx.Done():
				t.Fatal("FinishRefresh never observed waiting", ctx.Err())
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	var pastDue bool
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()>$1", due).Scan(&pastDue); err != nil || !pastDue {
		t.Fatal("test did not cross due time during SQL wait", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal("still-valid replacement failed because its schedule became due", err)
	}
	current, err := store.ReadSession(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 2 || !current.ExpiresAt.Equal(created.ExpiresAt) || !current.RefreshAt.Equal(due.Truncate(time.Microsecond)) || !bytes.Equal(current.Ciphertext, replacement) {
		t.Fatal("replacement changed original lifetime or schedule")
	}
	var consumed bool
	if err = admin.QueryRow(ctx, "SELECT refresh_claim IS NULL AND claim_until IS NULL FROM browser_session WHERE root_id=$1 AND id=$2", root, r.ID[:]).Scan(&consumed); err != nil || !consumed {
		t.Fatal("refresh claim not consumed", err)
	}
	if err = store.FinishRefresh(ctx, r.ID, 1, claim, replacement, due); !errors.Is(err, identity.ErrDenied) {
		t.Fatal("stale credential claim replay accepted", err)
	}
}
