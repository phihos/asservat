package integration

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyObservationPoolDowngradeRefusal(t *testing.T, ctx context.Context, admin *pgxpool.Pool, grantID string) {
	t.Helper()
	raw, err := fs.ReadFile(migrations.Files(), "00128_syscall_observation_events.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("missing downgrade")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, down)
	_ = tx.Rollback(ctx)
	if err == nil || !strings.Contains(err.Error(), "retained syscall observation event spend") {
		t.Fatal("event history downgrade", err)
	}
	var spent int64
	if err = admin.QueryRow(ctx, "SELECT events_spent FROM adhoc_observation_spend WHERE grant_id=$1", grantID).Scan(&spent); err != nil || spent != 10 {
		t.Fatal("downgrade changed history", spent, err)
	}
}

func qualifyObservationPoolLockExpiry(t *testing.T, ctx context.Context, admin, caller *pgxpool.Pool, rootID, grantID string, expires time.Time) {
	t.Helper()
	var ok bool
	if err := caller.QueryRow(ctx, "SELECT spend_adhoc_observation($1,$2,1,1)", rootID, grantID).Scan(&ok); err != nil || !ok {
		t.Fatal("initial event debit", ok, err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT spent FROM adhoc_observation_spend WHERE root_id=$1 AND grant_id=$2 FOR UPDATE", rootID, grantID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		ok  bool
		err error
	}
	done := make(chan result, 1)
	go func() {
		var accepted bool
		err := caller.QueryRow(ctx, "SELECT spend_adhoc_observation($1,$2,1,1)", rootID, grantID).Scan(&accepted)
		done <- result{accepted, err}
	}()
	// Observe the actual blocked SQL statement before letting wall time expire.
	blocked := false
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE 'SELECT spend_adhoc_observation%' AND wait_event_type='Lock')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("debit did not wait for the retained pool lock")
	}
	if delay := time.Until(expires.Add(20 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.ok {
			t.Fatal("expired grant spent after lock", got)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked debit did not join")
	}
	var bytes, events int64
	if err = admin.QueryRow(ctx, "SELECT spent,events_spent FROM adhoc_observation_spend WHERE root_id=$1 AND grant_id=$2", rootID, grantID).Scan(&bytes, &events); err != nil || bytes != 1 || events != 1 {
		t.Fatal("expired wait changed spend", bytes, events, err)
	}
}
