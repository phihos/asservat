package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

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
