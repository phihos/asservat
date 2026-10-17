package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the fixture administrator models an old immutable acknowledgement.
// Compare database-rendered complete row bytes before/after each reader, then
// restore and read back the exact original row before positive requalification.
func withHistoricalAuthorityVersion(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, event, version string, deny func()) {
	t.Helper()
	const read = "SELECT object_version, row_to_json(a)::text FROM authority_audit a WHERE stream_id=$1 AND id=$2"
	var originalVersion, original string
	if err := admin.QueryRow(ctx, read, root, event).Scan(&originalVersion, &original); err != nil || originalVersion == "" || originalVersion == "null" {
		t.Fatal("original acknowledged authority receipt unavailable", err)
	}
	set := func(call context.Context, value string) error {
		tx, err := admin.Begin(call)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(call, "SET LOCAL session_replication_role=replica"); err != nil {
			return err
		}
		changed, err := tx.Exec(call, "UPDATE authority_audit SET object_version=$3 WHERE stream_id=$1 AND id=$2", root, event, value)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return errors.New("authority history fixture row mismatch")
		}
		return tx.Commit(call)
	}
	defer func() {
		call, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if err := set(call, originalVersion); err != nil {
			t.Error("restore original authority receipt", err)
			return
		}
		var restoredVersion, restored string
		if err := admin.QueryRow(call, read, root, event).Scan(&restoredVersion, &restored); err != nil || restoredVersion != originalVersion || restored != original {
			t.Error("restored authority history differs", err)
		}
	}()
	if err := set(ctx, version); err != nil {
		t.Fatal(err)
	}
	var storedVersion, stored string
	if err := admin.QueryRow(ctx, read, root, event).Scan(&storedVersion, &stored); err != nil || storedVersion != version {
		t.Fatal("stored authority history does not match intended version", err)
	}
	deny()
	var afterVersion, after string
	if err := admin.QueryRow(ctx, read, root, event).Scan(&afterVersion, &after); err != nil || afterVersion != storedVersion || after != stored {
		t.Fatal("current authority read rewrote stored history", err)
	}
}

// A retained audit from another root must not disappear from the assignment
// LEFT JOIN and thereby hide a Deny. Only the fixture administrator can model
// this historical corruption; every original row field is restored exactly.
func withHistoricalAuthorityRoot(t *testing.T, ctx context.Context, admin *pgxpool.Pool, event, root, foreign string, deny func()) {
	t.Helper()
	const read = "SELECT stream_id::text, row_to_json(a)::text FROM authority_audit a WHERE id=$1"
	var originalRoot, original string
	if err := admin.QueryRow(ctx, read, event).Scan(&originalRoot, &original); err != nil || originalRoot != root || root == foreign {
		t.Fatal("original authority history scope unavailable", err)
	}
	set := func(call context.Context, value string) error {
		tx, err := admin.Begin(call)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(call, "SET LOCAL session_replication_role=replica"); err != nil {
			return err
		}
		changed, err := tx.Exec(call, "UPDATE authority_audit SET stream_id=$2 WHERE id=$1", event, value)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return errors.New("authority scope fixture row mismatch")
		}
		return tx.Commit(call)
	}
	defer func() {
		call, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if err := set(call, root); err != nil {
			t.Error("restore original authority root", err)
			return
		}
		var restoredRoot, restored string
		if err := admin.QueryRow(call, read, event).Scan(&restoredRoot, &restored); err != nil || restoredRoot != root || restored != original {
			t.Error("restored authority root changed historical row", err)
		}
	}()
	if err := set(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	var storedRoot, stored string
	if err := admin.QueryRow(ctx, read, event).Scan(&storedRoot, &stored); err != nil || storedRoot != foreign {
		t.Fatal("foreign authority history scope not stored", err)
	}
	deny()
	var afterRoot, after string
	if err := admin.QueryRow(ctx, read, event).Scan(&afterRoot, &after); err != nil || afterRoot != foreign || after != stored {
		t.Fatal("current check rewrote foreign-root history", err)
	}
}
