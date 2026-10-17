package integration

import (
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

// Fixture administration models retained legacy data only. Exact row readback
// proves denial and restoration did not rewrite any other immutable provenance.
func withBootstrapAuditVersion(t *testing.T, ctx context.Context, admin *pgxpool.Pool, kind, root, id, version string, deny func()) {
	t.Helper()
	var read, update string
	switch kind {
	case "intent":
		read = "SELECT audit_object_version,to_jsonb(c)::text FROM fleet_bootstrap_intent c WHERE installation_id=$1 AND id=$2"
		update = "UPDATE fleet_bootstrap_intent SET audit_object_version=$3 WHERE installation_id=$1 AND id=$2"
	case "issued":
		read = "SELECT issue_audit_version,to_jsonb(v)::text FROM fleet_bootstrap v WHERE installation_id=$1 AND id=$2"
		update = "UPDATE fleet_bootstrap SET issue_audit_version=$3 WHERE installation_id=$1 AND id=$2"
	default:
		t.Fatal("unknown fixture receipt family")
	}
	var original string
	var before []byte
	if e := admin.QueryRow(ctx, read, root, id).Scan(&original, &before); e != nil || original == "" || original == "null" {
		t.Fatal("original versioned bootstrap", e)
	}
	set := func(call context.Context, v string) error {
		tx, e := admin.Begin(call)
		if e != nil {
			return e
		}
		defer tx.Rollback(context.Background())
		if _, e = tx.Exec(call, "SET LOCAL session_replication_role=replica"); e != nil {
			return e
		}
		n, e := tx.Exec(call, update, root, id, v)
		if e != nil {
			return e
		}
		if n.RowsAffected() != 1 {
			return errors.New("historical bootstrap fixture row mismatch")
		}
		return tx.Commit(call)
	}
	defer func() {
		call, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if e := set(call, original); e != nil {
			t.Error("restore bootstrap receipt", e)
			return
		}
		var version string
		var restored []byte
		if e := admin.QueryRow(call, read, root, id).Scan(&version, &restored); e != nil || version != original || !bytes.Equal(restored, before) {
			t.Error("restored bootstrap differs from original row", e)
		}
	}()
	if e := set(ctx, version); e != nil {
		t.Fatal(e)
	}
	var storedVersion string
	var stored []byte
	if e := admin.QueryRow(ctx, read, root, id).Scan(&storedVersion, &stored); e != nil || storedVersion != version {
		t.Fatal("stored historical receipt", e)
	}
	deny()
	var after []byte
	if e := admin.QueryRow(ctx, read, root, id).Scan(&storedVersion, &after); e != nil || storedVersion != version || !bytes.Equal(after, stored) {
		t.Fatal("current denial rewrote historical row", e)
	}
}
