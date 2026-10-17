package integration

import (
	"asservat.local/asservat/internal/adapters/postgres"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

// This runs after actual provider signing, encrypted S3 audit and SQL activation.
// Only fixture administration models legacy persisted version columns. Runtime
// roles cannot alter them, and each original value is restored exactly.
func qualifyConnectorHistoricalVersions(t *testing.T, ctx context.Context, admin *pgxpool.Pool, signing *postgres.EnrollmentSigning, activation *postgres.EnrollmentActivation, claim value.EnrollmentClaim) {
	t.Helper()
	original, err := signing.PrepareConnector(ctx, claim)
	if err != nil || original.Signed == nil || !original.Active {
		t.Fatal("original connector activation", err)
	}
	for _, kind := range []string{"claim", "certificate"} {
		for _, version := range []string{"", "null"} {
			name := version
			if name == "" {
				name = "empty"
			}
			t.Run("connector-retained-"+kind+"-"+name, func(t *testing.T) {
				var read, update string
				var key string
				if kind == "claim" {
					read = "SELECT claim_object_version FROM fleet_bootstrap WHERE id=$1"
					update = "UPDATE fleet_bootstrap SET claim_object_version=$2 WHERE id=$1"
					key = claim.BootstrapID
				} else {
					read = "SELECT audit_object_version FROM fleet_certificate_issue WHERE id=$1"
					update = "UPDATE fleet_certificate_issue SET audit_object_version=$2 WHERE id=$1"
					key = original.Attempt.ID
				}
				var previous string
				if err := admin.QueryRow(ctx, read, key).Scan(&previous); err != nil || previous == "" || previous == "null" {
					t.Fatal("original connector version", err)
				}
				set := func(call context.Context, v string) error {
					tx, err := admin.Begin(call)
					if err != nil {
						return err
					}
					defer tx.Rollback(context.Background())
					if _, err = tx.Exec(call, "SET LOCAL session_replication_role=replica"); err != nil {
						return err
					}
					changed, err := tx.Exec(call, update, key, v)
					if err != nil {
						return err
					}
					if changed.RowsAffected() != 1 {
						return errors.New("original connector row mismatch")
					}
					return tx.Commit(call)
				}
				defer func() {
					call, end := context.WithTimeout(context.Background(), 5*time.Second)
					defer end()
					if err := set(call, previous); err != nil {
						t.Error("restore connector version", err)
					}
				}()
				if err := set(ctx, version); err != nil {
					t.Fatal(err)
				}
				if kind == "claim" {
					if _, err := signing.PrepareConnector(ctx, claim); err == nil {
						t.Fatal("historical claim authorized signing preparation")
					}
				}
				if _, err := activation.ActivateConnector(ctx, claim, original.Attempt.ID); err == nil {
					t.Fatal("historical receipt authorized activation replay")
				}
				var after string
				if err := admin.QueryRow(ctx, read, key).Scan(&after); err != nil || after != version {
					t.Fatal("current denial rewrote history", err)
				}
			})
		}
	}
	if _, err := activation.ActivateConnector(ctx, claim, original.Attempt.ID); err != nil {
		t.Fatal("restored exact connector history", err)
	}
}
