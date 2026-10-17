package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Explicit historical fixture administration only: the genuine SQL/S3/Bao
// owner flow has already acknowledged/activated these objects. A transaction-
// local trigger bypass models an old persisted receipt, without granting any
// runtime role mutation rights. Every subtest restores the exact original bytes
// for the remaining independent lifecycle cases; this is not product recovery.
func exerciseOwnerHistoricalVersions(t *testing.T, ctx context.Context, l *ownerConfigLab, ledger, ack, activation, registry *postgres.OwnerEnrollments, attempt value.OwnerCertificateAttempt, certificate value.OwnerCertificate, proof func() value.OwnerEnrollmentProof) {
	t.Helper()
	c := attempt.Permit.Configuration.Configuration
	for _, kind := range []string{"configuration", "enrollment", "certificate"} {
		for _, version := range []string{"", "null"} {
			name := version
			if name == "" {
				name = "empty"
			}
			t.Run("retained-"+kind+"-"+name+"-cannot-authorize", func(t *testing.T) {
				p := proof() // Actual original fixture observation, before corruption.
				var readSQL, writeSQL string
				var args []any
				switch kind {
				case "configuration":
					readSQL = "SELECT audit_receipt_json FROM hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4"
					writeSQL = "UPDATE hub_owner_configuration_revision SET audit_receipt_json=$5 WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4"
					args = []any{c.Pool.InstallationID, c.Pool.ClusterID, c.Revision.UID, c.Revision.Generation}
				case "enrollment":
					readSQL = "SELECT audit_receipt_json FROM hub_owner_enrollment WHERE id=$1"
					writeSQL = "UPDATE hub_owner_enrollment SET audit_receipt_json=$2 WHERE id=$1"
					args = []any{attempt.Enrollment.ID}
				case "certificate":
					readSQL = "SELECT audit_receipt_json FROM hub_owner_certificate WHERE id=$1"
					writeSQL = "UPDATE hub_owner_certificate SET audit_receipt_json=$2 WHERE id=$1"
					args = []any{attempt.Permit.ID}
				default:
					t.Fatal("unknown historical fixture purpose")
				}
				var original []byte
				if err := l.admin.QueryRow(ctx, readSQL, args...).Scan(&original); err != nil {
					t.Fatal(err)
				}
				var receipt audit.Receipt
				if json.Unmarshal(original, &receipt) != nil || receipt.Version == "" || receipt.Version == "null" {
					t.Fatal("actual original receipt has no immutable version")
				}
				receipt.Version = version
				historical, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				setFixtureReceipt := func(call context.Context, raw []byte) error {
					tx, err := l.admin.Begin(call)
					if err != nil {
						return err
					}
					defer tx.Rollback(context.Background())
					if _, err = tx.Exec(call, "SET LOCAL session_replication_role=replica"); err != nil {
						return err
					}
					values := append(append([]any(nil), args...), raw)
					changed, err := tx.Exec(call, writeSQL, values...)
					if err != nil {
						return err
					}
					if changed.RowsAffected() != 1 {
						t.Fatal("historical fixture row mismatch")
					}
					return tx.Commit(call)
				}
				// Register restoration before the possibly uncertain fixture write.
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := setFixtureReceipt(cleanup, original); err != nil {
						t.Error("restore original fixture receipt", err)
					}
				})
				if err = setFixtureReceipt(ctx, historical); err != nil {
					t.Fatal(err)
				}
				if kind == "configuration" {
					if _, err = l.reader.ReadOwnerConfiguration(ctx); err == nil {
						t.Fatal("unversioned acknowledged configuration became current")
					}
				}
				if kind != "certificate" {
					if _, _, _, err = ledger.ClaimOwnerEnrollment(ctx, p); err == nil {
						t.Fatal("unversioned history authorized enrollment replay")
					}
					if _, err = ledger.PrepareOwnerCertificate(ctx, p); err == nil {
						t.Fatal("unversioned history authorized signing preparation")
					}
				} else {
					if _, _, err = ack.ReadOwnerCertificateReceipt(ctx, audit.OwnerCertificate{Attempt: attempt, Certificate: certificate}); err == nil {
						t.Fatal("unversioned certificate receipt became reusable")
					}
				}
				if _, err = activation.ActivateOwnerCertificate(ctx, p, attempt); err == nil {
					t.Fatal("unversioned retained history authorized certificate activation")
				}
				if _, err = registry.ReadOwnerRegistration(ctx, certificate); err == nil {
					t.Fatal("unversioned retained history authorized current registration")
				}
				var after []byte
				if err = l.admin.QueryRow(ctx, readSQL, args...).Scan(&after); err != nil || !bytes.Equal(after, historical) {
					t.Fatal("current denial rewrote historical bytes", err)
				}
			})
		}
	}
}
