package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Owns a pristine fleet database. The actual compiled profile-reader credential
// reads a protected, backed root; initial native/administrator inputs remain
// fixture facts. No collection, download or installed-runtime claim is made.
func TestCapacityAuditProfileDiagnosticsWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects)
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal("initialize original capacity", err)
		}
		f.open(t)
		o := f.rootObservation(t)
		root, err := f.roots.ReserveCapacityRoot(ctx, o)
		if err != nil {
			t.Fatal("reserve original root", err)
		}
		root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
		if err != nil {
			t.Fatal("back original root", err)
		}
		root, err = f.roots.PublishCapacityRoot(ctx, o, root)
		if err != nil || !root.AdmissionReady(time.Now()) {
			t.Fatal("publish original root", err)
		}

		raw, err := fs.ReadFile(migrations.Files(), "00139_saved_packet_query.sql")
		if err != nil {
			t.Fatal(err)
		}
		up, down, _ := strings.Cut(string(raw), "-- +goose Down")
		definition := func(part string) string {
			start := strings.Index(part, "CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(")
			if start < 0 {
				t.Fatal("profile definition missing")
			}
			end := strings.Index(part[start:], "END $$;")
			if end < 0 {
				t.Fatal("profile definition end missing")
			}
			return part[start : start+end+len("END $$;")]
		}
		before, after := definition(down), definition(up)
		install := func(body string) {
			t.Helper()
			if _, err := admin.Exec(ctx, body); err != nil {
				t.Fatal("install exact profile function", err)
			}
		}
		// Always restore the candidate function, including on a failing assertion.
		t.Cleanup(func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := admin.Exec(clean, after); err != nil {
				t.Error("restore diagnostic function", err)
			}
		})
		reader, err := postgres.NewCapacityAuditProfiles(ctx, f.roles["capacity-profile-read"], f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.qualification.Digest, f.input.AccountVersion)
		if err != nil {
			t.Fatal(err)
		}
		read := func() error {
			n := time.Now().UTC().Truncate(time.Microsecond)
			var result []byte
			return f.roles["capacity-profile-read"].QueryRow(ctx, `SELECT public.read_capacity_audit_profiles($1,$2,$3,$4,$5,$6,$7)`, f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.qualification.Digest[:], f.input.AccountVersion, n, n.Add(5*time.Second)).Scan(&result)
		}
		for _, body := range []string{before, after} {
			install(body)
			f.fresh(t)
			if err := read(); err != nil {
				t.Fatal("fresh compiled-reader control", err)
			}
			f.readAuditProfiles(t)
		}
		for _, cut := range []string{"permission", "source", "trust"} {
			if !t.Run(cut, func(t *testing.T) {
				f.fresh(t)
				switch cut {
				case "permission":
					_, err = admin.Exec(ctx, `UPDATE permission_stream SET fresh_until=clock_timestamp()+interval '150 milliseconds' WHERE id=$1`, f.input.PermissionRootID)
				case "trust":
					_, err = admin.Exec(ctx, `UPDATE fleet_observation SET fresh_until=clock_timestamp()+interval '150 milliseconds' WHERE installation_id=$1`, f.input.InstallationID)
				case "source":
					// The source guard forbids backdating. Let its actual positive30s
					// observation expire, keeping the two independent producers current.
					var until time.Time
					if err = admin.QueryRow(ctx, `SELECT fresh_until FROM capacity_source WHERE root_id=$1`, f.input.PermissionRootID).Scan(&until); err != nil {
						t.Fatal(err)
					}
					for time.Now().Before(until) {
						f.refreshBase(t)
						remaining := time.Until(until)
						if remaining > time.Second {
							remaining = time.Second
						}
						if remaining > 0 {
							time.Sleep(remaining)
						}
					}
				}
				if err != nil {
					t.Fatal("controlled restrictive expiry", err)
				}
				if cut != "source" {
					time.Sleep(200 * time.Millisecond)
				}
				for _, diagnostic := range []bool{false, true} {
					body := before
					if diagnostic {
						body = after
					}
					install(body)
					var pgErr *pgconn.PgError
					if err := read(); !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.Message != "current capacity audit profile unavailable" {
						t.Fatal("original refusal changed", err)
					}
					if !diagnostic {
						if pgErr.Detail != "" {
							t.Fatal("baseline unexpectedly contains detail")
						}
						continue
					}
					var detail map[string]any
					if len(pgErr.Detail) > 2048 || json.Unmarshal([]byte(pgErr.Detail), &detail) != nil || detail["stage"] != "capacity-audit-current" || detail["cut"] != cut {
						t.Fatal("bounded closed diagnostic category", len(pgErr.Detail), detail["cut"])
					}
					for key, value := range detail {
						switch key {
						case "stage", "cut":
						case "now", "inputObserved", "callerUntil", "effectiveUntil", "trustObserved", "trustUntil", "permissionObserved", "permissionUntil", "permissionLeaseUntil", "sourceObserved", "sourceUntil", "plannedUntil":
							if _, err := time.Parse(time.RFC3339Nano, value.(string)); err != nil {
								t.Fatal("diagnostic timestamp", key, err)
							}
						case "trustSuspended", "recoveryBlocked", "permissionSuspended", "sourceSuspended", "reconciled":
							if _, ok := value.(bool); !ok {
								t.Fatal("diagnostic flag", key)
							}
						default:
							t.Fatal("unexpected diagnostic field", key)
						}
					}
					for _, secret := range []string{f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.input.AccountVersion, "synthetic-"} {
						if strings.Contains(pgErr.Detail, secret) {
							t.Fatal("private input in operator detail")
						}
					}
					if _, err := reader.ReadCapacityAuditProfiles(ctx); err != auditapp.ErrUnavailable {
						t.Fatal("public adapter exposed SQL detail", err)
					}
					t.Logf("original23514/message unchanged; cut=%s detailBytes=%d; adapter remains generic", cut, len(pgErr.Detail))
				}
			}) {
				return
			}
		}
		install(after)
		f.fresh(t)
		f.readAuditProfiles(t)
	})
}
