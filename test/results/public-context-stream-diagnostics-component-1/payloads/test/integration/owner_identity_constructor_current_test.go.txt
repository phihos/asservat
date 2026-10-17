package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual PostgreSQL current-state/lock behavior; the initial source/witness and
// role root remain the existing explicit synthetic test boundary. No native
// guard or already-running worker is simulated by a constructor success.
func qualifyOwnerIdentityConstructorCurrent(t *testing.T, ctx context.Context, admin *pgxpool.Pool, config *pgx.ConnConfig, root *ownerIdentitySQLRoot, input contracts.OwnerIdentityRoles, observer *postgres.FleetObservation, observerPool *pgxpool.Pool, a fleet.Administration, mode string) {
	t.Helper()
	initial, err := readOwnerSQLPrerequisites(ctx, admin, input)
	if err != nil || !initial.current() {
		t.Fatal("original constructor prerequisites", err)
	}
	accepted, err := postgres.NewOwnerIdentitySQLRoles(ctx, config, root, input)
	if err != nil {
		t.Fatal("original current source constructor", err)
	}
	accepted.Close()
	wantReason := "source-current"
	switch mode {
	case "constructor-expired-source":
		// Deliberately short independent source observation; no SQL timestamp edit
		// or refreshed authority after it expires.
		a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		a.FreshUntil = a.ObservedAt.Add(250 * time.Millisecond)
		if err = observer.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, observer), a); err != nil {
			t.Fatal("short original source", err)
		}
		timer := time.NewTimer(time.Until(a.FreshUntil))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal("fixture cancelled")
		case <-timer.C:
		}
		sample, e := readOwnerSQLPrerequisites(ctx, admin, input)
		if e != nil || !sample.stable() || !sample.Unsuspended || sample.Unexpired {
			t.Fatal("expiry isolation", e)
		}
	case "constructor-bridge-contention":
		wantReason = "recovery"
		var raw, receiptRaw []byte
		if err = admin.QueryRow(ctx, `SELECT record_json,audit_receipt_json FROM public.fleet_initial_activation WHERE installation_id=$1`, input.InstallationID).Scan(&raw, &receiptRaw); err != nil {
			t.Fatal("original activation", err)
		}
		var record audit.InitialInstallation
		var receipt audit.Receipt
		if json.Unmarshal(raw, &record) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || record.Claim.ID != input.InitialClaimID || !record.Valid() || !receipt.ValidInitialInstallation(record.Scope.InstallationID, record.Claim.ID) {
			t.Fatal("original retained activation invalid")
		}
		bridge, e := postgres.NewInitialRuntimeBridgeSQL(ctx, config, record, receipt)
		if e != nil {
			t.Fatal("actual original bridge", e)
		}
		defer bridge.Close()
		var failedObservation error
		var observerPID int
		if err = observerPool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&observerPID); err != nil {
			t.Fatal("observer process", err)
		}
		started := time.Now().UTC().Truncate(time.Microsecond)
		a.ObservedAt = started
		a.FreshUntil = started.Add(5 * time.Second)
		a.Suspended = true
		basis := fleetBasisFixture(t, ctx, observer)
		err = bridge.WithInitialRuntimeBridge(ctx, func(call context.Context) error {
			// This actual callback holds the same recovery/activation locks as native
			// I/O. The independently credentialed restrictive observer must hit its unchanged 1s
			// lock timeout. No loop/retry or renewed source is used.
			result := make(chan error, 1)
			go func() { result <- observer.ObserveAdministration(call, basis, a) }()
			joined := false
			defer func() {
				if !joined {
					failedObservation = <-result
				}
			}()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			blocked := false
			for i := 0; i < 40; i++ {
				if e := admin.QueryRow(call, `SELECT COALESCE((SELECT wait_event_type='Lock' AND query LIKE '%ObserveFleetAdministration%' FROM pg_stat_activity WHERE pid=$1),false)`, observerPID).Scan(&blocked); e != nil {
					return e
				}
				if blocked {
					break
				}
				select {
				case failedObservation = <-result:
					joined = true
					return errors.New("observer returned before actual trust lock wait")
				case <-call.Done():
					return call.Err()
				case <-ticker.C:
				}
			}
			if !blocked {
				return errors.New("actual observer trust lock wait not observed")
			}
			failedObservation = <-result
			joined = true
			if failedObservation == nil {
				return errors.New("fixture observer unexpectedly crossed retained bridge lock")
			}
			return nil
		})
		if err != nil || failedObservation == nil {
			t.Fatal("actual bridge/observer contention not reached", err)
		}
		// The existing observer fences after failed observation. Success here while
		// bridge remains open proves its lock ended with the operation, not Close.
		if err = observer.FenceAdministration(ctx, basis, started); err != nil {
			t.Fatal("post-operation fence remained blocked", err)
		}
		sample, e := readOwnerSQLPrerequisites(ctx, admin, input)
		retained := sample
		retained.Recovery = true // The new version intentionally invalidates its old observation.
		if e != nil || !retained.stable() || sample.Recovery || sample.Unsuspended || sample.Unexpired {
			t.Fatal("failed observation fence not retained", e)
		}
	default:
		t.Fatal("unknown constructor fixture mode")
	}
	denied, err := postgres.NewOwnerIdentitySQLRoles(ctx, config, root, input)
	if denied != nil {
		denied.Close()
	}
	if !errors.Is(err, cfg.ErrUnavailable) || err.Error() != "owner identity SQL prerequisite unavailable: "+wantReason {
		t.Fatal("constructor accepted unavailable current source", err)
	}
	if root.claims != 0 || root.receipts != 0 {
		t.Fatal("constructor consumed a role attempt")
	}
	for _, purpose := range contracts.OwnerIdentityRolePurposes() {
		name, ok := postgres.OwnerIdentityRoleName(input.InstallationID, purpose)
		if !ok {
			t.Fatal("unknown fixed purpose")
		}
		var exists bool
		if e := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, name).Scan(&exists); e != nil || exists {
			t.Fatal("denied constructor created a role", e)
		}
	}
	t.Log("actual constructor refused original unavailable fleet source without role effects; no authority retry or deadline change")
}
