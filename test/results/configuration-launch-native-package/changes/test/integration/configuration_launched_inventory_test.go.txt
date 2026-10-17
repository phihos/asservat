package integration

import (
	"context"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This matrix qualifies actual SQL roles and locked replay. Kubernetes
// enforcement and the launched-object receipt are explicitly synthetic here;
// the separate native API matrix exercises the concrete protected root.
type configurationLaunchedSQLRoot struct {
	*configurationRoleSQLRoot
	reads atomic.Int32
}

func (r *configurationLaunchedSQLRoot) ReadLaunchedConfigurationRuntimeRoles(ctx context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	r.reads.Add(1)
	return r.ReadConfigurationRuntimeRoles(ctx)
}

func qualifyConfigurationLaunchedInventory(t *testing.T, ctx context.Context, admin *pgxpool.Pool, connection *pgx.ConnConfig, root *configurationRoleSQLRoot, original contracts.ConfigurationRuntimeRoleSnapshot, mode string) {
	t.Helper()
	in := original.State.Input
	now := time.Now().UTC().Truncate(time.Microsecond)
	root.mu.Lock()
	root.value.State.Projection = &contracts.PublicRuntimeProjectionClaim{OperationID: custodyID(), ClaimedAt: now, Until: now.Add(5 * time.Second), SecretUID: custodyID()}
	root.value.State.Launch = &contracts.ConfigurationRuntimeLaunch{
		OperationID: custodyID(), ClaimedAt: now, Until: now.Add(5 * time.Second), Sources: original.Sources,
		InertResourceVersion: "1", RunningDigest: strings.Repeat("a", 64), ProjectionUID: root.value.State.Projection.SecretUID,
		Configuration: contracts.WorkerObjectReference{Name: "worker-inputs", UID: custodyID()}, Providers: contracts.WorkerObjectReference{Name: "worker-providers", UID: custodyID()},
		Receipt: &contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: "2", ObservedAt: now},
	}
	root.value.Sources.WorkloadDigest = root.value.State.Launch.RunningDigest
	claims, receipts := root.claims, root.receipts
	root.mu.Unlock()
	launched := &configurationLaunchedSQLRoot{configurationRoleSQLRoot: root}
	producer, err := postgres.NewConfigurationRuntimeSQLRoles(ctx, connection, launched, in)
	if err != nil {
		t.Fatal("launched inventory constructor", err)
	}
	defer producer.Close()

	// Read only minimized public role provenance. Passwords are neither queried
	// nor logged. The credential verifier itself checks exact compiled ACLs.
	type inventoryRow struct {
		Name, Comment string
		OID           uint32
		Connections   int32
	}
	inventory := func() []inventoryRow {
		t.Helper()
		rows, e := admin.Query(ctx, `SELECT rolname,oid,rolconnlimit,coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=ANY($1::text[]) ORDER BY rolname`, []string{original.State.Roles[0].Receipt.RoleName, original.State.Roles[1].Receipt.RoleName, original.State.Roles[2].Receipt.RoleName})
		if e != nil {
			t.Fatal("read actual role inventory", e)
		}
		defer rows.Close()
		var out []inventoryRow
		for rows.Next() {
			var r inventoryRow
			if e = rows.Scan(&r.Name, &r.OID, &r.Connections, &r.Comment); e != nil {
				t.Fatal(e)
			}
			out = append(out, r)
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		return out
	}
	before := inventory()
	if len(before) != len(contracts.ConfigurationRuntimeRolePurposes()) {
		t.Fatal("incomplete original SQL inventory")
	}
	defer func() {
		root.mu.Lock()
		defer root.mu.Unlock()
		if root.claims != claims || root.receipts != receipts {
			t.Error("launched lookup created another credential claim or completion")
		}
		for i := range root.value.State.Roles {
			if !reflect.DeepEqual(root.value.State.Roles[i], original.State.Roles[i]) {
				t.Error("launched lookup rewrote original inert role provenance")
			}
		}
	}()

	// The ordinary branch must not reinterpret the running digest as the
	// original inert claim. Only the exact explicit launch disposition bridges it.
	if _, err = producer.VerifyConfigurationRuntimeRoles(ctx); err == nil {
		t.Fatal("ordinary inventory verification adopted a running workload")
	}
	first := pgx.Identifier{original.State.Roles[0].Receipt.RoleName}.Sanitize()
	switch mode {
	case "launched-matrix":
		for range 2 {
			got, e := producer.VerifyLaunchedConfigurationRuntimeRoles(ctx)
			if e != nil || got.State.OperationID != original.State.OperationID || !reflect.DeepEqual(got.State.Roles, original.State.Roles) {
				t.Fatal("exact launched SQL inventory unavailable", e)
			}
		}
	case "launched-missing-role":
		if _, err = admin.Exec(ctx, "DROP OWNED BY "+first+"; DROP ROLE "+first); err != nil {
			t.Fatal(err)
		}
		before = inventory()
		for range 2 {
			if _, err = producer.VerifyLaunchedConfigurationRuntimeRoles(ctx); err == nil {
				t.Fatal("missing original role was accepted or recreated")
			}
		}
	case "launched-ambient":
		// This is an actual inherited ambient privilege, not a direct role grant.
		if _, err = admin.Exec(ctx, "GRANT SELECT ON public.custody_pool TO PUBLIC"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			clean, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			if _, e := admin.Exec(clean, "REVOKE SELECT ON public.custody_pool FROM PUBLIC"); e != nil {
				t.Error(e)
			}
		}()
		if _, err = producer.VerifyLaunchedConfigurationRuntimeRoles(ctx); err == nil {
			t.Fatal("ambient PUBLIC privilege accepted on launched replay")
		}
	case "launched-changed-source":
		root.mu.Lock()
		root.value.Sources.Owner.Generation++
		root.mu.Unlock()
		if _, err = producer.VerifyLaunchedConfigurationRuntimeRoles(ctx); err == nil {
			t.Fatal("launch disposition accepted changed complete source")
		}
	case "launched-held-lock":
		tx, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(context.Background())
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(1095979854,hashtext($1))", in.InstallationID); e != nil {
			t.Fatal(e)
		}
		short, end := context.WithTimeout(ctx, 100*time.Millisecond)
		_, e = producer.VerifyLaunchedConfigurationRuntimeRoles(short)
		end()
		if e == nil || launched.reads.Load() != 0 {
			t.Fatal("launch proof was read before its blocking lock or ignored original deadline", e)
		}
		if e = tx.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		if _, e = producer.VerifyLaunchedConfigurationRuntimeRoles(ctx); e != nil {
			t.Fatal("new passive observation failed after positive lock release", e)
		}
	case "launched-recovery-after-lock":
		tx, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(context.Background())
		var blocker int32
		if e = tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blocker); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, "UPDATE public.fleet_trust SET recovery_blocked=true WHERE installation_id=$1", in.InstallationID); e != nil {
			t.Fatal(e)
		}
		live, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		joined := make(chan struct{})
		go func() { defer close(joined); _, e := producer.VerifyLaunchedConfigurationRuntimeRoles(live); done <- e }()
		defer func() { cancel(); _ = tx.Rollback(context.Background()); <-joined }()
		wait, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		for {
			var blocked bool
			if e = admin.QueryRow(wait, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::int=ANY(pg_blocking_pids(pid)))", blocker).Scan(&blocked); e != nil {
				t.Fatal("launched verification did not reach actual recovery lock", e)
			}
			if blocked {
				break
			}
			select {
			case e = <-done:
				t.Fatal("launched verification exited before recovery lock", e)
			case <-wait.Done():
				t.Fatal("launched verification lock wait unavailable")
			case <-time.After(5 * time.Millisecond):
			}
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e == nil || launched.reads.Load() != 0 {
			t.Fatal("new recovery fence was ignored after blocking lock", e)
		}
	default:
		t.Fatal("unknown launched inventory mode")
	}
	if after := inventory(); !reflect.DeepEqual(before, after) {
		t.Fatal("lookup-only launched verification changed actual SQL inventory")
	}
	t.Log("actual SQL launched inventory checked original role OIDs/provenance/current recovery/ACL; protected Kubernetes launch proof and Secret root remain synthetic in this matrix")
}
