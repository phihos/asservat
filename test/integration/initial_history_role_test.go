package integration

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Exact selected-run fixture on a fresh owned database. The maintenance role
// is synthetic trusted installation input, never a runtime application grant.
func TestInitialSQLHistoryRoleWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run selected owned custody fixture on a fresh database")
	}
	var f fixture
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	ctx, end := context.WithTimeout(context.Background(), 35*time.Second)
	defer end()
	admin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal("fixture administration unavailable")
	}
	defer admin.Close()
	var used bool
	if e = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM fleet_initial_activation) OR EXISTS(SELECT 1 FROM fleet_trust)").Scan(&used); e != nil || used {
		t.Fatal("fresh installation database required")
	}
	endpoint, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal("fixture endpoint unavailable")
	}
	address, tlsConfig := pgTLSBridge(t, endpoint.Host)
	maintenance := initialSQLMaintenance(t, ctx, admin, address, tlsConfig)
	t.Run("original-creator-membership-survives-revoke", func(t *testing.T) {
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		tx, err := maintenance.Begin(bounded)
		if err != nil {
			t.Fatal("membership probe transaction unavailable")
		}
		defer func() {
			cleanup, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			_ = tx.Rollback(cleanup)
		}()
		if _, err = tx.Exec(bounded, "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'"); err != nil {
			t.Fatal("membership probe bounds unavailable")
		}
		name := "synthetic_history_" + strings.ReplaceAll(custodyID(), "-", "")
		if _, err = tx.Exec(bounded, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			t.Fatal("membership probe create unavailable")
		}
		inspect := func() (int, bool) {
			var count int
			var exact bool
			err = tx.QueryRow(bounded, `SELECT count(*),coalesce(bool_and(m.member=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND m.grantor=10 AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option),false)
			FROM pg_auth_members m WHERE m.roleid=(SELECT oid FROM pg_roles WHERE rolname=$1)`, name).Scan(&count, &exact)
			if err != nil {
				t.Fatal("membership probe catalogue unavailable")
			}
			return count, exact
		}
		before, beforeExact := inspect()
		if _, err = tx.Exec(bounded, "REVOKE "+pgx.Identifier{name}.Sanitize()+" FROM "+pgx.Identifier{maintenance.Config().ConnConfig.User}.Sanitize()); err != nil {
			t.Fatal("membership probe revoke returned SQL failure")
		}
		after, afterExact := inspect()
		t.Logf("creator grant before_count=%d before_exact=%t after_count=%d after_exact=%t", before, beforeExact, after, afterExact)
		if before != 1 || !beforeExact || after != 1 || !afterExact {
			t.Fatal("pinned creator membership behavior differs")
		}
		if err = tx.Rollback(bounded); err != nil {
			t.Fatal("membership probe rollback unavailable")
		}
	})
	pin := contracts.InitialSQLHistoryManager{Name: maintenance.Config().ConnConfig.User}
	if e = admin.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", pin.Name).Scan(&pin.OID); e != nil {
		t.Fatal("independent manager pin unavailable")
	}
	plan, e := postgres.NewInitialSQLCredentials(custodyID(), time.Now())
	if e != nil {
		t.Fatal("synthetic setup credentials unavailable")
	}
	manager, e := postgres.NewInitialSQLRoles(ctx, maintenance, plan.InstallationID)
	if e != nil {
		t.Fatal("maintenance scope unavailable")
	}
	if e = manager.CheckHistoryManager(ctx, pin); e != nil {
		t.Fatal("independent original manager preflight rejected")
	}
	bounded, stop := context.WithTimeout(ctx, 5*time.Second)
	e = manager.Provision(bounded, plan)
	stop()
	if e != nil {
		t.Fatal("original role preparation failed")
	}
	independent, e := postgres.NewInitialSQLCredentials(plan.InstallationID, time.Now())
	if e != nil {
		t.Fatal("synthetic history material unavailable")
	}
	name, e := postgres.InitialSQLHistoryRoleName(plan.InstallationID)
	if e != nil {
		t.Fatal("history identity unavailable")
	}
	login := postgres.InitialSQLLogin{Username: name, Password: independent.Preparation.Password}
	for _, bad := range []contracts.InitialSQLHistoryManager{{Name: pin.Name, OID: pin.OID + 1}, {Name: "another_setup_manager", OID: pin.OID}} {
		if manager.CheckHistoryManager(ctx, bad) == nil {
			t.Fatal("inconsistent manager pin passed read-only preflight")
		}
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		e = manager.ProvisionHistory(bounded, plan, login, bad)
		stop()
		if e == nil {
			t.Fatal("untrusted creator pin admitted")
		}
		var exists bool
		if e = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", login.Username).Scan(&exists); e != nil || exists {
			t.Fatal("wrong creator pin created history role")
		}
	}
	for _, step := range []string{"create", "replay"} {
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		e = manager.ProvisionHistory(bounded, plan, login, pin)
		stop()
		if e != nil {
			t.Fatalf("history %s failed: %s", step, postgres.InitialSQLHistoryDiagnostic(e))
		}
	}
	config := maintenance.Config()
	config.ConnConfig.User = name
	config.ConnConfig.Password = login.Password
	config.ConnConfig.RequireAuth = "scram-sha-256"
	history, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal("history connection unavailable")
	}
	defer history.Close()
	if e = postgres.CheckInitialSQLHistoryRole(ctx, history, plan.InstallationID, pin); e != nil {
		t.Fatal("passive history privileges rejected")
	}
	if _, e = history.Exec(ctx, "SELECT count(*) FROM fleet_initial_activation"); e != nil {
		t.Fatal("passive metadata read unavailable")
	}
	for _, query := range []string{"UPDATE fleet_initial_activation SET singleton=singleton", "SELECT count(*) FROM fleet_trust", "CREATE TABLE public.history_escape(id integer)"} {
		if _, e = history.Exec(ctx, query); e == nil {
			t.Fatal("passive history role acquired broader rights")
		}
	}
	// Each negative uses separate fixture-administrator mutations. The product
	// verifier receives only the passive history connection and original pin.
	checkDenied := func(t *testing.T) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		if postgres.CheckInitialSQLHistoryRole(bounded, history, plan.InstallationID, pin) == nil {
			t.Fatal("changed role authority accepted")
		}
	}
	mutate := func(label, change, restore string) {
		t.Run(label, func(t *testing.T) {
			if _, err := admin.Exec(ctx, change); err != nil {
				t.Fatal("fixture privilege mutation unavailable")
			}
			defer func() {
				if _, err := admin.Exec(ctx, restore); err != nil {
					t.Fatal("fixture privilege restoration unavailable")
				}
				if postgres.CheckInitialSQLHistoryRole(ctx, history, plan.InstallationID, pin) != nil {
					t.Fatal("original reader did not recover after exact fixture restoration")
				}
			}()
			checkDenied(t)
		})
	}
	historyName := pgx.Identifier{name}.Sanitize()
	managerName := pgx.Identifier{pin.Name}.Sanitize()
	for _, option := range []string{"INHERIT", "SET"} {
		mutate("reject-creator-"+strings.ToLower(option), "GRANT "+historyName+" TO "+managerName+" WITH "+option+" TRUE", "GRANT "+historyName+" TO "+managerName+" WITH "+option+" FALSE")
	}
	mutate("reject-missing-admin", "REVOKE ADMIN OPTION FOR "+historyName+" FROM "+managerName, "GRANT "+historyName+" TO "+managerName+" WITH ADMIN TRUE")
	mutate("reject-missing-original-grant", "REVOKE "+historyName+" FROM "+managerName, "GRANT "+historyName+" TO "+managerName+" WITH ADMIN TRUE,INHERIT FALSE,SET FALSE")
	other := "synthetic_history_other"
	otherName := pgx.Identifier{other}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE ROLE "+otherName+" NOLOGIN"); e != nil {
		t.Fatal("fixture role unavailable")
	}
	defer func() {
		if _, e := admin.Exec(ctx, "DROP ROLE "+otherName); e != nil {
			t.Error("fixture role cleanup failed")
		}
	}()
	mutate("reject-extra-incoming-member", "GRANT "+historyName+" TO "+otherName+" WITH ADMIN FALSE,INHERIT FALSE,SET FALSE", "REVOKE "+historyName+" FROM "+otherName)
	mutate("reject-outgoing-membership", "GRANT "+otherName+" TO "+historyName+" WITH INHERIT FALSE,SET FALSE", "REVOKE "+otherName+" FROM "+historyName)
	t.Run("reject-additional-manager-grantor", func(t *testing.T) {
		// The already trusted non-superuser manager can grant membership, as
		// PostgreSQL documents. Its independently attributed grant to a separate NOLOGIN member is
		// not accepted as the bootstrap-superuser's single original grant.
		if _, e := maintenance.Exec(ctx, "GRANT "+historyName+" TO "+otherName+" WITH ADMIN FALSE,INHERIT FALSE,SET FALSE GRANTED BY "+managerName); e != nil {
			state := "none"
			if pg, ok := e.(interface{ SQLState() string }); ok {
				code := pg.SQLState()
				if len(code) == 5 && strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' && r < 'A' || r > 'Z' }) < 0 {
					state = code
				}
			}
			t.Fatalf("fixture manager grant unavailable (sqlstate=%s)", state)
		}
		defer func() {
			if _, e := maintenance.Exec(ctx, "REVOKE "+historyName+" FROM "+otherName+" GRANTED BY "+managerName); e != nil {
				t.Error("fixture manager grant retirement failed")
			}
			if postgres.CheckInitialSQLHistoryRole(ctx, history, plan.InstallationID, pin) != nil {
				t.Error("original bootstrap grant did not recover")
			}
		}()
		var additional bool
		if e := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname=$1) AND member=(SELECT oid FROM pg_roles WHERE rolname=$3) AND grantor=$2)", name, pin.OID, other).Scan(&additional); e != nil || !additional {
			t.Fatal("fixture did not establish independently attributed grant")
		}
		checkDenied(t)
	})
	mutate("reject-extra-write", "GRANT UPDATE ON fleet_initial_activation TO "+historyName, "REVOKE UPDATE ON fleet_initial_activation FROM "+historyName)
	mutate("reject-replaced-manager-name", "ALTER ROLE "+managerName+" RENAME TO synthetic_history_prior_manager; CREATE ROLE "+managerName+" NOLOGIN", "DROP ROLE "+managerName+"; ALTER ROLE synthetic_history_prior_manager RENAME TO "+managerName)
	// The manager may safely retire its login/role-creation abilities; unchanged
	// historical identity still permits passive reads without its credential.
	t.Run("passive-after-manager-retirement", func(t *testing.T) {
		if _, e = admin.Exec(ctx, "ALTER ROLE "+managerName+" NOLOGIN NOCREATEROLE"); e != nil {
			t.Fatal("fixture manager retirement unavailable")
		}
		defer func() {
			if _, e := admin.Exec(ctx, "ALTER ROLE "+managerName+" LOGIN CREATEROLE"); e != nil {
				t.Error("fixture manager restoration failed")
			}
		}()
		if postgres.CheckInitialSQLHistoryRole(ctx, history, plan.InstallationID, pin) != nil {
			t.Fatal("passive reader depended on active setup privileges")
		}
	})
	var memberships int
	if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname=$1) OR member=(SELECT oid FROM pg_roles WHERE rolname=$1)", name).Scan(&memberships); e != nil || memberships != 1 {
		t.Fatal("history role membership differs from original creator grant")
	}
	wrong := login
	wrong.Password = plan.Preparation.Password
	bounded, stop = context.WithTimeout(ctx, 5*time.Second)
	e = manager.ProvisionHistory(bounded, plan, wrong, pin)
	stop()
	if e == nil {
		t.Fatal("history password adopted setup material")
	}
}
