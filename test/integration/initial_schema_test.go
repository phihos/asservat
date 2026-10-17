package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Synthetic protected-root port: this fixture qualifies the actual Goose/SQL
// boundary, not Kubernetes guard authority or the deployed initial-schema CLI.
type syntheticSchemaRoot struct {
	mu                                   sync.Mutex
	record                               *contracts.InitialPreparationSchema
	reads, failRead, claims, completions int
	loseCompletion                       bool
	expired                              bool
}

func (r *syntheticSchemaRoot) ReadInitialSchema(ctx context.Context) (contracts.InitialPreparationRoot, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	if r.reads == r.failRead || ctx.Err() != nil {
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	until := time.Now().Add(5 * time.Second)
	if r.expired {
		until = time.Now().Add(-time.Second)
	}
	w := contracts.InitialPreparationRoot{}
	if r.record != nil {
		v := *r.record
		w.Schema = &v
	}
	return w, until, nil
}
func (r *syntheticSchemaRoot) ClaimInitialSchema(ctx context.Context, v contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || r.record != nil {
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	v.AttemptID = custodyID()
	v.ClaimedAt = time.Now().UTC().Truncate(time.Microsecond)
	r.record = &v
	r.claims++
	return contracts.InitialPreparationRoot{Schema: &v}, time.Now().Add(5 * time.Second), nil
}
func (r *syntheticSchemaRoot) CompleteInitialSchema(ctx context.Context, v contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || r.record == nil || r.record.AttemptID != v.AttemptID {
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	v.CompletedAt = &now
	r.record = &v
	r.completions++
	if r.loseCompletion {
		r.loseCompletion = false
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	return contracts.InitialPreparationRoot{Schema: &v}, time.Now().Add(5 * time.Second), nil
}

func TestInitialSchemaWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run selected owned custody fixture")
	}
	var f fixture
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, end := context.WithTimeout(context.Background(), 100*time.Second)
	defer end()
	admin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal("fixture administration unavailable")
	}
	t.Cleanup(admin.Close)
	name := "schema_" + strings.ReplaceAll(custodyID(), "-", "")
	manager := "schema_manager_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal("owned empty database unavailable")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.Exec(bounded, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Error("owned database cleanup failed")
		}
		if _, e := admin.Exec(bounded, "DROP ROLE IF EXISTS "+pgx.Identifier{manager}.Sanitize()); e != nil {
			t.Error("owned manager cleanup failed")
		}
	})
	if _, e = admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{manager}.Sanitize()+" LOGIN NOINHERIT NOSUPERUSER CREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD 'synthetic-schema-manager' VALID UNTIL '"+time.Now().Add(30*time.Minute).UTC().Format(time.RFC3339)+"'"); e != nil {
		t.Fatal("synthetic manager unavailable")
	}
	pin := contracts.InitialSQLHistoryManager{Name: manager}
	if e = admin.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", manager).Scan(&pin.OID); e != nil {
		t.Fatal("manager identity unavailable")
	}
	endpoint, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal("fixture endpoint unavailable")
	}
	address, roots := pgTLSBridge(t, endpoint.Host)
	host, portText, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal("TLS fixture unavailable")
	}
	port, _ := strconv.Atoi(portText)
	config := admin.Config().ConnConfig.Copy()
	config.Host, config.Port, config.Database = host, uint16(port), name
	config.TLSConfig = roots.Clone()
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.Fallbacks = nil
	sqlAdmin, e := pgx.ConnectConfig(ctx, config)
	if e != nil {
		t.Fatal("owned database connection unavailable")
	}
	defer sqlAdmin.Close(context.Background())
	root := &syntheticSchemaRoot{}
	s, e := postgres.NewInitialSchema(config, root, pin)
	if e != nil {
		t.Fatal("bounded schema facet unavailable")
	}
	defer s.Close()
	if e = s.CheckManager(ctx); e != nil {
		t.Fatal("finite external manager rejected", e)
	}
	t.Run("reject-nonempty-schema-before-root-claim", func(t *testing.T) {
		if _, e = sqlAdmin.Exec(ctx, "CREATE TABLE public.custody_pool(synthetic integer)"); e != nil {
			t.Fatal("fault setup unavailable")
		}
		if e = s.Run(ctx); e == nil || root.claims != 0 {
			t.Fatal("preexisting empty table adopted")
		}
		if _, e = sqlAdmin.Exec(ctx, "DROP TABLE public.custody_pool"); e != nil {
			t.Fatal("fault cleanup unavailable")
		}
	})
	if !t.Run("original-prefix-resume-and-lost-completion", func(t *testing.T) {
		root.reads = 0
		root.failRead = 8
		runError := s.Run(ctx)
		if runError == nil {
			t.Fatal("lost current proof did not stop")
		}
		var head int
		headError := sqlAdmin.QueryRow(ctx, "SELECT max(version_id) FROM public.goose_db_version").Scan(&head)
		phase, version := postgres.InitialSchemaFailurePhase(runError)
		var primary, required, other int
		constraintError := sqlAdmin.QueryRow(ctx, `SELECT count(*) FILTER (WHERE contype='p'),count(*) FILTER (WHERE contype='n'),count(*) FILTER (WHERE contype NOT IN ('p','n')) FROM pg_constraint WHERE conrelid=to_regclass('public.goose_db_version')`).Scan(&primary, &required, &other)
		t.Logf("original prefix phase=%s version=%d head_read_ok=%t head=%d claims=%d root_reads=%d constraints_read_ok=%t primary=%d not_null=%d other=%d", phase, version, headError == nil, head, root.claims, root.reads, constraintError == nil, primary, required, other)
		if headError != nil || head < 1 {
			t.Fatal("first transactional prefix not retained")
		}
		original := *root.record
		root.failRead = 0
		root.loseCompletion = true
		if e = s.Run(ctx); e == nil || root.record.CompletedAt == nil {
			t.Fatal("lost completion acknowledgement not modeled", e)
		}
		if root.record.AttemptID != original.AttemptID || root.record.ClaimedAt != original.ClaimedAt || root.claims != 1 {
			t.Fatal("resume replaced original attempt")
		}
		completed := *root.record.CompletedAt
		if e = s.Run(ctx); e != nil || root.completions != 1 || !root.record.CompletedAt.Equal(completed) {
			t.Fatal("completed read-only replay failed", e)
		}
	}) {
		t.Fatal("original schema prerequisite failed; dependent checks not executed")
	}
	t.Run("runtime-manager-has-only-exact-grant-union", func(t *testing.T) {
		if e = s.CheckManager(ctx); e != nil {
			t.Fatal("qualified manager unavailable")
		}
		if _, e = sqlAdmin.Exec(ctx, "GRANT DELETE ON public.custody_pool TO "+pgx.Identifier{manager}.Sanitize()); e != nil {
			t.Fatal("hostile grant unavailable")
		}
		if e = s.Run(ctx); e == nil {
			t.Fatal("completed replay silently repaired extra authority")
		}
		if _, e = sqlAdmin.Exec(ctx, "REVOKE DELETE ON public.custody_pool FROM "+pgx.Identifier{manager}.Sanitize()); e != nil {
			t.Fatal("hostile grant cleanup unavailable")
		}
	})
	// These independently mutate the actual catalog shape; completed replay
	// must reject them without repairing the trusted schema on the caller's behalf.
	for _, fault := range []struct{ name, apply, restore string }{
		{"extra-check", "ALTER TABLE public.goose_db_version ADD CONSTRAINT synthetic_extra CHECK(version_id>=0)", "ALTER TABLE public.goose_db_version DROP CONSTRAINT synthetic_extra"},
		{"missing-not-null", "ALTER TABLE public.goose_db_version ALTER COLUMN is_applied DROP NOT NULL", "ALTER TABLE public.goose_db_version ALTER COLUMN is_applied SET NOT NULL"},
		{"wrong-primary-key", "ALTER TABLE public.goose_db_version DROP CONSTRAINT goose_db_version_pkey, ADD CONSTRAINT goose_db_version_pkey PRIMARY KEY(version_id)", "ALTER TABLE public.goose_db_version DROP CONSTRAINT goose_db_version_pkey, ADD CONSTRAINT goose_db_version_pkey PRIMARY KEY(id)"},
	} {
		if !t.Run("reject-metadata-"+fault.name, func(t *testing.T) {
			if _, err := sqlAdmin.Exec(ctx, fault.apply); err != nil {
				t.Fatal("metadata fault setup unavailable")
			}
			if err := s.Run(ctx); err == nil {
				t.Error("noncanonical metadata constraint accepted")
			}
			if _, err := sqlAdmin.Exec(ctx, fault.restore); err != nil {
				t.Fatal("metadata fault cleanup unavailable")
			}
			if err := s.Run(ctx); err != nil {
				t.Fatal("original metadata replay unavailable after fixture repair")
			}
		}) {
			t.Fatal("metadata prerequisite failed; dependent checks not executed")
		}
	}
	t.Run("reject-foreign-down-or-reordered-history", func(t *testing.T) {
		if _, e = sqlAdmin.Exec(ctx, "UPDATE public.goose_db_version SET is_applied=false WHERE version_id=1"); e != nil {
			t.Fatal("history fault unavailable")
		}
		if e = s.Run(ctx); e == nil {
			t.Fatal("down history accepted")
		}
		if _, e = sqlAdmin.Exec(ctx, "UPDATE public.goose_db_version SET is_applied=true WHERE version_id=1"); e != nil {
			t.Fatal("history repair unavailable")
		}
		if _, e = sqlAdmin.Exec(ctx, "INSERT INTO public.goose_db_version(version_id,is_applied) VALUES(999,true)"); e != nil {
			t.Fatal("foreign history fault unavailable")
		}
		if e = s.Run(ctx); e == nil {
			t.Fatal("foreign migration accepted")
		}
		if _, e = sqlAdmin.Exec(ctx, "DELETE FROM public.goose_db_version WHERE version_id=999"); e != nil {
			t.Fatal("foreign history cleanup unavailable")
		}
	})
	t.Run("changed-instance-bundle-and-expired-root-deny", func(t *testing.T) {
		original := *root.record
		root.record.DatabaseOID++
		if e = s.Run(ctx); e == nil {
			t.Fatal("changed database adopted")
		}
		*root.record = original
		root.record.PostmasterAt = root.record.PostmasterAt.Add(time.Second)
		if e = s.Run(ctx); e == nil {
			t.Fatal("restart adopted")
		}
		*root.record = original
		root.record.BundleDigest = strings.Repeat("f", 64)
		if e = s.Run(ctx); e == nil {
			t.Fatal("new binary bundle adopted")
		}
		*root.record = original
		root.expired = true
		if e = s.Run(ctx); e == nil {
			t.Fatal("expired proof replayed")
		}
		root.expired = false
	})
	t.Run("held-original-session-lock-never-taken-over", func(t *testing.T) {
		if _, e = sqlAdmin.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(0x4153534552565343)); e != nil {
			t.Fatal("fixture lock unavailable")
		}
		if e = s.Run(ctx); e == nil {
			t.Fatal("concurrent migration owner bypassed")
		}
		if _, e = sqlAdmin.Exec(ctx, "SELECT pg_advisory_unlock($1)", int64(0x4153534552565343)); e != nil {
			t.Fatal("fixture unlock unavailable")
		}
		if e = s.Run(ctx); e != nil {
			t.Fatal("original owner replay unavailable", e)
		}
	})
	t.Run("completed-schema-read-only-resume-after-child-creation", func(t *testing.T) {
		current := config.Copy()
		current.User, current.Password = manager, "synthetic-schema-manager"
		m, e := pgx.ConnectConfig(ctx, current)
		if e != nil {
			t.Fatal("original finite manager login unavailable")
		}
		defer m.Close(context.Background())
		child := "schema_child_" + strings.ReplaceAll(custodyID(), "-", "")
		if _, e = m.Exec(ctx, "CREATE ROLE "+pgx.Identifier{child}.Sanitize()+" NOLOGIN NOINHERIT"); e != nil {
			t.Fatal("actual creator membership setup unavailable")
		}
		defer func() {
			if _, e := admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{child}.Sanitize()); e != nil {
				t.Error("owned child cleanup failed")
			}
		}()
		if e = s.Run(ctx); e == nil {
			t.Fatal("active schema stage bypassed membership preflight")
		}
		v, until, e := postgres.VerifyInitialSchemaCompletion(ctx, current, root)
		if e != nil || v.AttemptID != root.record.AttemptID || !time.Now().Before(until) || until.After(time.Now().Add(5*time.Second)) {
			t.Fatal("read-only original completed schema unavailable", e)
		}
		if _, _, e = postgres.VerifyInitialSchemaCompletion(ctx, config, root); e == nil {
			t.Fatal("DDL login used as manager read authority")
		}
		original := root.record.PostmasterAt
		root.record.PostmasterAt = original.Add(time.Second)
		if _, _, e = postgres.VerifyInitialSchemaCompletion(ctx, current, root); e == nil {
			t.Fatal("read-only resume adopted restarted database")
		}
		root.record.PostmasterAt = original
	})

	t.Run("activation-consumes-original-schema-incarnation", func(t *testing.T) { initialSchemaActivationBinding(t, ctx, config, sqlAdmin, manager, *root.record) })
}
