package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const fleetFreshnessObserveSQL = `SELECT public.observe_fleet_administration($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

type fleetFreshnessLab struct {
	db      *pgxpool.Pool
	pools   map[string]*pgxpool.Pool
	objects *objectstore.InitialInstallationObjects
}

type fleetFreshnessLock struct {
	tx         pgx.Tx
	connection *pgxpool.Conn
	pid        uint32
	once       sync.Once
}

func fleetFreshnessHold(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) *fleetFreshnessLock {
	t.Helper()
	c, e := pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	h := &fleetFreshnessLock{connection: c, pid: c.Conn().PgConn().PID()}
	t.Cleanup(func() { h.close(t) })
	h.tx, e = c.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.tx.Exec(ctx, "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; SET LOCAL idle_in_transaction_session_timeout='5s'"); e != nil {
		t.Fatal(e)
	}
	if _, e = h.tx.Exec(ctx, query, args...); e != nil {
		t.Fatal("original fixture lock", e)
	}
	return h
}
func (h *fleetFreshnessLock) close(t *testing.T) {
	t.Helper()
	h.once.Do(func() {
		if h.tx != nil {
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if e := h.tx.Rollback(ctx); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Error("owned blocker rollback", e)
			}
		}
		h.connection.Release()
	})
}

type fleetFreshnessCall struct {
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	err    error
}

func fleetFreshnessStart(t *testing.T, parent context.Context, fn func(context.Context) error) *fleetFreshnessCall {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	c := &fleetFreshnessCall{cancel: cancel, done: make(chan error, 1)}
	go func() { c.done <- fn(ctx) }()
	t.Cleanup(func() { c.cancel(); c.join() })
	return c
}
func (c *fleetFreshnessCall) join() error {
	c.once.Do(func() { c.err = <-c.done; c.cancel() })
	return c.err
}
func fleetFreshnessPID(t *testing.T, ctx context.Context, p *pgxpool.Pool) uint32 {
	t.Helper()
	var pid uint32
	if e := p.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); e != nil {
		t.Fatal(e)
	}
	return pid
}
func fleetFreshnessBlocked(t *testing.T, parent context.Context, db *pgxpool.Pool, pid, blocker uint32) {
	t.Helper()
	ctx, stop := context.WithTimeout(parent, time.Second)
	defer stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var yes bool
		if e := db.QueryRow(ctx, "SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1::integer))", pid, blocker).Scan(&yes); e != nil {
			t.Fatal("actual PostgreSQL blocker unavailable", e)
		}
		if yes {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("expected original PostgreSQL blocker absent", pid, blocker)
		case <-tick.C:
		}
	}
}
func fleetFreshnessWait(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until.Add(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func fleetFreshnessAuditObjects(t *testing.T, ctx context.Context, f fixture) *objectstore.InitialInstallationObjects {
	t.Helper()
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "fleet-freshness-" + strings.ReplaceAll(custodyID(), "-", "")
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	if _, e := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); e != nil {
		t.Fatal(e)
	}
	if _, e := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	store, e := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	keys := authorityTestKeys{a: aead}
	return &objectstore.InitialInstallationObjects{Store: store, Seal: keys, Open: keys}
}

func qualifyFleetFreshnessMigrationACLs(t *testing.T, ctx context.Context, db *pgxpool.Pool, migration []byte) {
	t.Run("migration-fences-existing-root-without-observation-backfill", func(t *testing.T) {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Error(e)
			}
		}()
		installation := custodyID()
		// Explicit synthetic legacy row, used only to demonstrate restrictive
		// upgrade behavior. It never supplies positive schema59 authority.
		if _, err = tx.Exec(ctx, `INSERT INTO fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) VALUES($1,$2,'synthetic-legacy-source',1,$3,false,false,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),clock_timestamp(),clock_timestamp()+interval '5 seconds')`, installation, custodyID(), make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, string(migration)); err != nil {
			t.Fatal("actual upgrade migration", err)
		}
		var fenced bool
		if err = tx.QueryRow(ctx, `SELECT t.semantic_version=2 AND t.suspended AND t.recovery_blocked AND v.recovery_blocked AND v.fresh_until='epoch'::timestamptz AND NOT EXISTS(SELECT FROM fleet_observation) FROM fleet_trust t JOIN fleet_current_trust v USING(installation_id) WHERE t.installation_id=$1`, installation).Scan(&fenced); err != nil || !fenced {
			t.Fatal("upgrade adopted legacy dates or fabricated positive observation", err)
		}
	})
	for _, mode := range []string{"legacy-table", "legacy-column", "legacy-public", "legacy-inherited", "legacy-trigger", "legacy-references", "retained-trigger", "retained-foreign-key", "global-writer-member", "default-table", "default-trigger", "default-references", "default-function"} {
		t.Run("migration-refuses-"+mode, func(t *testing.T) {
			tx, e := db.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
					t.Error(e)
				}
			}()
			role := "fleet_acl_" + strings.ReplaceAll(custodyID(), "-", "")
			unrelated := role + "_other"
			exec := func(sql string) {
				t.Helper()
				if _, e := tx.Exec(ctx, sql); e != nil {
					t.Fatal("migration ACL setup", e)
				}
			}
			exec("CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " NOLOGIN")
			exec("CREATE ROLE " + pgx.Identifier{unrelated}.Sanitize() + " NOLOGIN")
			exec("GRANT SELECT ON fleet_trust TO " + pgx.Identifier{unrelated}.Sanitize())
			switch mode {
			case "legacy-table":
				exec("GRANT INSERT,UPDATE ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "legacy-column":
				exec("GRANT UPDATE(observed_at,fresh_until) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "legacy-public":
				exec("GRANT UPDATE(fresh_until) ON fleet_trust TO PUBLIC")
			case "legacy-inherited":
				exec("GRANT UPDATE(source_generation) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
				exec("GRANT " + pgx.Identifier{role}.Sanitize() + " TO " + pgx.Identifier{unrelated}.Sanitize())
			case "legacy-trigger":
				exec("GRANT TRIGGER ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "legacy-references":
				exec("GRANT REFERENCES(installation_id) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "retained-trigger":
				exec("GRANT USAGE,CREATE ON SCHEMA public TO " + pgx.Identifier{role}.Sanitize())
				exec("GRANT TRIGGER ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
				exec("SET LOCAL ROLE " + pgx.Identifier{role}.Sanitize())
				exec("CREATE FUNCTION " + pgx.Identifier{"public", role + "_fn"}.Sanitize() + "() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$")
				exec("CREATE TRIGGER " + pgx.Identifier{role + "_hook"}.Sanitize() + " BEFORE UPDATE ON public.fleet_trust FOR EACH ROW EXECUTE FUNCTION " + pgx.Identifier{"public", role + "_fn"}.Sanitize() + "()")
				exec("RESET ROLE")
				exec("REVOKE TRIGGER ON fleet_trust FROM " + pgx.Identifier{role}.Sanitize())
			case "retained-foreign-key":
				exec("GRANT USAGE,CREATE ON SCHEMA public TO " + pgx.Identifier{role}.Sanitize())
				exec("GRANT REFERENCES(installation_id) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
				exec("SET LOCAL ROLE " + pgx.Identifier{role}.Sanitize())
				exec("CREATE TABLE " + pgx.Identifier{"public", role + "_child"}.Sanitize() + "(installation_id uuid REFERENCES public.fleet_trust(installation_id))")
				exec("RESET ROLE")
				exec("REVOKE REFERENCES(installation_id) ON fleet_trust FROM " + pgx.Identifier{role}.Sanitize())
			case "global-writer-member":
				exec("GRANT pg_write_all_data TO " + pgx.Identifier{role}.Sanitize())
			case "default-table":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT INSERT,UPDATE ON TABLES TO " + pgx.Identifier{role}.Sanitize())
			case "default-trigger":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT TRIGGER ON TABLES TO " + pgx.Identifier{role}.Sanitize())
			case "default-references":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT REFERENCES ON TABLES TO " + pgx.Identifier{role}.Sanitize())
			case "default-function":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO " + pgx.Identifier{role}.Sanitize())
			}
			snapshot := func() string {
				t.Helper()
				var out string
				if e := tx.QueryRow(ctx, `SELECT jsonb_build_object('table',(SELECT relacl::text FROM pg_class WHERE oid='public.fleet_trust'::regclass),'columns',(SELECT jsonb_agg(ARRAY[attname,attacl::text] ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.fleet_trust'::regclass),'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY oid) FROM pg_roles r WHERE rolname=ANY($1)),'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member) FROM pg_auth_members m WHERE roleid IN (SELECT oid FROM pg_roles WHERE rolname=ANY($1)) OR member IN (SELECT oid FROM pg_roles WHERE rolname=ANY($1))),'defaults',(SELECT jsonb_agg(to_jsonb(d) ORDER BY oid) FROM pg_default_acl d),'triggers',(SELECT jsonb_agg(to_jsonb(g) ORDER BY oid) FROM pg_trigger g WHERE tgrelid='public.fleet_trust'::regclass),'references',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_constraint c WHERE confrelid='public.fleet_trust'::regclass),'owned-relations',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_class c WHERE relowner IN (SELECT oid FROM pg_roles WHERE rolname=ANY($1))))::text`, []string{role, unrelated}).Scan(&out); e != nil {
					t.Fatal(e)
				}
				return out
			}
			before := snapshot()
			exec("SAVEPOINT migration59")
			_, e = tx.Exec(ctx, string(migration))
			var pg *pgconn.PgError
			expected := "fleet observation migration requires retirement of existing direct fleet writer grants"
			if mode == "global-writer-member" {
				expected = "fleet observation migration requires retirement of global runtime writer membership"
			}
			if strings.HasPrefix(mode, "default-") {
				expected = "fleet observation migration rejects runtime authority from default privileges"
			}
			if strings.HasPrefix(mode, "retained-") {
				expected = "fleet observation migration requires retirement of untrusted fleet hooks"
			}
			if !errors.As(e, &pg) || pg.Code != "55000" || pg.Message != expected {
				t.Fatal("migration did not refuse the actual surviving writer prerequisite", mode, e)
			}
			exec("ROLLBACK TO SAVEPOINT migration59")
			if snapshot() != before {
				t.Fatal("rejected migration changed unrelated roles or existing grants")
			}
			var unchanged bool
			if e := tx.QueryRow(ctx, `SELECT to_regclass('public.fleet_observation') IS NULL AND NOT EXISTS(SELECT FROM pg_attribute WHERE attrelid='public.fleet_trust'::regclass AND attname='semantic_version') AND (SELECT version_id=58 AND is_applied FROM goose_db_version ORDER BY id DESC LIMIT 1)`).Scan(&unchanged); e != nil || !unchanged {
				t.Fatal("failed migration changed schema/history", e)
			}
			t.Log("actual migration59 refusal", mode, "SQLSTATE", pg.Code)
		})
	}
	t.Run("migration-preserves-unrelated-reader-and-lock-grants", func(t *testing.T) {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Error(e)
			}
		}()
		role := "fleet_reader_" + strings.ReplaceAll(custodyID(), "-", "")
		for _, sql := range []string{
			"CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " NOLOGIN",
			"GRANT SELECT ON fleet_trust,fleet_current_trust TO " + pgx.Identifier{role}.Sanitize(),
			"GRANT UPDATE(installation_id) ON fleet_trust,fleet_current_trust TO " + pgx.Identifier{role}.Sanitize(),
		} {
			if _, err = tx.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
		}
		var original uint32
		if err = tx.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", role).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, string(migration)); err != nil {
			t.Fatal("migration rejected unrelated reader/row-lock grants", err)
		}
		var retained bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE oid=$1 AND rolname=$2) AND has_table_privilege($1,'public.fleet_trust','SELECT') AND has_table_privilege($1,'public.fleet_current_trust','SELECT') AND has_column_privilege($1,'public.fleet_trust','installation_id','UPDATE') AND has_column_privilege($1,'public.fleet_current_trust','installation_id','UPDATE') AND NOT has_column_privilege($1,'public.fleet_trust','fresh_until','UPDATE') AND NOT has_table_privilege($1,'public.fleet_observation','INSERT')`, original, role).Scan(&retained); err != nil || !retained {
			t.Fatal("migration replaced role or rewrote unrelated privileges", err)
		}
	})
}
