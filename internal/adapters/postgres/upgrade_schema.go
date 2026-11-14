package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
)

// schemaLockID is the session advisory lock that serializes schema changes.
const schemaLockID int64 = 0x4153534552565343

// schemaLockWait bounds how long a second setup run waits for a running one.
const schemaLockWait = 2 * time.Minute

// SchemaBundle is the embedded migrations' build identity.
type SchemaBundle struct {
	Digest string
	Head   int64
}

// EmbeddedSchema validates the embedded migrations: consecutive numbering
// from 1 and only the transactional, upward-only goose annotations.
func EmbeddedSchema() (SchemaBundle, error) {
	return schemaBundle(migrations.Files(), currentSchemaVersion)
}

func schemaBundle(source fs.FS, head int64) (SchemaBundle, error) {
	var zero SchemaBundle
	if head < 1 || head > currentSchemaVersion {
		return zero, cfg.ErrInvalid
	}
	entries, e := fs.ReadDir(source, ".")
	if e != nil || int64(len(entries)) != head {
		return zero, cfg.ErrInvalid
	}
	sum := sha256.New()
	for i, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) < 11 || len(name) > 128 || name[5] != '_' || !strings.HasSuffix(name, ".sql") {
			return zero, cfg.ErrInvalid
		}
		n, e := strconv.ParseInt(name[:5], 10, 64)
		if e != nil || n != int64(i+1) {
			return zero, cfg.ErrInvalid
		}
		b, e := fs.ReadFile(source, name)
		if e != nil || len(b) == 0 || len(b) > 512<<10 {
			return zero, cfg.ErrInvalid
		}
		up, down, depth := 0, 0, 0
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "--") || !strings.Contains(line, "+goose") {
				continue
			}
			switch line {
			case "-- +goose Up":
				up++
				if up != 1 || depth != 0 {
					return zero, cfg.ErrInvalid
				}
			case "-- +goose Down":
				if up != 1 || down != 0 || depth != 0 {
					return zero, cfg.ErrInvalid
				}
				down++
			case "-- +goose StatementBegin":
				if up != 1 || depth != 0 {
					return zero, cfg.ErrInvalid
				}
				depth++
			case "-- +goose StatementEnd":
				if depth != 1 {
					return zero, cfg.ErrInvalid
				}
				depth--
			default:
				return zero, cfg.ErrInvalid
			}
		}
		if up != 1 || depth != 0 {
			return zero, cfg.ErrInvalid
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(name)))
		sum.Write(size[:])
		sum.Write([]byte(name))
		binary.BigEndian.PutUint64(size[:], uint64(len(b)))
		sum.Write(size[:])
		sum.Write(b)
	}
	return SchemaBundle{Digest: hex.EncodeToString(sum.Sum(nil)), Head: head}, nil
}

// UpgradeSchema applies the embedded migrations a database lacks, from an
// empty database (goose creates its version table) or from an earlier
// release. It runs as the schema-owning DDL role. The applied history must be
// an exact, all-applied prefix of the embedded migrations; concurrent runs
// serialize on a session advisory lock.
type UpgradeSchema struct {
	db     *sql.DB
	bundle SchemaBundle
}

func NewUpgradeSchema(c *pgx.ConnConfig) (*UpgradeSchema, error) {
	if c == nil || c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.ServerName == "" || c.TLSConfig.MinVersion < tls.VersionTLS13 || len(c.Fallbacks) != 0 || c.Tracer != nil || c.ValidateConnect != nil || c.AfterConnect != nil || c.User == "" || c.Database == "" {
		return nil, cfg.ErrInvalid
	}
	b, e := EmbeddedSchema()
	if e != nil {
		return nil, e
	}
	copy := c.Copy()
	copy.RuntimeParams = map[string]string{"application_name": "asservat-setup-schema", "search_path": "public,pg_catalog", "timezone": "UTC", "lock_timeout": strconv.Itoa(int(schemaLockWait/time.Millisecond)) + "ms", "statement_timeout": "300000ms", "idle_in_transaction_session_timeout": "300000ms", "synchronous_commit": "on", "row_security": "off"}
	copy.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*copy)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	db.SetConnMaxLifetime(30 * time.Minute)
	return &UpgradeSchema{db: db, bundle: b}, nil
}

func (s *UpgradeSchema) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Run returns the head before and after. A current database is a no-op; an
// interrupted run resumes at the next missing version.
func (s *UpgradeSchema) Run(ctx context.Context) (from, to int64, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return 0, 0, cfg.ErrUnavailable
	}
	locker := &schemaLocker{head: s.bundle.Head}
	store, _ := database.NewStore(database.DialectPostgres, "public.goose_db_version")
	p, e := goose.NewProvider(goose.DialectCustom, s.db, migrations.Files(), goose.WithStore(store), goose.WithSessionLocker(locker), goose.WithDisableGlobalRegistry(true), goose.WithAllowOutofOrder(false), goose.WithVerbose(false))
	if e != nil {
		return 0, 0, cfg.ErrInvalid
	}
	if _, e = p.Up(ctx); e != nil {
		if locker.err != nil {
			return locker.from, locker.from, locker.err
		}
		return locker.from, locker.from, cfg.ErrUnavailable
	}
	if !locker.locked {
		// Nothing was pending, so goose did not lock: check the history
		// once without the lock.
		conn, e := s.db.Conn(ctx)
		if e != nil {
			return 0, 0, cfg.ErrUnavailable
		}
		defer conn.Close()
		var owner uint32
		if e = conn.QueryRowContext(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user").Scan(&owner); e != nil {
			return 0, 0, cfg.ErrUnavailable
		}
		head, exists, e := schemaHistory(ctx, conn, s.bundle.Head, owner)
		if e != nil || !exists || head != s.bundle.Head {
			return head, head, errors.Join(cfg.ErrChanged, e)
		}
		return head, head, nil
	}
	return locker.from, s.bundle.Head, nil
}

// schemaLocker takes the advisory lock, waiting at most lock_timeout, and
// then checks the applied history before goose reads it.
type schemaLocker struct {
	locked bool
	head   int64
	from   int64
	err    error
}

func (g *schemaLocker) SessionLock(ctx context.Context, c *sql.Conn) error {
	if _, e := c.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); e != nil {
		g.err = cfg.ErrUnavailable
		return g.err
	}
	var owner uint32
	if e := c.QueryRowContext(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user").Scan(&owner); e != nil {
		g.err = cfg.ErrUnavailable
	} else if head, exists, e := schemaHistory(ctx, c, g.head, owner); e != nil {
		g.err = e
	} else if exists {
		g.from = head
	} else {
		// A database without a version table must be empty: never adopt
		// another application's schema.
		var present bool
		if e := c.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')`).Scan(&present); e != nil {
			g.err = cfg.ErrUnavailable
		} else if present {
			g.err = cfg.ErrChanged
		}
	}
	if g.err != nil {
		_, _ = c.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", schemaLockID)
		return g.err
	}
	g.locked = true
	return nil
}

func (g *schemaLocker) SessionUnlock(ctx context.Context, c *sql.Conn) error {
	var released bool
	if e := c.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID).Scan(&released); e != nil || !released {
		return cfg.ErrUnavailable
	}
	return nil
}

type schemaQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// schemaHistory returns the applied head when the version table exists. The
// table must be goose's own, owned by the migrating role, and hold an exact
// all-applied prefix of this binary's migrations.
func schemaHistory(ctx context.Context, q schemaQuery, maximum int64, owner uint32) (int64, bool, error) {
	if maximum < 1 || maximum > currentSchemaVersion {
		return 0, false, cfg.ErrChanged
	}
	var exists bool
	if e := q.QueryRowContext(ctx, "SELECT to_regclass('public.goose_db_version') IS NOT NULL").Scan(&exists); e != nil {
		return 0, false, cfg.ErrUnavailable
	}
	if !exists {
		return 0, false, nil
	}
	var safe bool
	if e := q.QueryRowContext(ctx, `SELECT c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
 AND c.relowner=$1
 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=c.oid AND NOT tgisinternal)
 FROM pg_class c WHERE c.oid='public.goose_db_version'::regclass`, owner).Scan(&safe); e != nil || !safe {
		return 0, false, cfg.ErrChanged
	}
	// Include version zero and one overflow row beyond this compiled bundle.
	rows, e := q.QueryContext(ctx, "SELECT id,version_id,is_applied FROM public.goose_db_version ORDER BY id LIMIT $1", maximum+2)
	if e != nil {
		return 0, false, cfg.ErrUnavailable
	}
	defer rows.Close()
	entries := []schemaVersion{}
	for rows.Next() {
		var v schemaVersion
		if e = rows.Scan(&v.ID, &v.Version, &v.Applied); e != nil {
			return 0, false, cfg.ErrUnavailable
		}
		entries = append(entries, v)
	}
	if rows.Err() != nil {
		return 0, false, cfg.ErrUnavailable
	}
	head, e := schemaPrefix(entries, maximum)
	return head, true, e
}

type schemaVersion struct {
	ID, Version int64
	Applied     bool
}

// schemaPrefix accepts versions 0..n, each applied once in order, n <= maximum.
func schemaPrefix(entries []schemaVersion, maximum int64) (int64, error) {
	if maximum < 1 || len(entries) == 0 || int64(len(entries)) > maximum+1 {
		return 0, cfg.ErrChanged
	}
	var lastID int64
	for i, v := range entries {
		if v.ID <= lastID || v.Version != int64(i) || !v.Applied {
			return 0, cfg.ErrChanged
		}
		lastID = v.ID
	}
	return int64(len(entries) - 1), nil
}

// CompiledSchemaVersion is this binary's compiled schema head.
const CompiledSchemaVersion = currentSchemaVersion

// SchemaState is the database's applied head and the oldest binary schema it
// still serves (ADR-227 decision 1).
type SchemaState struct{ Head, Floor int64 }

// Compatible applies the runtime rule to a binary compiled at schema.
func (s SchemaState) Compatible(schema int64) bool {
	return s.Head >= schema && s.Floor <= schema
}

// ReadSchemaState reads the head and floor with any role that may read the
// version table (every runtime role can). It does not require this binary's
// migrations to be a prefix of the history.
func ReadSchemaState(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (SchemaState, error) {
	if ctx == nil || ctx.Err() != nil || q == nil {
		return SchemaState{}, cfg.ErrUnavailable
	}
	head, floor, err := schemaState(ctx, q.QueryRow(ctx, schemaStateQuery))
	return SchemaState{head, floor}, err
}

// State reads the head and floor through the migrator's connection.
func (s *UpgradeSchema) State(ctx context.Context) (SchemaState, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return SchemaState{}, cfg.ErrUnavailable
	}
	head, floor, err := schemaState(ctx, s.db.QueryRowContext(ctx, schemaStateQuery))
	return SchemaState{head, floor}, err
}

// PlannedFloor is the floor the database would have after Run: the highest
// floor a not yet applied embedded migration declares, else the current one.
func (s *UpgradeSchema) PlannedFloor(current SchemaState) (int64, error) {
	floor := current.Floor
	for version := current.Head + 1; version <= s.bundle.Head; version++ {
		n, err := migrationDeclaredFloor(version)
		if err != nil {
			return 0, err
		}
		floor = max(floor, n)
	}
	return floor, nil
}

var migrationFloor = regexp.MustCompile(`asservat:oldest-binary-schema=([0-9]+)`)

// migrationDeclaredFloor is the floor one embedded migration sets (0 for an
// expand migration that leaves it).
func migrationDeclaredFloor(version int64) (int64, error) {
	matches, err := fs.Glob(migrations.Files(), fmt.Sprintf("%05d_*.sql", version))
	if err != nil || len(matches) != 1 {
		return 0, cfg.ErrInvalid
	}
	raw, err := fs.ReadFile(migrations.Files(), matches[0])
	if err != nil {
		return 0, cfg.ErrInvalid
	}
	var floor int64
	for _, m := range migrationFloor.FindAllSubmatch(raw, -1) {
		n, e := strconv.ParseInt(string(m[1]), 10, 64)
		if e != nil || n < 1 || n > version {
			return 0, cfg.ErrInvalid
		}
		floor = max(floor, n)
	}
	return floor, nil
}
