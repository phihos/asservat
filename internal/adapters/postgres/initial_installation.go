package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InitialInstallations is an installation-only facet, never ordinary runtime
// recovery. Composition supplies separate preparation, audit and activation
// pools; only the activation role can write the private activation columns.
type InitialInstallations struct {
	expectedDatabase *value.DatabaseIncarnation
	ledger           *Ledger
	scope            value.InstallationWitnessScope
	plan             artifact.Digest
}

var _ app.InitialInstallationPreparation = (*InitialInstallations)(nil)
var _ app.InitialInstallationActivation = (*InitialInstallations)(nil)
var _ auditapp.InitialInstallationAcknowledgements = (*InitialInstallations)(nil)

func NewInitialInstallations(ctx context.Context, pool *pgxpool.Pool, scope value.InstallationWitnessScope, plan artifact.Digest) (*InitialInstallations, error) {
	if !scope.Valid() || plan == (artifact.Digest{}) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &InitialInstallations{ledger: l, scope: scope, plan: plan}, nil
}

// NewInitialInstallationsForSchema is selected only by the protected projection
// for the explicit schema capability. A completed root or preflight observation
// cannot replace the independent transaction-time incarnation comparison.
func NewInitialInstallationsForSchema(ctx context.Context, pool *pgxpool.Pool, scope value.InstallationWitnessScope, plan artifact.Digest, expected contracts.InitialSchemaExpectation) (*InitialInstallations, error) {
	db, err := InitialSchemaIncarnation(expected)
	if err != nil {
		return nil, err
	}
	s, err := NewInitialInstallations(ctx, pool, scope, plan)
	if err != nil {
		return nil, err
	}
	s.expectedDatabase = &db
	return s, nil
}
func (s *InitialInstallations) database(ctx context.Context, tx pgx.Tx) (value.DatabaseIncarnation, time.Time, error) {
	db, now, err := initialDatabase(ctx, tx)
	if err == nil && s.expectedDatabase != nil && !sameInitialDatabase(db, *s.expectedDatabase) {
		err = value.ErrDenied
	}
	return db, now, err
}

func (s *InitialInstallations) inputs(w value.InstallationWitness, a value.Administration, now time.Time) bool {
	return w.Valid(now) && w.Scope == s.scope && a.Valid(now) && !a.Suspended && a.InstallationID == s.scope.InstallationID && a.IssuerEpoch == s.scope.IssuerEpoch
}
func (s *InitialInstallations) record(r audit.InitialInstallation) bool {
	return r.Valid() && r.Scope == s.scope && r.Claim.PlanDigest == s.plan && (s.expectedDatabase == nil || sameInitialDatabase(*s.expectedDatabase, r.Claim.Database))
}

// No external I/O or automatic uncertain-COMMIT replay within this transaction.
// The caller preserves the original witness/source deadlines through all waits.
func (s *InitialInstallations) transaction(ctx context.Context, f func(pgx.Tx) error) error {
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	tx, err := s.ledger.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return value.ErrUnavailable
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer done()
		_ = tx.Rollback(cleanup)
	}()
	_, err = tx.Exec(ctx, "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL synchronous_commit=on; SET LOCAL row_security=off")
	if err == nil {
		err = f(tx)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err == nil {
		return nil
	}
	for _, e := range []error{value.ErrInvalid, value.ErrDenied, value.ErrConflict, value.ErrUnavailable} {
		if errors.Is(err, e) {
			return e
		}
	}
	return value.ErrUnavailable
}

func initialDatabase(ctx context.Context, tx pgx.Tx) (value.DatabaseIncarnation, time.Time, error) {
	var d value.DatabaseIncarnation
	var now time.Time
	var applied, replica bool
	err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_postmaster_start_time(),
 (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
 version_id,is_applied,pg_catalog.clock_timestamp(),pg_catalog.pg_is_in_recovery()
 FROM public.goose_db_version ORDER BY id DESC LIMIT 1`).Scan(&d.StartedAt, &d.DatabaseOID, &d.SchemaVersion, &applied, &now, &replica)
	if err != nil {
		return d, now, err
	}
	if !applied || replica || d.SchemaVersion != currentSchemaVersion || !d.Valid() {
		return d, now, value.ErrUnavailable
	}
	d.StartedAt = ownerTime(d.StartedAt)
	return d, ownerTime(now), nil
}

func sameInitialDatabase(a, b value.DatabaseIncarnation) bool {
	return a.StartedAt.Equal(b.StartedAt) && a.DatabaseOID == b.DatabaseOID && a.SchemaVersion == b.SchemaVersion
}

// Exact schema inventory prevents a missing/renamed control table or an RLS
// policy from hiding prior state. MAINTAIN allows these locks without granting
// UPDATE/DELETE/TRUNCATE on operational tables. Migrations are installer-fenced.
func lockInitialTables(ctx context.Context, tx pgx.Tx) error {
	read := func() ([]string, error) {
		rows, e := tx.Query(ctx, `SELECT c.relname,c.relkind::text,c.relpersistence::text,c.relrowsecurity
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p','f','m') ORDER BY c.relname`)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		names := []string{}
		for rows.Next() {
			var name, kind, persistence string
			var rls bool
			if e = rows.Scan(&name, &kind, &persistence, &rls); e != nil {
				return nil, e
			}
			if kind != "r" || persistence != "p" || rls || len(names) >= 128 {
				return nil, value.ErrDenied
			}
			names = append(names, name)
		}
		return names, rows.Err()
	}
	names, err := read()
	if err != nil {
		return err
	}
	if !slices.Equal(names, initialInstallationTables) {
		return value.ErrDenied
	}
	// Fleet first follows existing authority-before-effect lock order. The rest
	// have no allowed operational rows during first activation.
	order := append([]string{"fleet_trust"}, names...)
	seen := map[string]bool{}
	quoted := []string{}
	for _, name := range order {
		if !seen[name] {
			seen[name] = true
			quoted = append(quoted, pgx.Identifier{"public", name}.Sanitize())
		}
	}
	if _, err = tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ",")+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return err
	}
	after, err := read()
	if err != nil {
		return err
	}
	if !slices.Equal(names, after) {
		return value.ErrDenied
	}
	return nil
}

func (s *InitialInstallations) pristine(ctx context.Context, tx pgx.Tx, a value.Administration) error {
	for _, name := range initialInstallationTables {
		if name == "goose_db_version" || name == "fleet_trust" || name == "fleet_initial_activation" {
			continue
		}
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM "+pgx.Identifier{"public", name}.Sanitize()+")").Scan(&exists); err != nil {
			return err
		} else if exists {
			return value.ErrDenied
		}
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.fleet_trust").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if count != 1 {
		return value.ErrDenied
	}
	var valid bool
	err := tx.QueryRow(ctx, `SELECT installation_id=$1 AND issuer_epoch=$2 AND source_uid=$3 AND source_generation=$4 AND source_digest=$5
 AND recovery_blocked AND suspended AND activated_postmaster_at IS NULL AND activated_database_oid IS NULL
 AND observed_at <= $6 FROM public.fleet_trust`, s.scope.InstallationID, s.scope.IssuerEpoch, a.Revision.UID, a.Revision.Generation, a.Revision.Digest[:], ownerTime(a.ObservedAt)).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return value.ErrDenied
	}
	return nil
}

func readInitialRecord(ctx context.Context, tx pgx.Tx) (audit.InitialInstallation, []byte, pgtype.Timestamptz, error) {
	var r audit.InitialInstallation
	var b, receipt []byte
	var at pgtype.Timestamptz
	err := tx.QueryRow(ctx, "SELECT record_json,audit_receipt_json,activated_at FROM public.fleet_initial_activation WHERE singleton FOR UPDATE").Scan(&b, &receipt, &at)
	if err != nil {
		return r, nil, at, err
	}
	if json.Unmarshal(b, &r) != nil || !r.Valid() {
		return r, nil, at, value.ErrDenied
	}
	return r, receipt, at, nil
}

func (s *InitialInstallations) PrepareInitialInstallation(ctx context.Context, w value.InstallationWitness, a value.Administration) (audit.InitialInstallation, error) {
	var out audit.InitialInstallation
	if s == nil || ctx == nil || !w.Valid(w.ObservedAt) || !a.Valid(a.ObservedAt) || w.Scope != s.scope {
		return out, value.ErrInvalid
	}
	ctx, end := context.WithDeadline(ctx, identity.Earlier(w.FreshUntil, a.FreshUntil))
	defer end()
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		if err := lockInitialTables(ctx, tx); err != nil {
			return err
		}
		db, now, err := s.database(ctx, tx)
		if err != nil {
			return err
		}
		if !s.inputs(w, a, now) {
			return value.ErrDenied
		}
		old, _, at, err := readInitialRecord(ctx, tx)
		if err == nil {
			if !s.record(old) || !old.Claim.Current(now) || !sameInitialDatabase(db, old.Claim.Database) || old.Claim.FleetSource != a.Revision || w.Claim != nil && !w.Claim.Same(old.Claim) || at.Valid && w.Claim == nil {
				return value.ErrDenied
			}
			if !at.Valid {
				if err = s.pristine(ctx, tx, a); err != nil {
					return err
				}
			}
			out = old
		} else if errors.Is(err, pgx.ErrNoRows) {
			if w.Claim != nil {
				return value.ErrDenied
			}
			if err = s.pristine(ctx, tx, a); err != nil {
				return err
			}
			out = audit.InitialInstallation{Scope: s.scope, Claim: value.InitialActivationClaim{ID: uuid.NewString(), Database: db, FleetSource: a.Revision, PlanDigest: s.plan, NotBefore: now, NotAfter: now.Add(5 * time.Minute)}}
			if !out.Valid() {
				return value.ErrInvalid
			}
			b, e := json.Marshal(out)
			if e != nil {
				return e
			}
			if _, err = tx.Exec(ctx, "INSERT INTO public.fleet_initial_activation(installation_id,claim_id,record_json) VALUES($1,$2,$3)", s.scope.InstallationID, out.Claim.ID, b); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO public.fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until)
    VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(installation_id) DO NOTHING`, s.scope.InstallationID, s.scope.IssuerEpoch, a.Revision.UID, a.Revision.Generation, a.Revision.Digest[:], ownerTime(a.ObservedAt), ownerTime(a.FreshUntil))
			if err != nil {
				return err
			}
		} else {
			return err
		}
		db, now, err = s.database(ctx, tx)
		if err != nil {
			return err
		}
		if !s.inputs(w, a, now) || !out.Claim.Current(now) || !sameInitialDatabase(db, out.Claim.Database) {
			return value.ErrDenied
		}
		return nil
	})
	if err != nil {
		return audit.InitialInstallation{}, err
	}
	return out, nil
}

func (s *InitialInstallations) AcknowledgeInitialInstallation(ctx context.Context, r audit.InitialInstallation, receipt audit.Receipt) error {
	if s == nil || ctx == nil || !s.record(r) || !receipt.ValidInitialInstallation(s.scope.InstallationID, r.Claim.ID) {
		return value.ErrInvalid
	}
	return s.transaction(ctx, func(tx pgx.Tx) error {
		old, existing, _, err := readInitialRecord(ctx, tx)
		if err != nil {
			return err
		}
		if old.Scope != r.Scope || !old.Claim.Same(r.Claim) {
			return value.ErrDenied
		}
		if s.expectedDatabase != nil {
			if _, _, err := s.database(ctx, tx); err != nil {
				return err
			}
		}
		b, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		if existing != nil {
			if !bytes.Equal(existing, b) {
				return value.ErrConflict
			}
			return nil
		}
		_, err = tx.Exec(ctx, "UPDATE public.fleet_initial_activation SET audit_receipt_json=$1 WHERE singleton AND audit_receipt_json IS NULL", b)
		if err == nil && s.expectedDatabase != nil {
			_, _, err = s.database(ctx, tx)
		}
		return err
	})
}

func (s *InitialInstallations) ActivateInitialInstallation(ctx context.Context, w value.InstallationWitness, a value.Administration) error {
	if s == nil || ctx == nil || w.Claim == nil || !w.Valid(w.ObservedAt) || !a.Valid(a.ObservedAt) || w.Scope != s.scope {
		return value.ErrInvalid
	}
	ctx, end := context.WithDeadline(ctx, identity.Earlier(w.FreshUntil, a.FreshUntil))
	defer end()
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if err := lockInitialTables(ctx, tx); err != nil {
			return err
		}
		r, receipt, at, err := readInitialRecord(ctx, tx)
		if err != nil {
			return err
		}
		var ack audit.Receipt
		if !s.record(r) || !w.Claim.Same(r.Claim) || a.Revision != r.Claim.FleetSource || json.Unmarshal(receipt, &ack) != nil || !ack.ValidInitialInstallation(s.scope.InstallationID, r.Claim.ID) {
			return value.ErrDenied
		}
		check := func() error {
			db, now, e := s.database(ctx, tx)
			if e != nil {
				return e
			}
			if !s.inputs(w, a, now) || !r.Claim.Current(now) || !sameInitialDatabase(db, r.Claim.Database) {
				return value.ErrDenied
			}
			return nil
		}
		if err = check(); err != nil {
			return err
		}
		if at.Valid {
			// A lost commit reply may observe the result; it must never clear a later
			// suspension/recovery block or overwrite renewed source state.
			var active bool
			err = tx.QueryRow(ctx, `SELECT NOT suspended AND NOT recovery_blocked AND issuer_epoch=$2
    AND source_uid=$3 AND source_generation=$4 AND source_digest=$5
    AND fresh_until > pg_catalog.clock_timestamp() FROM public.fleet_current_trust WHERE installation_id=$1`, s.scope.InstallationID, s.scope.IssuerEpoch, r.Claim.FleetSource.UID, r.Claim.FleetSource.Generation, r.Claim.FleetSource.Digest[:]).Scan(&active)
			if err != nil {
				return err
			}
			if !active {
				return value.ErrDenied
			}
			return check()
		}
		if err = s.pristine(ctx, tx, a); err != nil {
			return err
		}
		// ADR-226: the cluster identity and WAL timeline let a later lossless
		// restart re-activate (reactivate_restarted_database).
		tag, err := tx.Exec(ctx, `UPDATE public.fleet_trust SET suspended=false,recovery_blocked=false,
   activated_postmaster_at=$2,activated_database_oid=$3,observed_at=$4,fresh_until=$5,
   activated_system_identifier=(pg_catalog.pg_control_system()).system_identifier::text,
   activated_timeline=('x'||pg_catalog.substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()),1,8))::bit(32)::integer
   WHERE installation_id=$1 AND recovery_blocked AND activated_postmaster_at IS NULL AND activated_database_oid IS NULL`, s.scope.InstallationID, r.Claim.Database.StartedAt, r.Claim.Database.DatabaseOID, ownerTime(a.ObservedAt), ownerTime(a.FreshUntil))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return value.ErrDenied
		}
		// This one-shot seed is part of the already qualified first activation,
		// never an observer repair or an activation-field trigger. Pristine above
		// required the entire new table to be empty. No conflict/replay overwrite.
		tag, err = tx.Exec(ctx, `INSERT INTO public.fleet_observation(installation_id,semantic_version,
   issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,
   activated_database_oid,observed_at,fresh_until)
   SELECT installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,
   activated_postmaster_at,activated_database_oid,$2,$3 FROM public.fleet_trust WHERE installation_id=$1`,
			s.scope.InstallationID, ownerTime(a.ObservedAt), ownerTime(a.FreshUntil))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return value.ErrDenied
		}
		if _, err = tx.Exec(ctx, "UPDATE public.fleet_initial_activation SET activated_at=pg_catalog.clock_timestamp() WHERE singleton AND activated_at IS NULL"); err != nil {
			return err
		}
		return check()
	})
}
